package backup

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"identity-agent-core/backup/remote"
	"identity-agent-core/store"

	"github.com/google/uuid"
	"sort"
	"strings"
)

type remoteBackend interface {
	Push(ctx context.Context, objectKey string, data []byte) error
	Pull(ctx context.Context, objectKey string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error)
}

var remoteBackendFactory = func(dest Destination, creds RemoteCredentialSecrets) (remoteBackend, error) {
	return remote.NewBackend(toRemoteDestination(dest), toRemoteCredentials(creds))
}

func toRemoteDestination(dest Destination) remote.DestinationConfig {
	return remote.DestinationConfig{
		Provider:  dest.CloudProvider,
		Bucket:    dest.CloudBucket,
		Prefix:    dest.CloudPrefix,
		Endpoint:  dest.CloudEndpoint,
		Region:    dest.CloudRegion,
		RemoteURL: dest.RemoteURL,
	}
}

func toRemoteCredentials(creds RemoteCredentialSecrets) remote.CredentialSecrets {
	return remote.CredentialSecrets{
		AccessKey:          creds.AccessKey,
		SecretKey:          creds.SecretKey,
		SessionToken:       creds.SessionToken,
		Username:           creds.Username,
		Password:           creds.Password,
		AccountName:        creds.AccountName,
		ServiceAccountJSON: creds.ServiceAccountJSON,
	}
}

// Service orchestrates backup export, push, and status.
type Service struct {
	DataDir         string
	Store           store.Store
	ConfigStore     *ConfigStore
	CredentialStore *CredentialStore
	Pusher          *PairedPusher
	Scheduler       *Scheduler
	failures        int
}

func NewService(dataDir string, st store.Store) *Service {
	cs := NewConfigStore(dataDir)
	credStore, err := NewCredentialStore(dataDir)
	if err != nil {
		log.Printf("[backup] credential store init failed: %v", err)
	}
	svc := &Service{
		DataDir:         dataDir,
		Store:           st,
		ConfigStore:     cs,
		CredentialStore: credStore,
		Pusher:          NewPairedPusher(),
	}
	svc.Scheduler = NewScheduler(svc)
	return svc
}

func (s *Service) Collector() *Collector {
	return &Collector{DataDir: s.DataDir, Store: s.Store}
}

// NotifyEvent schedules a debounced backup for a store-layer change.
func (s *Service) NotifyEvent(reason EventReason) {
	if s == nil || s.Scheduler == nil {
		return
	}
	s.Scheduler.TriggerEvent(string(reason))
}

// Export writes an encrypted archive to disk and optionally pushes to destinations.
func (s *Service) Export(mnemonic, passphrase, destPath string, tiers []string) (*ExportResult, error) {
	return s.ExportWithReason(mnemonic, passphrase, destPath, tiers, "")
}

// ExportWithSeed is Export for a caller that already holds the seed in bytes.
//
// The distinction matters at the edge rather than here: a root device reads its
// own wrapped seed off disk instead of asking its owner to type the words, so
// the secret never travels to take a backup. Both paths derive the same key.
func (s *Service) ExportWithSeed(mnemonic, seedB64, passphrase, destPath string, tiers []string) (*ExportResult, error) {
	return s.exportWithReason(mnemonic, seedB64, passphrase, destPath, tiers, "")
}

// ExportWithReason creates a full or delta archive based on schedule and delta chain health.
func (s *Service) ExportWithReason(mnemonic, passphrase, destPath string, tiers []string, reason string) (*ExportResult, error) {
	return s.exportWithReason(mnemonic, "", passphrase, destPath, tiers, reason)
}

func (s *Service) exportWithReason(mnemonic, seedB64, passphrase, destPath string, tiers []string, reason string) (*ExportResult, error) {
	start := time.Now()
	collector := s.Collector()
	opts := DefaultCollectOptions(tiers)
	if len(tiers) == 0 {
		cfg, _ := s.ConfigStore.LoadConfig()
		opts.Tiers = cfg.DefaultTiers
	}
	hasTier1 := false
	for _, t := range opts.Tiers {
		if t == TierCritical {
			hasTier1 = true
		}
	}
	if !hasTier1 {
		opts.Tiers = append([]string{TierCritical}, opts.Tiers...)
	}

	deltaState, err := s.ConfigStore.LoadDeltaState()
	if err != nil {
		s.recordFailure(opts.Tiers, err, time.Since(start))
		return nil, err
	}

	forceFull := false
	chainReset := false
	if deltaState.ChainDigestQB64 != "" {
		if err := deltaState.VerifyChain(); err != nil {
			log.Printf("[backup] delta chain mismatch, discarding chain: %v", err)
			deltaState = ResetDeltaState()
			forceFull = true
			chainReset = true
		}
	}

	// A destination that has never received a FULL archive gets one.
	//
	// Deltas restore only on top of a full archive, so a destination holding
	// nothing but deltas holds nothing anybody can recover from. Without this
	// the sequence any sensible person follows — add a destination, take a
	// backup — leaves them with a destination that cannot restore, and it stays
	// that way until the next scheduled compaction, up to a month later. Add a
	// host, take a backup, and the Identity Agent still reports nothing off
	// this device that can be recovered from. It is reporting correctly.
	//
	// Keyed on the last FULL rather than the last success, and the difference
	// matters twice. A destination that has only ever taken deltas has a recent
	// success and holds nothing restorable, so keying on success would leave
	// every destination that already exists broken and fix only new ones.
	//
	// And it is rate-limited rather than latched. Keying on "has never
	// succeeded" meant one permanently unreachable destination made EVERY
	// backup a full one, forever, silently killing deltas for that agent — and
	// a paired machine whose offer is not turned on is exactly such a
	// destination, so that would be the common state rather than a rare one.
	if !forceFull {
		if cfg, cerr := s.ConfigStore.LoadConfig(); cerr == nil {
			for _, d := range cfg.Destinations {
				if !d.Enabled || d.LastFullAt != "" {
					continue
				}
				if d.LastError != "" && !readyToRetryFull(d) {
					continue
				}
				log.Printf("[backup] destination %s holds nothing it could restore from, "+
					"so this archive is full rather than a delta", d.ID)
				forceFull = true
				break
			}
		}
	}

	snapshotType, compaction := DecideSnapshotType(deltaState, reason, forceFull)
	if chainReset {
		compaction = true
	}

	fullBundle, pointers, err := collector.Collect(opts)
	if err != nil {
		s.recordFailure(opts.Tiers, err, time.Since(start))
		return nil, err
	}

	archiveBundle := fullBundle
	if snapshotType == SnapshotDelta {
		archiveBundle = FilterDeltaBundle(fullBundle, &deltaState, opts.Tiers)
		if len(archiveBundle.Ordered) == 0 {
			log.Printf("[backup] no delta changes for %s — skipping export", reason)
			return &ExportResult{
				Bytes:        nil,
				Size:         0,
				Tiers:        opts.Tiers,
				SnapshotType: SnapshotDelta,
			}, nil
		}
	}

	pendingState := deltaState
	if err := UpdateDeltaStateAfterBackup(&pendingState, fullBundle, snapshotType, compaction); err != nil {
		s.recordFailure(opts.Tiers, err, time.Since(start))
		return nil, err
	}

	// Recipients configured once, at pairing, are what let a scheduled backup
	// run unattended: nobody is present to type a phrase at 3am, and an agent
	// that had to store one to keep working would defeat the point.
	sealTo, err := s.sealRecipients()
	if err != nil {
		s.recordFailure(opts.Tiers, err, time.Since(start))
		return nil, err
	}

	var seedBytes []byte
	if seedB64 != "" {
		if seedBytes, err = DecodeB64(seedB64); err != nil {
			s.recordFailure(opts.Tiers, err, time.Since(start))
			return nil, fmt.Errorf("root seed is not valid base64: %w", err)
		}
	}

	result, err := collector.CreateArchive(opts, ExportRequest{
		Mnemonic:             mnemonic,
		BIP39Seed:            seedBytes,
		Passphrase:           passphrase,
		Tiers:                opts.Tiers,
		SnapshotType:         snapshotType,
		Bundle:               archiveBundle,
		ExternalPointers:     pointers,
		DeltaStateDigestQB64: pendingState.ChainDigestQB64,
		SealToPublicKeys:     sealTo,
	})
	if err != nil {
		s.recordFailure(opts.Tiers, err, time.Since(start))
		return nil, err
	}

	// Opened before it counts. This runs BEFORE the archive is written or
	// pushed anywhere, so a bad archive is never delivered to a destination
	// and never recorded as a success. See verifyArchiveOpens.
	if verr := verifyArchiveOpens(result, ExportRequest{
		Mnemonic:   mnemonic,
		BIP39Seed:  seedBytes,
		Passphrase: passphrase,
	}, archiveBundle); verr != nil {
		if errors.Is(verr, ErrNoKeyToVerifyWith) {
			// Kept, and honestly labelled. See ErrNoKeyToVerifyWith.
			log.Printf("[backup] archive kept UNVERIFIED: %v", verr)
		} else {
			err := fmt.Errorf("backup failed verification and was not kept: %w", verr)
			log.Printf("[backup] VERIFICATION FAILED: %v", verr)
			s.recordFailure(opts.Tiers, err, time.Since(start))
			return nil, err
		}
	} else {
		result.VerifiedAt = time.Now().UTC().Format(time.RFC3339)
	}

	if destPath != "" {
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			s.recordFailure(opts.Tiers, err, time.Since(start))
			return nil, err
		}
		if err := os.WriteFile(destPath, result.Bytes, 0600); err != nil {
			s.recordFailure(opts.Tiers, err, time.Since(start))
			return nil, err
		}
	}

	// A destination this agent already has. Done here rather than at pairing
	// time so an agent paired before backup existed still gets one, and so a
	// person never has to know these are two separate things to set up.
	if n, aerr := s.AdoptPairedMachinesAsDestinations(); aerr != nil {
		log.Printf("[backup] could not check for paired machines to back up to: %v", aerr)
	} else if n > 0 {
		log.Printf("[backup] added %d paired machine(s) as backup destinations", n)
	}

	cfg, _ := s.ConfigStore.LoadConfig()
	destIDs := s.pushToDestinations(cfg, result)

	// Did it reach anywhere that outlives this machine? Recorded separately
	// from "the backup ran", because they are different facts and only one of
	// them is worth telling somebody they are safe on.
	survived := false
	for _, id := range destIDs {
		for _, d := range cfg.Destinations {
			if d.ID == id && ReachOf(d, s.DataDir) != ReachThisDeviceOnly {
				survived = true
			}
		}
	}
	if !survived {
		log.Printf("[backup] WARNING: this archive reached nowhere that survives losing this device")
	}

	if err := s.ConfigStore.SaveDeltaState(pendingState); err != nil {
		log.Printf("[backup] failed to persist delta state: %v", err)
	}

	s.recordSuccess(opts.Tiers, result.Size, destIDs, time.Since(start), result.SnapshotType,
		result.VerifiedAt != "", survived, result.Manifest.SelfSufficient)
	s.failures = 0
	return result, nil
}

// sealRecipients reads the configured recovery public keys.
//
// A malformed key is fatal rather than skipped. Quietly dropping one would
// produce an archive the owner believes they can open and cannot, and that is
// only discovered on the day it matters.
func (s *Service) sealRecipients() ([][]byte, error) {
	cfg, err := s.ConfigStore.LoadConfig()
	if err != nil {
		return nil, nil // no config yet is not an error; it just means no recipients
	}
	var keys [][]byte
	for i, encoded := range cfg.SealToPublicKeysB64 {
		raw, err := DecodeB64(encoded)
		if err != nil {
			return nil, fmt.Errorf("recovery public key %d is not valid base64: %w", i, err)
		}
		if len(raw) != X25519KeyLen {
			return nil, fmt.Errorf("recovery public key %d must be %d bytes, got %d", i, X25519KeyLen, len(raw))
		}
		keys = append(keys, raw)
	}
	return keys, nil
}

// pushToDestinations delivers the archive and reports where it actually landed.
//
// Every failure here used to be discarded — a local path that could not be
// written and a paired machine that was unreachable both returned silently, and
// the run was still recorded as a success with a shorter list. A backup that
// reached nowhere was indistinguishable from one that reached everywhere.
// readyToRetryFull rate-limits the full-archive retry for a failing destination.
//
// A destination that has never held a full archive should get one, but one that
// can never be reached must not turn every backup on this agent into a full
// archive. Once a day repairs a destination that comes back, and costs almost
// nothing for one that does not.
func readyToRetryFull(d Destination) bool {
	if d.LastSuccessAt == "" {
		// It has never worked at all, so a full archive costs no more than a
		// delta to something that will refuse both.
		return true
	}
	t, err := time.Parse(time.RFC3339, d.LastSuccessAt)
	if err != nil {
		return true
	}
	return time.Since(t) >= 24*time.Hour
}

// ownAID is the identity these archives belong to.
//
// A destination files by identity, so an archive that cannot say whose it is
// cannot be stored safely anywhere that holds more than one.
func (s *Service) ownAID() string {
	if s.Store == nil {
		return ""
	}
	identity, err := s.Store.GetIdentity()
	if err != nil || identity == nil {
		return ""
	}
	return identity.AID
}

func (s *Service) pushToDestinations(cfg Config, result *ExportResult) []string {
	destIDs := []string{}
	for _, d := range cfg.Destinations {
		if !d.Enabled {
			continue
		}
		var err error
		switch d.Type {
		case DestLocalPath:
			err = s.pushLocalDestination(d, result)
		case DestPairedAgent:
			err = s.Pusher.Push(d.PairedURL, s.ownAID(), result.Bytes)
		case DestCloudUser:
			err = s.pushCloudDestination(d, result)
		case DestCloudHosted:
			err = fmt.Errorf("cloud_hosted is a commercial service and is not available here")
		default:
			err = fmt.Errorf("unrecognised destination type %q", d.Type)
		}

		if err != nil {
			log.Printf("[backup] destination %s (%s) FAILED: %v", d.ID, d.Type, err)
			s.noteDestinationResult(d.ID, err, int64(result.Size), result.SnapshotType == SnapshotFull)
			continue
		}
		s.noteDestinationResult(d.ID, nil, int64(result.Size), result.SnapshotType == SnapshotFull)
		destIDs = append(destIDs, d.ID)
	}
	return destIDs
}

func (s *Service) pushCloudDestination(dest Destination, result *ExportResult) error {
	if s.CredentialStore == nil {
		return fmt.Errorf("credential store unavailable")
	}
	creds, err := s.CredentialStore.Load(dest.CredentialID)
	if err != nil {
		return err
	}
	backend, err := remoteBackendFactory(dest, creds)
	if err != nil {
		return err
	}
	key := remote.ArchiveObjectKey(toRemoteDestination(dest), result.SnapshotType)
	return backend.Push(context.Background(), key, result.Bytes)
}

// PullLatestArchive downloads the newest encrypted .iab from a user-managed destination.
func (s *Service) PullLatestArchive(dest Destination) ([]byte, string, error) {
	if dest.Type != DestCloudUser {
		return nil, "", fmt.Errorf("pull only supported for cloud_user_managed destinations")
	}
	if s.CredentialStore == nil {
		return nil, "", fmt.Errorf("credential store unavailable")
	}
	creds, err := s.CredentialStore.Load(dest.CredentialID)
	if err != nil {
		return nil, "", err
	}
	backend, err := remoteBackendFactory(dest, creds)
	if err != nil {
		return nil, "", err
	}
	ctx := context.Background()
	key, err := remote.LatestArchiveKey(ctx, backend, dest.CloudPrefix)
	if err != nil {
		return nil, "", err
	}
	data, err := backend.Pull(ctx, key)
	if err != nil {
		return nil, "", err
	}
	return data, key, nil
}

// SaveDestinationCredentials stores encrypted remote credentials and returns the credential ID.
func (s *Service) SaveDestinationCredentials(creds RemoteCredentialSecrets) (string, error) {
	if s.CredentialStore == nil {
		return "", fmt.Errorf("credential store unavailable")
	}
	id := uuid.New().String()
	return id, s.CredentialStore.Save(id, creds)
}

func (s *Service) recordSuccess(tiers []string, size int, dests []string, dur time.Duration, snapshotType string, verified, survived, selfSufficient bool) {
	if snapshotType == "" {
		snapshotType = SnapshotFull
	}
	_ = s.ConfigStore.AppendHistory(HistoryEntry{
		ID:             uuid.New().String(),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Tiers:          tiers,
		SizeBytes:      size,
		SnapshotType:   snapshotType,
		Success:        true,
		DurationMs:     dur.Milliseconds(),
		Destinations:   dests,
		Verified:       verified,
		OffDevice:      survived,
		SelfSufficient: selfSufficient,
	})
}

func (s *Service) recordFailure(tiers []string, err error, dur time.Duration) {
	s.failures++
	_ = s.ConfigStore.AppendHistory(HistoryEntry{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Tiers:      tiers,
		Success:    false,
		DurationMs: dur.Milliseconds(),
		Error:      err.Error(),
	})
}

// Status returns current backup health.
func (s *Service) Status() (StatusResponse, error) {
	cfg, err := s.ConfigStore.LoadConfig()
	if err != nil {
		return StatusResponse{}, err
	}
	hist, err := s.ConfigStore.LoadHistory()
	if err != nil {
		return StatusResponse{}, err
	}
	return s.ConfigStore.BuildStatus(cfg, hist, s.failures), nil
}

// SaveConfig persists configuration.
func (s *Service) SaveConfig(cfg Config) error {
	return s.ConfigStore.SaveConfig(cfg)
}

// LoadConfig returns current configuration.
func (s *Service) LoadConfig() (Config, error) {
	return s.ConfigStore.LoadConfig()
}

// ReceiveArchive stores an opaque archive on a backup-only device (ACT2 boundary).
func (s *Service) ReceiveArchive(identityAID string, data []byte) (string, error) {
	// Whether this machine will hold this at all, before a byte is written.
	//
	// This route is PUBLIC, so "the caller" is any host that can open a
	// connection. It used to write whatever it was given to a directory named
	// after whatever the caller claimed, which made the caller the author of
	// both the bytes and the path.
	cfg, cerr := s.ConfigStore.LoadConfig()
	if cerr != nil {
		return "", cerr
	}
	held, _ := s.ListReceived(identityAID)
	if err := cfg.Offer.MayAccept(identityAID, len(held) > 0); err != nil {
		return "", err
	}

	dir := filepath.Join(s.DataDir, "backup_receive", identityAID)
	if err := cfg.Offer.RoomFor(s.DataDir, int64(len(data))); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	// Named to the second, plus a counter, because two archives CAN arrive
	// inside one second and the timestamp alone silently overwrote the first.
	//
	// The name is CLAIMED by creating the file exclusively rather than by
	// checking whether it exists and then writing it. A stat-then-write leaves
	// a window in which two concurrent pushes both see the name free, both take
	// it, and both write the same file — and since the route is public and the
	// name is a predictable timestamp, that window can be aimed at. The result
	// there is worse than a lost archive: two interleaved writes leave one file
	// with parts of both, and the rename below publishes it under a name that
	// looks like a complete archive.
	base := time.Now().UTC().Format("20060102-150405")
	var f *os.File
	var path string
	for n := 0; ; n++ {
		if n == 0 {
			path = filepath.Join(dir, base+archiveSuffix)
		} else {
			path = filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, n, archiveSuffix))
		}
		// Both names have to be free, and for different reasons. The finished
		// archive may already be there from an earlier push in this same
		// second — the rename below would replace it silently. The partial may
		// be there from a push happening right now.
		if _, serr := os.Stat(path); serr == nil {
			continue
		} else if !os.IsNotExist(serr) {
			return "", serr
		}
		var err error
		// O_EXCL: the create fails if somebody else already took this name, so
		// the loop advances instead of two callers sharing a file.
		f, err = os.OpenFile(path+partialSuffix, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			// Anything other than "taken" is a real failure. The earlier
			// version treated every error as "taken" and retried forever, so a
			// directory that could not be read span on a public route.
			return "", err
		}
		if n > 10000 {
			return "", fmt.Errorf("could not find a free name for this archive")
		}
	}

	// Written aside and moved into place, so a transfer that dies partway
	// leaves nothing rather than something that looks restorable.
	tmp := path + partialSuffix
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return path, nil
}

// AdoptArchivesFiledUnderNoIdentity moves archives that were stored before a
// push had to say who it was from.
//
// A push with an empty identifier used to produce a path that collapsed to the
// receive directory itself, so those archives sit loose in backup_receive/
// rather than in a per-identity directory under it. Held() only looks at
// directories and the listing route cannot be called with an empty identifier,
// so they are on disk and reachable by nothing — an off-site copy somebody is
// relying on, invisible to every screen and every recovery path.
//
// They cannot be attributed: the sender is exactly the thing that was missing.
// So they are moved somewhere a person can see them and decide, rather than
// deleted, and rather than left where nothing looks.
func (s *Service) AdoptArchivesFiledUnderNoIdentity() (int, error) {
	root := filepath.Join(s.DataDir, "backup_receive")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	moved := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), archiveSuffix) {
			continue
		}
		dest := filepath.Join(root, unattributed)
		if err := os.MkdirAll(dest, 0755); err != nil {
			return moved, err
		}
		if err := os.Rename(filepath.Join(root, e.Name()), filepath.Join(dest, e.Name())); err != nil {
			return moved, err
		}
		moved++
	}
	if moved > 0 {
		log.Printf("[backup] moved %d archive(s) that did not say which identity they belong to "+
			"into %s, where they can at least be seen", moved, unattributed)
	}
	return moved, nil
}

// ListReceived returns opaque archive paths for a paired identity (no decrypt).
func (s *Service) ListReceived(identityAID string) ([]string, error) {
	dir := filepath.Join(s.DataDir, "backup_receive", identityAID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		// Only finished archives. A ".partial" left by a transfer that died
		// sorts AFTER the archive it was going to replace, and recovery takes
		// the last entry — so an aborted push became the file somebody restored
		// from. Writing aside and renaming is pointless if the reader picks up
		// the aside copy.
		if e.IsDir() || !strings.HasSuffix(e.Name(), archiveSuffix) {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}
