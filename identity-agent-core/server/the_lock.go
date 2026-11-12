package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/lockgate"
	"identity-agent-core/permission"
	"identity-agent-core/secureenclave"
)

// THE LOCK OF A LOGGED-OUT IDENTITY (ADR-074).
//
// A gated identity is open or locked. Locked, this core answers only the lock
// routes below: it reads no seed and serves nothing else. Open, it serves as it
// always did, and a lock stops it accepting requests, gives what is running a
// few seconds to finish, deletes the device-held key and zeroes the held one.
//
// WHAT THE LOCK IS WORTH is said in LockClass and nowhere is it overstated: with
// a placeholder authentication provider it is app_only (see lockgate).
// Ending the process is what ends the exposure of memory; the app stops the core
// after a lock (ADR-074 section 5).

// The routes a locked core answers, and the only ones.
const (
	lockStatePath  = "/api/lock/state"
	lockUnlockPath = "/api/lock/unlock"
	lockLockPath   = "/api/lock/lock"
	lockSecretPath = "/api/lock/secret"
)

var errAlreadyLocking = errors.New("a lock is already in progress")

func (l *theLock) isLocking() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.locking }

// DrainWithin is how long a request already running is given when a lock fires.
const DrainWithin = 30 * time.Second

// cancelGrace is how long after cancelling the stragglers the lock waits for
// them to return before going ahead.
const cancelGrace = 3 * time.Second

func isALockRoute(path string) bool {
	switch path {
	case lockStatePath, lockUnlockPath, lockLockPath, lockSecretPath,
		// The proof an app asks for before it sends the owner secret anywhere.
		// It reads no seed and reveals nothing but a MAC (ADR-074 adds it to the
		// routes a locked core answers).
		"/api/local-owner/proof":
		return true
	}
	return false
}

// isTheHealthProbe is the public liveness answer, which reveals nothing. A
// locked core answers it, or every caller that wants 200 from a live core reads
// a locked one as dead or absent (the app's process supervisor, the agent
// detector, the witness heartbeat). The lock is reported on /api/lock/state.
func isTheHealthProbe(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/api/health"
}

type flight struct {
	cancel context.CancelFunc
	w      *flightWriter
}

// theLock is the lock state of the one identity this core serves.
type theLock struct {
	sess *lockgate.Session

	mu      sync.Mutex
	locking bool
	flights map[*flight]struct{}
	conns   map[*trackedConn]struct{}
	drained *sync.Cond
	// startedGated: this core began with a gate. If the gate later seems to be
	// gone (a file deleted under it), it refuses rather than falls open.
	startedGated bool

	drainWithin time.Duration
	workStarted bool
	// endWork ends the work that needs the identity's key (relay, witnessing,
	// anchoring, add-ons, the scheduled backup) and drops what it cached;
	// resumeWork starts it again. Set by the core that owns this lock.
	endWork, resumeWork func()

	// transition is held for the whole of a log-out and for the whole of an
	// unlock or secret change, so the two never interleave. gen counts log-outs
	// begun: an unlock that was admitted before one began is refused after it.
	transition sync.Mutex
	gen        uint64
}

func (l *theLock) generation() uint64 { l.mu.Lock(); defer l.mu.Unlock(); return l.gen }

// beginChange is for an unlock or secret change that was admitted at generation
// gen0. It returns false when a log-out began or ran since, in which case the
// caller answers 409 and changes nothing; otherwise the caller holds the
// transition until it calls the returned release.
func (l *theLock) beginChange(gen0 uint64) (release func(), ok bool) {
	l.transition.Lock()
	if l.isLocking() || l.generation() != gen0 {
		l.transition.Unlock()
		return nil, false
	}
	return l.transition.Unlock, true
}

func newTheLock(sess *lockgate.Session) *theLock {
	l := &theLock{sess: sess, flights: map[*flight]struct{}{}, conns: map[*trackedConn]struct{}{}, drainWithin: DrainWithin}
	l.drained = sync.NewCond(&l.mu)
	return l
}

// flightWriter lets a lock make an answer that has not been sent yet never be
// sent: after the lock cancels a request, nothing it writes reaches the caller,
// so a signature the lock interrupted is never completed (ADR-074 section 5).
type flightWriter struct {
	http.ResponseWriter
	mu      sync.Mutex
	dead    bool
	started bool
	lock    *theLock
	f       *flight
}

func (w *flightWriter) kill() {
	w.mu.Lock()
	w.dead = true
	w.mu.Unlock()
}

func (w *flightWriter) WriteHeader(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dead {
		return
	}
	w.started = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *flightWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dead {
		return 0, errors.New("identity is locked")
	}
	w.started = true
	return w.ResponseWriter.Write(b)
}

func (w *flightWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dead {
		return
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *flightWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// trackedConn is a taken-over connection the lock can close. Closing it by any
// route takes it out of the lock's set, so the set holds only open connections.
type trackedConn struct {
	net.Conn
	lock *theLock
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.lock.mu.Lock()
		delete(c.lock.conns, c)
		c.lock.mu.Unlock()
	})
	return c.Conn.Close()
}

// Hijack hands the connection to a streaming handler (a websocket). The request
// is then no longer one the lock can wait for, so it leaves the count and its
// connection is closed when the lock fires. A request the lock has already
// cancelled may not take one over: the lock has closed the connections it knew
// of, so one taken after would never be closed.
func (w *flightWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("this connection cannot be taken over")
	}
	// The lock cancels a request (kill) under lock.mu, and a connection is
	// added to the set under it, so one of the two always sees the other.
	w.lock.mu.Lock()
	w.mu.Lock()
	dead := w.dead
	w.mu.Unlock()
	w.lock.mu.Unlock()
	if dead {
		return nil, nil, errors.New("identity is locked")
	}
	c, rw, err := h.Hijack()
	if err != nil {
		return nil, nil, err
	}
	tc := &trackedConn{Conn: c, lock: w.lock}
	w.lock.mu.Lock()
	w.mu.Lock()
	dead = w.dead
	w.mu.Unlock()
	if !dead {
		w.lock.conns[tc] = struct{}{}
	}
	w.lock.mu.Unlock()
	if dead {
		_ = c.Close()
		return nil, nil, errors.New("identity is locked")
	}
	w.lock.leave(w.f)
	return tc, rw, nil
}

func (l *theLock) leave(f *flight) {
	l.mu.Lock()
	if _, ok := l.flights[f]; ok {
		delete(l.flights, f)
		l.drained.Broadcast()
	}
	l.mu.Unlock()
}

func refuseLocked(w http.ResponseWriter) {
	// 423 Locked: not "unauthorised" (the caller may be the owner) and not
	// "not found" (the route exists).
	writeError(w, http.StatusLocked, "identity is locked",
		"log in to this identity before using it")
}

// guard is the middleware: a locked or locking core answers only the lock
// routes; an open one counts what is running so a lock can wait for it.
func (l *theLock) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isALockRoute(r.URL.Path) || isTheHealthProbe(r) {
			next.ServeHTTP(w, r)
			return
		}
		if l.sess.State() == lockgate.StateUngated {
			if l.startedGated {
				refuseLocked(w)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		l.mu.Lock()
		if l.locking || l.sess.State() != lockgate.StateOpen {
			l.mu.Unlock()
			refuseLocked(w)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		f := &flight{cancel: cancel}
		fw := &flightWriter{ResponseWriter: w, lock: l, f: f}
		f.w = fw
		l.flights[f] = struct{}{}
		l.mu.Unlock()
		defer func() {
			cancel()
			l.leave(f)
		}()
		next.ServeHTTP(fw, r.WithContext(ctx))
		fw.mu.Lock()
		cancelled, started := fw.dead, fw.started
		fw.mu.Unlock()
		if cancelled && !started {
			refuseLocked(w)
		}
	})
}

// lockNow is the lock: refuse new requests, give those running DrainWithin,
// cancel what is left, then delete the device-held key. If that fails the
// identity is still open and serving again, and the error says so.
func (l *theLock) lockNow() error {
	l.mu.Lock()
	if l.sess.State() == lockgate.StateLocked {
		l.mu.Unlock()
		return nil
	}
	if l.locking {
		l.mu.Unlock()
		return errAlreadyLocking
	}
	l.locking = true
	l.gen++
	l.mu.Unlock()
	// Taken after locking is set, so no new change is admitted, and held to the
	// end, so one already running finishes before the key is dropped and one
	// waiting finds the log-out done and is refused (beginChange).
	l.transition.Lock()
	defer l.transition.Unlock()
	// Runs last, once locking is cleared: work refuses to start while a lock is
	// in progress.
	startAgain := false
	defer func() {
		if startAgain && l.resumeWork != nil {
			l.resumeWork()
		}
	}()
	defer func() { l.mu.Lock(); l.locking = false; l.mu.Unlock() }()

	if !l.waitForFlights(l.drainWithin) {
		l.mu.Lock()
		for f := range l.flights {
			f.w.kill()
			f.cancel()
		}
		l.mu.Unlock()
		l.waitForFlights(cancelGrace)
	}
	// The work that needs the key ends before the key goes, so nothing is
	// signing as the key is dropped. If the key cannot be dropped the identity
	// is still open and the work starts again.
	if l.endWork != nil {
		l.endWork()
	}
	if err := l.sess.Lock(); err != nil {
		startAgain = true
		return err
	}
	l.mu.Lock()
	open := make([]*trackedConn, 0, len(l.conns))
	for c := range l.conns {
		open = append(open, c)
	}
	l.mu.Unlock()
	for _, c := range open {
		_ = c.Close() // takes it out of the set
	}
	return nil
}

func (l *theLock) waitForFlights(within time.Duration) bool {
	deadline := time.Now().Add(within)
	timer := time.AfterFunc(within, func() { l.mu.Lock(); l.drained.Broadcast(); l.mu.Unlock() })
	defer timer.Stop()
	l.mu.Lock()
	defer l.mu.Unlock()
	for len(l.flights) > 0 {
		if !time.Now().Before(deadline) {
			return false
		}
		l.drained.Wait()
	}
	return true
}

// refuseWhileLocked is the middleware the router installs.
func (s *CoreServer) refuseWhileLocked(next http.Handler) http.Handler {
	if s.lock == nil {
		return next
	}
	return s.lock.guard(next)
}

// settleTheLock decides what state a core starts in. A new profile is gated and
// open. A profile with a gate and a device-held key reopens by reading it, with
// nobody present. A profile with a gate and no device-held key stays locked. A
// profile made before gates (it has a seed and no gate) is served as it was, and
// says so: moving it is a migration, not something a start does.
func (s *CoreServer) settleTheLock(cfg Config) {
	if cfg.DataDir == "" {
		return
	}
	lockgate.Install()
	id := cfg.ProfileID
	if id == "" {
		id = filepath.Base(cfg.DataDir)
	}
	mode := s.theGateModeFor(cfg)
	p := lockgate.OpenProfile(cfg.DataDir, id)
	if mode == lockgate.ModeNone && !p.Gated() {
		// A Linux core (the black box or a development box): not gated, and said so.
		return
	}
	if mode == lockgate.ModeNone {
		// A Linux profile that already has a gate keeps one, and the stricter
		// kind: it never becomes a phone, which would score itself.
		mode = lockgate.ModeController
	}
	g := &lockgate.Gate{Mode: mode, VerifyVoucher: lockgate.VoucherFromRootDevice(s.theKeyEntitledToVouch,
		s.thisIdentityAgentsIdentifier, s.thisMachinesControllerIdentifier)}
	sess := lockgate.NewSession(p, g)
	switch {
	case p.Gated():
		if err := sess.Reopen(); err != nil {
			log.Printf("[identity-agent-core] this identity stays locked: %v", err)
		}
	case !aSeedIsStoredAt(cfg.DataDir):
		// Made now: it must be gated before it stores anything. If Found fails
		// the store refuses (not ungated forever), and the next start retries.
		lockgate.RequireFounding(cfg.DataDir, sess)
		if err := sess.Found(); err != nil {
			log.Printf("[identity-agent-core] this identity has no gate and is NOT locked by anything: %v", err)
		}
	default:
		log.Printf("[identity-agent-core] this identity was made before gates: it is not locked by anything until it is moved")
	}
	s.lock = newTheLock(sess)
	s.lock.endWork = s.endSeedWork
	s.lock.resumeWork = s.startWhatNeedsTheIdentity
	s.lock.startedGated = sess.State() != lockgate.StateUngated
}

// thisPlatformGOOS is the platform the core decides its role by. A variable so
// a test can be a desktop on any machine.
var thisPlatformGOOS = runtime.GOOS

// theGateModeFor decides the mode from the platform first. What the app or the
// environment asked for can only add a gate on Linux; on a Mac or Windows
// computer only controller is accepted, and on a phone only root-device. A box
// identity (a file a process could plant, or one this core made) counts only on
// Linux: anywhere else it is ignored and logged.
func (s *CoreServer) theGateModeFor(cfg Config) lockgate.Mode {
	platform := s.theGateModeOfThisPlatform(cfg.DataDir)
	asked := cfg.GateMode
	if asked == "" || asked == platform {
		return platform
	}
	switch thisPlatformGOOS {
	case "darwin", "windows", "ios", "android":
		log.Printf("[identity-agent-core] ignoring the requested gate mode %q: this platform is always %q", asked, platform)
		return platform
	}
	return asked
}

// theGateModeOfThisPlatform is the role this core has when nobody said: a Mac or
// Windows computer is a controller whose log-in must be vouched for by its
// person's root device (a machine may not score itself, ADR-074 section 2); a
// phone holds the root; only a Linux core (the sealed black box, or a
// development box) may be ModeNone.
func (s *CoreServer) theGateModeOfThisPlatform(dataDir string) lockgate.Mode {
	switch thisPlatformGOOS {
	case "darwin", "windows":
		s.noteAnIgnoredBoxIdentity(dataDir)
		return lockgate.ModeController
	case "ios", "android":
		s.noteAnIgnoredBoxIdentity(dataDir)
		return lockgate.ModePhone
	}
	return lockgate.ModeNone
}

func (s *CoreServer) noteAnIgnoredBoxIdentity(dataDir string) {
	if _, err := os.Stat(filepath.Join(dataDir, boxIdentityFile)); err == nil || s.boxIdentity != nil {
		log.Printf("[identity-agent-core] a box identity is present but this is not a black box: ignored, the gate stays")
	}
}

// thisMachinesControllerIdentifier is the identifier this computer signs as a
// controller, the one a voucher names. Not the black box's identity, which is
// nil on a desktop. Read when a voucher is checked, not at start, since reading
// the key can reach the keychain.
func (s *CoreServer) thisMachinesControllerIdentifier() string {
	return theControllerIdentifierOf(s)
}

// theControllerIdentifierOf reads the platform's controller key. A variable so a
// test can stand in for the hardware this machine lacks.
var theControllerIdentifierOf = func(s *CoreServer) string {
	id, err := s.thisMachineAsAController()
	if err != nil {
		return ""
	}
	return id.AID
}

func aSeedIsStoredAt(dataDir string) bool {
	_, _, _, err := secureenclave.RootSeedProtection(dataDir)
	return err == nil
}

// startWhatNeedsTheIdentityIfOpen starts the work that reads the seed, unless the
// identity is locked, in which case unlock starts it.
func (s *CoreServer) startWhatNeedsTheIdentityIfOpen() {
	if s.lock != nil && s.lock.sess.State() == lockgate.StateLocked {
		return
	}
	s.startWhatNeedsTheIdentity()
}

func (s *CoreServer) startWhatNeedsTheIdentity() {
	if s.lock != nil {
		s.lock.mu.Lock()
		if s.lock.workStarted {
			s.lock.mu.Unlock()
			return
		}
		s.lock.workStarted = true
		s.lock.mu.Unlock()
	}
	// Everything below runs in the open period's scope, so a lock ends it and
	// an unlock starts it again (the_lock_work.go).

	// Machines granted as an app's back end before an app signed as itself are
	// withdrawn, so no credential of this identity still says they act for it.
	s.runSeedWork(func(context.Context, <-chan struct{}) { s.withdrawTheGrantsOfRetiredAppBackEnds() })

	if cfg, err := s.backupService().LoadConfig(); err == nil && cfg.Enabled && cfg.ScheduleDaily {
		// Give the scheduler a way to reach this agent's own seed, or every
		// backup it schedules will skip. It reads the seed rather than asking
		// for the words: an agent has the first and never has the second, and a
		// backup that waits to be typed at is not a backup.
		s.backupService().Scheduler.SetSeedProvider(func() ([]byte, error) {
			return secureenclave.LoadRootSeed(s.DataDir)
		})
		s.backupService().Scheduler.StartDaily()
	}

	// Bring up the URL relay when one is configured. It is the single URL
	// manager: a live relay allocation is a durable, provably-ours address, so
	// EndpointService ranks it above the ephemeral tunnel. Absent a configured
	// relay this returns immediately, leaving the tunnel/direct path in place.
	s.runSeedWork(func(ctx context.Context, _ <-chan struct{}) { s.startRelayUnder(ctx) })
	s.beginWitnessing()
	s.runSeedWork(func(_ context.Context, stop <-chan struct{}) { s.keepAnchoring(stop) })
	s.runSeedWork(func(context.Context, <-chan struct{}) { s.backfillRegistryEvents() })
	s.runAddons()
	// Witnessing asked for while locked waits in its jobs; start its worker.
	s.witnessing.witnessMu.Lock()
	waiting := len(s.witnessing.witnessJobs) > 0
	s.witnessing.witnessMu.Unlock()
	if waiting {
		s.kickWitnessing()
	}
}

// ---- routes ----

type lockStateReply struct {
	State string `json:"state"`
	// LockClass says what the lock is worth. Never "provider_bound" until a real
	// provider has released the key (ADR-074 section 4).
	LockClass string `json:"lock_class"`
	// HardwareLayer says whether the key is held under a platform hardware key
	// on this build. False in a development build with none.
	HardwareLayer bool `json:"hardware_layer"`
	// SecretSet says the owner set the optional identity secret.
	SecretSet bool   `json:"secret_set"`
	Profile   string `json:"profile"`
	// MinimumScore is what a log-in must measure to open it.
	MinimumScore int `json:"minimum_score"`
	// Statement is what the lock does and does not protect, in words a screen
	// can show unchanged.
	Statement string `json:"statement"`
}

func lockStatement(class lockgate.LockClass, hardware bool) string {
	noHW := ""
	if !hardware {
		noHW = " This build has no hardware key to keep the lock key in, so a copy of this identity's files could also open it."
	}
	switch class {
	case lockgate.ClassAppOnly:
		return "This identity is locked by the app only. Nothing measures who is logging in yet, so the lock is not protection against someone using this device as you." + noHW
	case lockgate.ClassSecretBound:
		return "This identity is locked by the app and by a secret only you know. Wrong secrets are slowed down in this app, but a program running as you on this device can still try secrets offline without the slowing. After a crash while the secret was being changed, the new lock key is also kept under this device's hardware key until the next start or log-out finishes the change." + noHW
	case lockgate.ClassProviderBound:
		return "This identity is locked until the authentication provider confirms it is you."
	case lockgate.ClassBroken:
		return "This identity is locked, but its lock record is missing or unreadable, so it cannot be opened here. Restore it from the recovery phrase."
	}
	return "Nothing locks this identity. It was made before locking existed."
}

func (s *CoreServer) lockState() lockStateReply {
	if s.lock == nil {
		return lockStateReply{State: string(lockgate.StateUngated), LockClass: string(lockgate.ClassNone),
			MinimumScore: permission.DefaultMinimumScore, Statement: lockStatement(lockgate.ClassNone, false)}
	}
	p := s.lock.sess.P
	class := p.Class()
	return lockStateReply{State: string(s.lock.sess.State()), LockClass: string(class),
		HardwareLayer: p.HardwareHeld(), SecretSet: p.HasSecret(), Profile: p.ID(),
		MinimumScore: permission.DefaultMinimumScore, Statement: lockStatement(class, p.HardwareHeld())}
}

func (s *CoreServer) mountLockRoutes(r interface {
	Get(string, http.HandlerFunc)
	Post(string, http.HandlerFunc)
	Put(string, http.HandlerFunc)
	Delete(string, http.HandlerFunc)
}) {
	r.Get("/lock/state", s.handleLockState)
	r.Post("/lock/unlock", s.handleLockUnlock)
	r.Post("/lock/lock", s.handleLockLock)
	r.Put("/lock/secret", s.handleLockSecret)
	r.Delete("/lock/secret", s.handleLockSecret)
}

func (s *CoreServer) handleLockState(w http.ResponseWriter, r *http.Request) {
	if !s.presentsLocalOwnerSecret(r) {
		writeError(w, http.StatusForbidden, "only the owner at this computer may ask", "")
		return
	}
	writeJSON(w, s.lockState())
}

type unlockBody struct {
	lockgate.ProviderResult
	Secret string `json:"secret,omitempty"`
}

func (s *CoreServer) handleLockUnlock(w http.ResponseWriter, r *http.Request) {
	// The owner proof is required here, in the handler, whatever the router
	// says about the route. Under app_only any process running as the owner can
	// read it, so this keeps out other users, other machines and web pages and
	// does not keep out the owner's own code (ADR-074 section 2).
	if !s.presentsLocalOwnerSecret(r) {
		writeError(w, http.StatusForbidden, "only the owner at this computer may log in", "")
		return
	}
	if s.lock == nil || s.lock.sess.State() == lockgate.StateUngated {
		writeError(w, http.StatusConflict, "this identity has no lock", "")
		return
	}
	gen0 := s.lock.generation()
	if s.lock.isLocking() {
		writeError(w, http.StatusConflict, "a log-out is in progress", "try again once it has finished")
		return
	}
	var b unlockBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "the log-in result is unreadable", err.Error())
		return
	}
	// A result the provider produced now. The placeholder is the only provider
	// there is, so it is named as itself when the app did not say.
	if b.Provider == "" {
		b.Provider = authprovider.PlaceholderProvider
	}
	release, ok := s.lock.beginChange(gen0)
	if !ok {
		writeError(w, http.StatusConflict, "a log-out happened while this log-in was arriving", "log in again")
		return
	}
	err := s.lock.sess.Unlock(b.ProviderResult, b.Secret)
	release()
	if err != nil {
		status, msg := lockRefusal(err)
		var d *lockgate.DelayedError
		if errors.As(err, &d) {
			w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())+1))
		}
		writeError(w, status, msg, err.Error())
		return
	}
	s.startWhatNeedsTheIdentity()
	writeJSON(w, s.lockState())
}

// lockRefusal turns the gate's refusal into a status and a plain sentence.
func lockRefusal(err error) (int, string) {
	var d *lockgate.DelayedError
	switch {
	case errors.As(err, &d):
		return http.StatusTooManyRequests, "too many wrong secrets: wait before trying again"
	case errors.Is(err, lockgate.ErrSecretNeeded), errors.Is(err, lockgate.ErrWrongSecret):
		return http.StatusUnauthorized, "this identity's secret is needed, and that one is not it"
	case errors.Is(err, lockgate.ErrBelowMinimum), errors.Is(err, lockgate.ErrUnmeasured),
		errors.Is(err, lockgate.ErrNeedsVoucher), errors.Is(err, lockgate.ErrBadVoucher):
		return http.StatusUnauthorized, "the log-in did not pass"
	case errors.Is(err, lockgate.ErrStale), errors.Is(err, lockgate.ErrReplayed), errors.Is(err, lockgate.ErrNoNonce),
		errors.Is(err, lockgate.ErrWrongProfile):
		return http.StatusBadRequest, "that log-in result cannot be used"
	}
	return http.StatusInternalServerError, "could not log in"
}

func (s *CoreServer) handleLockLock(w http.ResponseWriter, r *http.Request) {
	if !s.presentsLocalOwnerSecret(r) {
		writeError(w, http.StatusForbidden, "only the owner at this computer may log out", "")
		return
	}
	if s.lock == nil || s.lock.sess.State() == lockgate.StateUngated {
		writeError(w, http.StatusConflict, "this identity has no lock", "")
		return
	}
	if err := s.lock.lockNow(); errors.Is(err, errAlreadyLocking) {
		writeError(w, http.StatusConflict, "a log-out is already in progress", "")
		return
	} else if err != nil {
		// The identity is still open and serving: say so, plainly.
		writeError(w, http.StatusInternalServerError, "not logged out: the identity is still open", err.Error())
		return
	}
	writeJSON(w, s.lockState())
}

type secretBody struct {
	Current string `json:"current,omitempty"`
	New     string `json:"new,omitempty"`
}

func (s *CoreServer) handleLockSecret(w http.ResponseWriter, r *http.Request) {
	if !s.presentsLocalOwnerSecret(r) {
		writeError(w, http.StatusForbidden, "only the owner at this computer may change the secret", "")
		return
	}
	if s.lock == nil || s.lock.sess.State() != lockgate.StateOpen {
		writeError(w, http.StatusLocked, "identity is locked", "log in first")
		return
	}
	gen0 := s.lock.generation()
	if s.lock.isLocking() {
		writeError(w, http.StatusConflict, "a log-out is in progress", "try again once it has finished")
		return
	}
	var b secretBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&b); err != nil {
		writeError(w, http.StatusBadRequest, "unreadable", err.Error())
		return
	}
	next := b.New
	if r.Method == http.MethodDelete {
		next = ""
	} else if next == "" {
		writeError(w, http.StatusBadRequest, "a new secret is needed", "")
		return
	}
	release, ok := s.lock.beginChange(gen0)
	if !ok {
		writeError(w, http.StatusConflict, "a log-out happened while this change was arriving", "log in and try again")
		return
	}
	err := s.lock.sess.ChangeSecret(b.Current, next)
	release()
	if err != nil {
		status, msg := lockRefusal(err)
		writeError(w, status, msg, err.Error())
		return
	}
	writeJSON(w, s.lockState())
}
