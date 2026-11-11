package watcher

import (
	"context"
	"testing"
)

// Failed before: /public/kel-digest gave anyone the digest and first-seen time
// for every identity held, so contacts and meeting times could be listed.
func TestADigestIsGivenOnlyByAnOptedInPublicWatcherService(t *testing.T) {
	k := newTestWatcherKey(7)
	url, serving := servedBy(t, &k, nil)
	seen(t, serving, "EAlice", 0, "abcd")
	c := clientTrusting(k)
	if err := serving.Store.SetConfig(configPublicWatcher, "false"); err != nil {
		t.Fatal(err)
	}

	// Not opted in: the signed "never seen" answer, which a client accepts.
	got, _, err := c.QueryDigest(context.Background(), url, "EAlice", 0)
	if err != nil {
		t.Fatalf("the never-seen answer was not a valid signed answer: %v", err)
	}
	if got.Digest != nil || got.FirstSeenAt != nil || got.ObservedSince != nil {
		t.Fatalf("an agent that is not a public watcher service gave %+v", got)
	}
	never, _, err := c.QueryDigest(context.Background(), url, "ENeverMet", 0)
	if err != nil || never.Digest != nil {
		t.Fatalf("control: %+v, %v", never, err)
	}

	if err := serving.Store.SetConfig(configPublicWatcher, "true"); err != nil {
		t.Fatal(err)
	}
	got, _, err = c.QueryDigest(context.Background(), url, "EAlice", 0)
	if err != nil || got.Digest == nil || *got.Digest != "abcd" || got.FirstSeenAt == nil {
		t.Fatalf("an opted-in public watcher service did not answer: %+v, %v", got, err)
	}
	// Opting an identity out still hides it, in public mode too.
	if err := serving.Store.SetOptOut("EAlice", true); err != nil {
		t.Fatal(err)
	}
	got, _, _ = c.QueryDigest(context.Background(), url, "EAlice", 0)
	if got == nil || got.Digest != nil {
		t.Fatalf("an opted-out identity was given: %+v", got)
	}
}

func TestBeingAPublicWatcherServiceIsOffUnlessTheOwnerSaidSo(t *testing.T) {
	s := storedService(t)
	if s.PublicWatcherService() {
		t.Fatal("on by default")
	}
	for _, v := range []string{"", "yes please", "false"} {
		_ = s.Store.SetConfig(configPublicWatcher, v)
		if s.PublicWatcherService() {
			t.Fatalf("%q turned it on", v)
		}
	}
	_ = s.Store.SetConfig(configPublicWatcher, "true")
	if !s.PublicWatcherService() {
		t.Fatal("true did not turn it on")
	}
	if (&Service{}).PublicWatcherService() {
		t.Fatal("a watcher with no store is a public service")
	}
}
