package watcher

import "testing"

func TestKelDigestDeterministic(t *testing.T) {
	events := []map[string]interface{}{
		{"v": "KERI10JSON000256_", "t": "icp", "i": "EAlice", "s": "0", "k": []string{"Dkey1"}},
		{"v": "KERI10JSON000256_", "t": "rot", "i": "EAlice", "s": "1", "k": []string{"Dkey2"}},
	}
	d1, err := KelDigestAtSeq(events, 1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := KelDigestAtSeq(events, 1)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("digest not deterministic: %s != %s", d1, d2)
	}
	if d1 == "" || d1[0] != 'E' {
		t.Fatalf("expected Blake3 E qb64 digest, got %q", d1)
	}
}

func TestCurrentSeq(t *testing.T) {
	events := []map[string]interface{}{
		{"s": "0"}, {"s": "3"}, {"s": "1"},
	}
	if got := CurrentSeq(events); got != 3 {
		t.Fatalf("CurrentSeq = %d, want 3", got)
	}
}
