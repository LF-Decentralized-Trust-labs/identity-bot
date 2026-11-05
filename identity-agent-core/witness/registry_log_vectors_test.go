package witness

import "testing"

// The published vectors say which answers have the shape, and the Go checker
// agrees with every one of them, so an answer is held to the same shape the
// file states (and check_registry_log_vectors.py checks without this code).
func TestTheRegistryLogVectorsHold(t *testing.T) {
	v, err := LoadRegistryLogVectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Answers) < 10 || len(v.Heads) < 2 {
		t.Fatalf("the vectors are missing: %d answers, %d heads", len(v.Answers), len(v.Heads))
	}
	for _, a := range v.Answers {
		err := CheckRegistryLogAnswerShape(a.Answer)
		if (err == nil) != a.Conforms {
			t.Errorf("%s: conforms=%v but the checker says %v (%s)", a.Name, a.Conforms, err, a.Why)
		}
	}
	for _, h := range v.Heads {
		err := CheckRegistryLogHeadShape(h.Head)
		if (err == nil) != h.Conforms {
			t.Errorf("%s: conforms=%v but the checker says %v", h.Name, h.Conforms, err)
		}
	}
	if v.NoTEL.Status != 404 || v.NoTEL.Body["error"] != "no_tel" {
		t.Errorf("the no_tel answer is %+v", v.NoTEL)
	}
}
