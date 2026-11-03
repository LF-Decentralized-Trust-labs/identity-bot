package validutf8_test

import (
	"encoding/json"
	"testing"

	"identity-agent-core/internal/validutf8"
)

type inner struct{ S string }
type holder struct {
	A string
	P *inner
	L []inner
	M map[string]string
	I interface{}
}

func TestEveryStringIsMadeValidAndTheInputIsLeftAlone(t *testing.T) {
	in := holder{A: "a\xff", P: &inner{"p\xfe"}, L: []inner{{"l\xfd"}}, M: map[string]string{"k\xfc": "v\xfb"}, I: "i\xfa"}
	out, err := validutf8.Of(in)
	if err != nil {
		t.Fatal(err)
	}
	if in.A != "a\xff" || in.P.S != "p\xfe" || in.L[0].S != "l\xfd" || in.M["k\xfc"] != "v\xfb" {
		t.Fatal("the caller's value was changed")
	}
	raw, _ := json.Marshal(out)
	want := `{"A":"a` + "\uFFFD" + `","P":{"S":"p` + "\uFFFD" + `"},"L":[{"S":"l` + "\uFFFD" + `"}],"M":{"k` + "\uFFFD" + `":"v` + "\uFFFD" + `"},"I":"i` + "\uFFFD" + `"}`
	if string(raw) != want {
		t.Fatalf("got %s\nwant %s", raw, want)
	}
}

func TestTwoKeysThatDifferOnlyInBadBytesAreRefused(t *testing.T) {
	_, err := validutf8.Of(map[string]string{"a\xff": "1", "a\xfe": "2"})
	if err == nil {
		t.Fatal("two keys merged without an error")
	}
	if _, err := validutf8.Of(map[string]string{"a\xff": "1", "b": "2"}); err != nil {
		t.Fatalf("distinct keys refused: %v", err)
	}
}

type node struct {
	S    string
	Next *node
	M    map[string]interface{}
	L    []interface{}
}

func TestAValueThatReachesItselfIsRefusedNotWalkedForever(t *testing.T) {
	n := &node{S: "x\xff"}
	n.Next = n
	if _, err := validutf8.Of(n); err == nil {
		t.Fatal("cyclic pointer accepted")
	}
	m := map[string]interface{}{}
	m["self"] = m
	if _, err := validutf8.Of(node{M: m}); err == nil {
		t.Fatal("cyclic map accepted")
	}
	l := make([]interface{}, 1)
	l[0] = l
	if _, err := validutf8.Of(node{L: l}); err == nil {
		t.Fatal("cyclic slice accepted")
	}
}

func TestAValueSharedWithoutALoopIsFine(t *testing.T) {
	shared := &node{S: "s\xff"}
	out, err := validutf8.Of([]*node{shared, shared})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].S != "s\uFFFD" || out[1].S != "s\uFFFD" {
		t.Fatalf("got %q %q", out[0].S, out[1].S)
	}
}
