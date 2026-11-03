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
	out := validutf8.Of(in)
	if in.A != "a\xff" || in.P.S != "p\xfe" || in.L[0].S != "l\xfd" || in.M["k\xfc"] != "v\xfb" {
		t.Fatal("the caller's value was changed")
	}
	raw, _ := json.Marshal(out)
	want := `{"A":"a` + "\uFFFD" + `","P":{"S":"p` + "\uFFFD" + `"},"L":[{"S":"l` + "\uFFFD" + `"}],"M":{"k` + "\uFFFD" + `":"v` + "\uFFFD" + `"},"I":"i` + "\uFFFD" + `"}`
	if string(raw) != want {
		t.Fatalf("got %s\nwant %s", raw, want)
	}
}
