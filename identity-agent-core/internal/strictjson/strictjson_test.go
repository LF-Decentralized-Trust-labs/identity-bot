package strictjson

import (
	"strings"
	"testing"
)

type inner struct {
	Name     string `json:"name"`
	Required bool   `json:"required,omitempty"`
}

type doc struct {
	Nonce  string            `json:"nonce"`
	T      int               `json:"t"`
	Inner  *inner            `json:"inner,omitempty"`
	List   []inner           `json:"list"`
	Map    map[string]string `json:"map"`
	Any    map[string]any    `json:"any,omitempty"`
	hidden string
}

func TestADocumentIsReadOneWayOrNotAtAll(t *testing.T) {
	for _, ok := range []string{
		`{"nonce":"n","t":1}`,
		`{"t":-5,"inner":{"name":"x"},"list":[{"name":"y","required":true}]}`,
		`{"map":{"a":"1","A":"2"},"any":{"x":[1.5,{"y":null}]}}`,
		`{"nonce":"😀 é"}`,
		`{"t":9007199254740991}`,
	} {
		var d doc
		if err := Decode([]byte(ok), &d); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{"nonce":"n","Nonce":"evil"}`,       // a name in another case
		`{"NONCE":"evil"}`,                   // only in another case
		`{"nonce":"a","nonce":"b"}`,          // repeated
		`{"map":{"a":"1","a":"2"}}`,          // repeated inside a map
		`{"any":{"x":{"k":1,"k":2}}}`,        // repeated deep inside
		`{"list":[{"name":"y","Name":"z"}]}`, // in a nested struct
		`{"other":1}`,                        // unknown
		`{"hidden":"x"}`,                     // not a field encoding/json reads
		`{"nonce":"\ud800"}`,                 // half a surrogate pair
		`{"nonce":"\udc00x"}`,                // the other half alone
		`{"map":{"\ud800":"a","\ud801":"b"}}`,
		`{"nonce":"` + "\xff" + `"}`, // not UTF-8
		`{"t":1.0}`, `{"t":1e0}`, `{"t":-0}`, `{"t":01}`,
		`{"t":9007199254740993}`,
		`null`, `[]`, `"x"`,
		`{"t":1} {}`,
	} {
		var d doc
		if err := Decode([]byte(bad), &d); err == nil {
			t.Errorf("%s was read as %+v", bad, d)
		}
	}
}

// Every reader gives up at some depth, each at its own, so a document nested
// deeper than one of them will go is read by some and not others. This one
// stops at MaxDepth, the same place as the TypeScript reader.
func TestADocumentNestedTooDeepIsRefused(t *testing.T) {
	nest := func(n int, open, close string) string {
		return `{"any":{"x":` + strings.Repeat(open, n-2) + `1` + strings.Repeat(close, n-2) + `}}`
	}
	for _, c := range []struct {
		open, close string
	}{{"[", "]"}, {`{"k":`, "}"}} {
		var d doc
		if err := Decode([]byte(nest(MaxDepth, c.open, c.close)), &d); err != nil {
			t.Errorf("%d deep with %s was refused: %v", MaxDepth, c.open, err)
		}
		if err := Decode([]byte(nest(MaxDepth+1, c.open, c.close)), &d); err == nil {
			t.Errorf("%d deep with %s was read", MaxDepth+1, c.open)
		}
	}
}

func TestADocumentWithAByteOrderMarkIsRefused(t *testing.T) {
	var d doc
	if err := Decode([]byte("\xef\xbb\xbf"+`{"nonce":"n"}`), &d); err == nil {
		t.Error("a document that starts with a byte order mark was read")
	}
}
