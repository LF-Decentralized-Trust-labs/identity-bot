package witness

import (
	"encoding/base64"
	"testing"
)

// The bytes of a record are decoded the way the verdict decodes them, so a
// spelling the verdict would refuse is not read as an inception here.
func TestInceptionIsReadOnlyFromBytesTheVerdictCouldDecode(t *testing.T) {
	raw := []byte(`{"t":"icp","s":"0"}`)
	std := base64.StdEncoding.EncodeToString(raw)
	if _, _, ok := InceptionOf([]map[string]interface{}{{"raw_bytes_b64": std}}); !ok {
		t.Fatal("standard base64 was not read")
	}
	url := base64.RawURLEncoding.EncodeToString([]byte(`{"t":"icp","s":"0","x":"??>>"}`))
	if _, _, ok := InceptionOf([]map[string]interface{}{{"raw_bytes_b64": url}}); ok {
		t.Fatal("a spelling the verdict does not accept was read")
	}
}
