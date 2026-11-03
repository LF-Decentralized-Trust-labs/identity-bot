package appmanifest

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"identity-agent-core/internal/strictjson"
)

// DecodeManifest reads a manifest from its JSON as the published schema
// (contracts/app-manifest/app-manifest.schema.json) reads it, and does not
// validate it: call Validate on the result.
//
// encoding/json alone is more lenient than the schema, in ways that matter to
// a contract: it drops a key it does not know (so a misspelt "placment" would
// vanish and the app would be placed by default), it matches key names
// without regard to case, and it reads null as absent. A manifest is refused
// for:
//   - a key the schema does not declare, at any depth, or one spelt in
//     another case, a key named twice, or a whole number written any way but
//     plainly (internal/strictjson);
//   - null, except for the keys the schema allows it on (signature,
//     publisher_key, signature_algorithm, api_schema, binary.args and
//     binary.environment): a key that has no value is left out, so there is
//     one way to say "absent";
//   - an empty string for kind, sub_type, isolation, release_digest,
//     encrypted_machine or placement, none of which has "" among its values.
//
// A refusal of a null or an empty string begins with the dotted path of the
// key it is about.
func DecodeManifest(data []byte) (*AppManifest, error) {
	var m AppManifest
	if err := strictjson.Decode(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	if err := checkValues(doc, ""); err != nil {
		return nil, err
	}
	return &m, nil
}

// nullable lists the paths whose schema allows null.
var nullable = map[string]bool{
	"signature":           true,
	"publisher_key":       true,
	"signature_algorithm": true,
	"api_schema":          true,
	"binary.args":         true,
	"binary.environment":  true,
}

// notEmpty lists the top-level string keys whose schema has no "" value.
var notEmpty = map[string]bool{
	"kind": true, "sub_type": true, "isolation": true,
	"release_digest": true, "encrypted_machine": true, "placement": true,
}

// checkValues walks the document in sorted key order, so the first fault
// reported does not depend on map order.
func checkValues(v any, path string) error {
	switch v := v.(type) {
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(v)) {
			here := key
			if path != "" {
				here = path + "." + key
			}
			switch {
			case v[key] == nil && !nullable[here]:
				return fmt.Errorf("%s: null is not a value; leave the key out", here)
			case path == "" && notEmpty[key] && v[key] == "":
				return fmt.Errorf("%s: must not be empty; leave the key out", here)
			}
			if err := checkValues(v[key], here); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			here := fmt.Sprintf("%s[%d]", path, i)
			if item == nil {
				return fmt.Errorf("%s: null is not a value", here)
			}
			if err := checkValues(item, here); err != nil {
				return err
			}
		}
	}
	return nil
}
