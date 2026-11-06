package witness

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// registryLogVectors are answers a witness gives about an issuer's registry
// logs (SEAM-13 §2) and whether each has the shape, with the reason when it
// does not. It is the file another implementation tests itself against, and
// check_registry_log_vectors.py is a checker written without this code. It
// ships inside this module so a Go implementation reads the same file instead
// of keeping a copy.
//
//go:embed registry-log-vectors.json
var registryLogVectors []byte

// RegistryLogVectorSet is the published set.
type RegistryLogVectorSet struct {
	About   string `json:"about"`
	Answers []struct {
		Name     string          `json:"name"`
		Answer   json.RawMessage `json:"answer"`
		Conforms bool            `json:"conforms"`
		Why      string          `json:"why"`
	} `json:"answers"`
	Heads []struct {
		Name     string          `json:"name"`
		Head     json.RawMessage `json:"head"`
		Conforms bool            `json:"conforms"`
		Why      string          `json:"why"`
	} `json:"heads"`
	NoTEL struct {
		Status int               `json:"status"`
		Body   map[string]string `json:"body"`
	} `json:"no_tel"`
}

// LoadRegistryLogVectors reads the published set.
func LoadRegistryLogVectors() (RegistryLogVectorSet, error) {
	var v RegistryLogVectorSet
	err := json.Unmarshal(registryLogVectors, &v)
	return v, err
}

func exactKeys(m map[string]json.RawMessage, required []string, optional ...string) error {
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := m[k]; !ok {
			return fmt.Errorf("%s is required", k)
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	var extra []string
	for k := range m {
		if !allowed[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		return fmt.Errorf("%s is not part of the shape", strings.Join(extra, ", "))
	}
	return nil
}

func wholeNumber(raw json.RawMessage) (int, bool) {
	var n int
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	var num json.Number
	if d.Decode(&num) != nil {
		return 0, false
	}
	i, err := num.Int64()
	n = int(i)
	return n, err == nil
}

// CheckRegistryLogAnswerShape says whether raw is the body of a 200 answer to
// GET /witness/tel/{aid}: the shape, and nothing about whether the events are
// the issuer's, which only the issuer's key log can say.
func CheckRegistryLogAnswerShape(raw []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("not an object")
	}
	if err := exactKeys(m, []string{"aid", "registry_prefix", "events", "anchored_sn", "latest_kel_sn"}, "registries"); err != nil {
		return err
	}
	var aid, prefix string
	if json.Unmarshal(m["aid"], &aid) != nil || aid == "" {
		return fmt.Errorf("aid is a non-empty string")
	}
	if json.Unmarshal(m["registry_prefix"], &prefix) != nil || prefix == "" {
		return fmt.Errorf("registry_prefix is a non-empty string")
	}
	anchored, ok1 := wholeNumber(m["anchored_sn"])
	latest, ok2 := wholeNumber(m["latest_kel_sn"])
	if !ok1 || !ok2 || anchored < -1 || latest < 0 {
		return fmt.Errorf("anchored_sn and latest_kel_sn are whole numbers, a place in the key log")
	}
	if anchored > latest {
		return fmt.Errorf("anchored_sn is above latest_kel_sn")
	}
	registries := map[string]bool{prefix: true}
	if r, ok := m["registries"]; ok {
		var list []string
		if json.Unmarshal(r, &list) != nil || len(list) < 2 {
			return fmt.Errorf("registries is left out unless there are two or more")
		}
		if list[0] != prefix {
			return fmt.Errorf("registry_prefix is the first registry founded")
		}
		for _, x := range list {
			registries[x] = true
		}
	}
	var events []map[string]json.RawMessage
	if json.Unmarshal(m["events"], &events) != nil || m["events"][0] != '[' {
		return fmt.Errorf("events is an array of KERI events")
	}
	for i, e := range events {
		var t, d, id string
		_ = json.Unmarshal(e["t"], &t)
		_ = json.Unmarshal(e["d"], &d)
		_ = json.Unmarshal(e["i"], &id)
		if d == "" || id == "" {
			return fmt.Errorf("event %d is not a KERI event: it has no d and i", i)
		}
		switch t {
		case "vcp":
			if id != d || !registries[id] {
				return fmt.Errorf("event %d: a vcp names itself in i, and a registry the answer names", i)
			}
		case "iss", "rev":
			var ri string
			if json.Unmarshal(e["ri"], &ri) != nil || !registries[ri] {
				return fmt.Errorf("event %d: ri names a registry that is neither registry_prefix nor in registries", i)
			}
			if _, ok := e["dt"]; !ok {
				return fmt.Errorf("event %d: dt is required", i)
			}
			if _, ok := e["p"]; t == "rev" && !ok {
				return fmt.Errorf("event %d: a rev carries p, the event it revokes", i)
			}
		default:
			return fmt.Errorf("event %d: t is vcp, iss or rev", i)
		}
	}
	return nil
}

// CheckRegistryLogHeadShape says whether raw is the body of a 200 answer to
// GET /witness/tel/{aid}/head.
func CheckRegistryLogHeadShape(raw []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("not an object")
	}
	if err := exactKeys(m, []string{"anchored_sn", "latest_kel_sn", "event_digest"}); err != nil {
		return err
	}
	_, ok1 := wholeNumber(m["anchored_sn"])
	_, ok2 := wholeNumber(m["latest_kel_sn"])
	var digest string
	if !ok1 || !ok2 || json.Unmarshal(m["event_digest"], &digest) != nil || digest == "" {
		return fmt.Errorf("anchored_sn and latest_kel_sn are whole numbers and event_digest a non-empty string")
	}
	return nil
}
