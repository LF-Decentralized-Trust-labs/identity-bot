package schemas

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"identity-agent-core/internal/contractcheck"

	keri "github.com/grapeid/keri-go"
)

// The asset grant schemas are published in contracts/asset-grants, one file
// per schema, byte for byte as this package builds them: a verifier digests
// the exact bytes to confirm a credential names this schema, so a copy that
// differed by a space would be a different schema.

const grantContracts = "../contracts/asset-grants"

// publishedGrantFiles names each schema's file. Every schema built from the
// asset template is published, current and first versions alike, because a
// credential issued under either can be presented.
var publishedGrantFiles = map[*AssetGrant]string{
	AIAgentGrant:    "ai-agent-grant-1.1.0.schema.json",
	AIAgentGrantV1:  "ai-agent-grant-1.0.0.schema.json",
	AIAgentBody:     "ai-agent-body-1.1.0.schema.json",
	AIAgentBodyV1:   "ai-agent-body-1.0.0.schema.json",
	ControllerGrant: "controller-grant-1.1.0.schema.json",
}

func TestThePublishedGrantSchemasAreTheOnesBuilt(t *testing.T) {
	if contractcheck.Writing(t) {
		for g, name := range publishedGrantFiles {
			if err := os.WriteFile(filepath.Join(grantContracts, name), []byte(g.Schema.JSON), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(publishedGrantFiles) != len(assetCredentials) {
		t.Fatalf("%d schemas are built from the asset template and %d are published",
			len(assetCredentials), len(publishedGrantFiles))
	}
	want := []string{}
	for _, g := range assetCredentials {
		name, ok := publishedGrantFiles[g]
		if !ok {
			t.Fatalf("%s (%s) is not published", g.Schema.Name, g.Schema.SAID)
		}
		want = append(want, name)
		raw, err := os.ReadFile(filepath.Join(grantContracts, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != g.Schema.JSON {
			t.Fatalf("%s is not the %s schema this package builds. Regenerate it with "+
				"IA_WRITE_CONTRACTS=1 go test ./schemas, and treat a changed identifier as a new schema version.",
				name, g.Schema.Name)
		}
		said, err := keri.VerifySchema(raw)
		if err != nil || said != g.Schema.SAID {
			t.Fatalf("%s digests to %q (%v), not %s", name, said, err, g.Schema.SAID)
		}
	}
	// Nothing else sits in the directory claiming to be a grant schema.
	entries, err := filepath.Glob(filepath.Join(grantContracts, "*.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, filepath.Base(e))
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("contracts/asset-grants holds %v, but only %v are built", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("contracts/asset-grants holds %v, but only %v are built", got, want)
		}
	}
}
