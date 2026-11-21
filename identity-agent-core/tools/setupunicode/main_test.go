package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A handful of characters stand for the database: enough to hold the tool to
// what it takes from each file, and to what it leaves out.
var someFiles = map[string]string{
	"UnicodeData.txt": strings.Join([]string{
		"0020;SPACE;Zs;0;WS;;;;;N;;;;;",
		"0041;LATIN CAPITAL LETTER A;Lu;0;L;;;;;N;;;;0061;",
		"0061;LATIN SMALL LETTER A;Ll;0;L;;;;;N;;;0041;;0041",
		"00A0;NO-BREAK SPACE;Zs;0;CS;<noBreak> 0020;;;;N;NON-BREAKING SPACE;;;;",
		"00C5;LATIN CAPITAL LETTER A WITH RING ABOVE;Lu;0;L;0041 030A;;;;N;LATIN CAPITAL LETTER A RING;;;00E5;",
		"0301;COMBINING ACUTE ACCENT;Mn;230;NSM;;;;;N;NON-SPACING ACUTE;;;;",
		"030A;COMBINING RING ABOVE;Mn;230;NSM;;;;;N;NON-SPACING RING ABOVE;;;;",
		"0344;COMBINING GREEK DIALYTIKA TONOS;Mn;230;NSM;0308 0301;;;;N;GREEK NON-SPACING DIAERESIS TONOS;;;;",
		"200D;ZERO WIDTH JOINER;Cf;0;BN;;;;;N;;;;;",
		"212B;ANGSTROM SIGN;Lu;0;L;00C5;;;;N;ANGSTROM UNIT;;;00E5;",
		"3400;<CJK Ideograph Extension A, First>;Lo;0;L;;;;;N;;;;;",
		"3402;<CJK Ideograph Extension A, Last>;Lo;0;L;;;;;N;;;;;",
		"FB01;LATIN SMALL LIGATURE FI;Ll;0;L;<compat> 0066 0069;;;;N;;;;;",
		"FE0F;VARIATION SELECTOR-16;Mn;0;NSM;;;;;N;;;;;",
		"",
	}, "\n"),
	"CaseFolding.txt":                  "# a comment\n0041; C; 0061; # LATIN CAPITAL LETTER A\n00DF; F; 0073 0073; # full, not taken\n0130; T; 0069; # Turkic, not taken\n",
	"CompositionExclusions.txt":        "0344 # excluded\n",
	"extracted/DerivedJoiningType.txt": "0041..0061 ; D # made up for the test\n0301 ; T\n200D ; C\n",
	"emoji/emoji-data.txt":             "0041 ; Emoji # made up for the test\n0061 ; Emoji_Presentation\n",
}

func TestTheFactsAreWhatTheDataFilesSay(t *testing.T) {
	in, out := t.TempDir(), t.TempDir()
	for name, text := range someFiles {
		path := filepath.Join(in, name)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	make15(in, out, "15.0.0")
	raw, err := os.ReadFile(filepath.Join(out, "unicode-15.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("what was written is not JSON: %v", err)
	}
	for member, want := range map[string]string{
		// A space other than U+0020, a format character and a variation
		// selector are not seen as themselves.
		"seen":    "[[32,32],[65,65],[97,97],[197,197],[769,769],[778,778],[836,836],[8491,8491],[13312,13314],[64257,64257]]",
		"letters": "[[65,65],[97,97],[197,197],[8491,8491],[13312,13314],[64257,64257]]",
		"marks":   "[[769,769],[778,778],[836,836],[65039,65039]]",
		"script":  `[[65,65,"LATIN"],[97,97,"LATIN"],[197,197,"LATIN"],[769,769,"COMBINING"],[778,778,"COMBINING"],[836,836,"COMBINING"],[8491,8491,"ANGSTROM"],[13312,13314,"CJK"],[64257,64257,"LATIN"],[65039,65039,"VARIATION"]]`,
		"ccc":     "[[769,769,230],[778,778,230],[836,836,230]]",
		// A decomposition is written out in full, and a compatibility one
		// only where it is not the canonical one.
		"nfd":  "[[197,65,778],[836,776,769],[8491,65,778]]",
		"nfkd": "[[160,32],[64257,102,105]]",
		// A singleton and an excluded pair are not composites.
		"compose": "[[65,778,197]]",
		// Simple case folding only.
		"fold":    "[[65,97]]",
		"joining": `[[65,97,"D"],[769,769,"T"]]`,
		"emoji":   "[[65,65]]",
	} {
		var got any
		_ = json.Unmarshal(d[member], &got)
		compact, _ := json.Marshal(got)
		if string(compact) != want {
			t.Errorf("%s is %s, wanted %s", member, compact, want)
		}
	}
	// One range to a line, so a later version is a diff a person can read.
	if !strings.Contains(string(raw), "\n  [13312,13314],\n") {
		t.Error("the facts are not written one range to a line")
	}
	// Written again from the same files, it is the same bytes.
	again := t.TempDir()
	make15(in, again, "15.0.0")
	for _, name := range []string{"unicode-15.0.json", "unicode-15.0.SOURCE.txt"} {
		a, _ := os.ReadFile(filepath.Join(out, name))
		b, _ := os.ReadFile(filepath.Join(again, name))
		if string(a) != string(b) || len(a) == 0 {
			t.Errorf("%s is not the same written twice", name)
		}
	}
	// The source note names each file with its digest, and carries the
	// licence's copyright and permission notice word for word.
	note, _ := os.ReadFile(filepath.Join(out, "unicode-15.0.SOURCE.txt"))
	if !strings.Contains(string(note), licence) || !strings.Contains(licence, "this copyright and permission notice appear") ||
		!strings.Contains(string(note), "https://www.unicode.org/Public/15.0.0/ucd/emoji/emoji-data.txt") || strings.Count(string(note), "SHA-256 ") != len(someFiles) {
		t.Errorf("the source note does not name its files and carry the licence:\n%s", note)
	}
}
