package setupfile

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/internal/contractcheck"
	"identity-agent-core/update"
)

// probes are values put, one at a time, at every place of a file and of a
// chosen list: each is something one reader might take one way and another
// reader another.
func probes() []any {
	long := strings.Repeat("n", MaxName+1)
	out := []any{nil, true, false, 0, 7, -1, 1.5, "", " ", []any{}, object{}, []any{"x"}, object{"x": "y"}, []any{nil},
		// Names.
		"Reader", "READER", " Reader", "Reader ", "Two  spaces", "reader@elsewhere", long, "Board", "board", "Model sign-in",
		"Caf\u00e9", "Cafe\u0301", "Re\u0430der", "Re\u03b1der", "\uff32\uff45\uff41\uff44\uff45\uff52", "\U0001d411\U0001d41e", "Of\ufb01ce", "No\u00a0break", "Zero\u200bwidth", "Turned\u202earound",
		"Bell\u0007", "Later \u1c89", "\u212a2", "Ma\u017fs", "D\u0131van", "\u0130stanbul", "Stra\u00dfe", "STRA\u1e9eE", "\u03bf\u03b4\u03bf\u03c2", "\u03bf\u03b4\u03bf\u03c3",
		"\ud55c\uae00", "\u1112\u1161\u11ab", "\u09aa\u09be\u09a0\u0995", "x\u0323\u0301", "x\u0301\u0323", "\u016a\u031b", "Private \ue000", "Team \U0001f600",
		"line one\nline two", "a\ttab", "a\rreturn",
		// What text is shaped like.
		identifierOf("an asset"), aDigest("a document"), "1AAI" + strings.Repeat("a", 44), "0123456789abcdef0123456789abcdef",
		"3f2a9c1b7d4e6f8091a2b3c4d5e6f708192a3b4c", strings.Repeat("0f1e2d3c", 8), "image@sha256:" + strings.Repeat("0f1e2d3c", 8),
		"q7Zr2Lm9Xc4Vb1Nn8Kp3Jh6Gf5Ds0Aa7Qw2Er9Ty4Ui", "A" + identifierOf("a seed")[1:], aSaltOf("a salt"),
		"A" + strings.Repeat("a", 43), "0A" + strings.Repeat("a", 22),
		keyShaped("sk- and 32 letters and digits"), "sk-this-is-a-long-hyphenated-slug", keyShaped("a live key"), keyShaped("a GitHub token"),
		keyShaped("a GitLab token"), keyShaped("an npm token"), keyShaped("an age key"),
		keyShaped("a JSON Web Token"), "postgres://reader:hunter2@db.example/handbook", "https://reader@docs.example/handbook",
		joined("-----BEGIN PRIV", "ATE KEY-----"), keyShaped("an access key"), "Quarterly-Report-2026-Final-Version-For-The-Board",
		"Employee_Handbook_2026_Final_Reviewed_Version.pdf", "https://news.example/2026/11/20/how-we-rebuilt-the-handbook-for-everyone-in-2026-11-20",
		"https://docs.google.com/document/d/1x7Zr2Lm9Xc4Vb1Nn8Kp3Jh6Gf5Ds0Aa7Qw2Er9Ty4U/edit", "Build-2026-11-20-Release-Candidate-For-The-Handbook-Site",
		// Times, origins and the words fields take.
		"2026-11-20T09:00:00Z", "0000-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-11-20T09:00:00+00:00", "2026-11-20T24:00:00Z",
		"2026-11-20T09:00:60Z", "9999-12-31T23:59:59Z", "2026-11-20t09:00:00z",
		"https://portal.example", "https://portal.example:443", "http://portal.example:80", "https://portal.example:8443", "https://portal.example:08443",
		"https://portal.example:65536", "https://Portal.example", "https://portal.example/", "https://user@portal.example", "http://127.0.0.1:8080",
		"http://127.1", "https://[::1]:8443", "https://[::1]", "https://[0:0:0:0:0:0:0:1]:8443", "https://[::ffff:1.2.3.4]:8443", "https://xn--caf-dma.example",
		"https://-bad.example", "https://portal..example", "ftp://portal.example", "https://",
		"self", "asset", "employees", "The Staff", "open", "request", "invite", "anyone", "website", "example.worker", "example.utility_app", "example.unknown",
		"Not A Kind", "code.repository.read", "code.repository.write", "machine.provide", "dns.record.write", "Code.Repository.Read", "read",
		"board.a0123456789abcdef0123456789abcdef.write", "create", "change", "remove", "item", "existing", "sealed", "unsealed", "changed", "broken",
		"unchecked", "sealed_by_an_earlier_key", "identity-agent-set-up/1", "identity-agent-set-up/2", "identity-agent-set-up/01", "identity-agent-set-up-approval/1",
		object{"utility_app": "Board", "permission": "write"}, object{"utility_app": "BOARD", "permission": "write"}, object{"utility_app": "Board"},
		object{"utility_app": "Board", "permission": "write", "more": true}, object{"utility_app": identifierOf("an asset"), "permission": "write"},
		[]any{"code.repository.read"}, []any{"code.repository.read", "code.repository.read"}, []any{"machine.provide", "code.repository.write"},
		[]any{object{"utility_app": "Board", "permission": "write"}, object{"utility_app": "board", "permission": "write"}},
		object{"code.repository.read": object{"repository": []any{"example/site"}}}, object{"": object{"repository": []any{"example/site"}}},
		object{"code.repository.read": object{}}, object{"code.repository.read": object{"Repository": []any{"x"}}}, object{"code.repository.read": object{"repository": []any{"x", "x"}}},
		object{"mode": "open"}, object{"mode": "invite", "required_cred_issuer": "self"}, object{"example.labels": object{"label": "docs"}}, object{"example.other": object{}},
	}
	// Writing in many languages, and what is not writing.
	for _, table := range [][][2]string{writtenNames, notNames, writtenText, notText} {
		for _, n := range table {
			out = append(out, n[1])
		}
	}
	for _, pair := range append(append([][3]string{}, oneName...), twoNames...) {
		out = append(out, pair[1], pair[2])
	}
	out = append(out, aSaltOf("a salt"), "x"+aSaltOf("a salt"), keyShaped("sk- after a route, and 64 hexadecimal"), keyShaped("sk- and 32 hexadecimal digits"),
		"sk-Report-2026-final-version-x", "sk-"+strings.Repeat("a", 19), keyShaped("sk- and 20 letters and a dash"), "sk-a_"+strings.Repeat("b", 20),
		keyShaped("a mail service key"), keyShaped("a PGP private key block"),
		"postgres://USER:PASSWORD@HOST/handbook", "https://user:pass@docs.example", "https://user:<password>@docs.example", "https://user:$PASSWORD@docs.example",
		"https://user:xxxx@docs.example", "https://user:hunter2@docs.example", "mailto:someone:else@docs.example", "https://user:Password1@docs.example",
		"postgres://admin:$uperS3cret9@db.example", "postgres://admin:%24uper@db.example", "postgres://admin:{Xk29fj3Lq8@db.example",
		"https://user:${DB_PASSWORD}@docs.example", "https://user:${db}@docs.example", "https://user:{{password}}@docs.example", "https://user:{{a}@docs.example",
		"https://user:[password]@docs.example", "https://user:<a><b>@docs.example", "https://user:%s@docs.example", "https://user:%d@docs.example",
		"https://user:your-password@docs.example", "https://user:YOUR_PASSWORD@docs.example", "https://user:yourpassword@docs.example",
		"sk-notes-internationalisationguide", keyShaped("sk- and 24 letters"), keyShaped("sk- and 23 letters and a digit"))
	return out
}

// memberProbes are names put on a new member of every object.
func memberProbes() []string {
	return []string{"extra", "", "Extra Member", keyShaped("a GitHub token"), strings.Repeat("m", MaxMember+1), "Turned\u202earound", identifierOf("an asset"),
		"q7Zr2Lm9Xc4Vb1Nn8Kp3Jh6Gf5Ds0Aa7Qw2Er9Ty4Ui", "name", "kind", "about", "seal", "note", "title", "extensions", "permissions", "format", "reports_to", "utility_apps"}
}

// places are every place of a JSON value, as a way to get there.
func places(v any, at []any, out *[][]any) {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range sorted(t) {
			here := append(append([]any{}, at...), k)
			*out = append(*out, here)
			places(t[k], here, out)
		}
	case []any:
		for i, e := range t {
			here := append(append([]any{}, at...), i)
			*out = append(*out, here)
			places(e, here, out)
		}
	}
}

func clone(t testing.TB, v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

// put sets, or with remove deletes, what is at a place.
func put(root any, place []any, value any, remove bool) any {
	if len(place) == 0 {
		return value
	}
	switch t := root.(type) {
	case map[string]any:
		k := place[0].(string)
		if len(place) == 1 && remove {
			delete(t, k)
		} else {
			t[k] = put(t[k], place[1:], value, remove)
		}
	case []any:
		i := place[0].(int)
		if len(place) == 1 && remove {
			return append(t[:i:i], t[i+1:]...)
		}
		t[i] = put(t[i], place[1:], value, remove)
	}
	return root
}

func get(root any, place []any) any {
	for _, p := range place {
		switch t := root.(type) {
		case map[string]any:
			root = t[p.(string)]
		case []any:
			root = t[p.(int)]
		}
	}
	return root
}

// mutations are a value with one thing changed, every way: each place taken
// away, each place given each probe, and each object given each new member.
func mutations(t testing.TB, base any, each func(what string, mutated any)) {
	var all [][]any
	places(base, nil, &all)
	for _, place := range all {
		each(fmt.Sprintf("%v removed", place), put(clone(t, base), place, nil, true))
		for i, probe := range probes() {
			each(fmt.Sprintf("%v given probe %d", place, i), put(clone(t, base), place, clone(t, probe), false))
		}
	}
	for _, place := range append([][]any{nil}, all...) {
		if _, isObject := get(base, place).(map[string]any); !isObject {
			continue
		}
		for i, name := range memberProbes() {
			for j, value := range []any{"x", true, object{"label": "docs"}, "Board", "Two  spaces", []any{"Board"}} {
				m := clone(t, base)
				get(m, place).(map[string]any)[name] = clone(t, value)
				each(fmt.Sprintf("%v given member %d as %d", place, i, j), m)
			}
		}
	}
}

// Files, choices and chosen lists, each one change away from a good one (and
// some files two), are
// judged here and then by the implementation written apart from this one,
// from the format document. Where the two differ, the document does not say
// what the code does. It runs where Python and its blake3 module are
// installed, as every independent check does: one case in twelve, or every
// one (some minutes) where IA_REQUIRE_INDEPENDENT_CHECK=1 says the check must
// run.
func TestFilesOneChangeFromAGoodOneAreReadAlikeByTheIndependentImplementation(t *testing.T) {
	every := os.Getenv("IA_REQUIRE_INDEPENDENT_CHECK") == "1"
	if py, err := exec.LookPath("python3"); !every && (err != nil || exec.Command(py, "-c", "import blake3").Run() != nil) {
		t.Skip("python3 or its blake3 module is not installed")
	}
	count := 0
	sampled := func() bool {
		count++
		return every || count%12 == 0
	}
	set := written(t)
	set.Files, set.Approvals, set.Lists = nil, nil, nil
	file := func(what string, v any, more func(*fileVector)) {
		if !sampled() {
			return
		}
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		fv := fileVector{Name: what, File: string(raw)}
		if more != nil {
			more(&fv)
		}
		set.Files = append(set.Files, judged(t, fv))
	}
	bases := map[string]any{}
	for name, raw := range map[string][]byte{
		"two websites":             text(t, twoWebsites()),
		"the full file":            text(t, aFullFile()),
		"a sealed file":            sealed(t, twoWebsites(), "exporter", "exporter"),
		"a file sealed by another": sealed(t, twoWebsites(), "exporter", "other"),
	} {
		var v any
		_ = json.Unmarshal(raw, &v)
		bases[name] = v
	}
	for _, name := range sorted(bases) {
		mutations(t, bases[name], func(what string, m any) {
			file(name+": "+what, m, nil)
			if strings.HasPrefix(name, "a sealed") && strings.Contains(what, "seal") {
				file(name+", read with an earlier key: "+what, m, func(v *fileVector) { v.EarlierKeys = []string{"exporter"} })
			}
		})
	}
	// Two changes at once, for what one change cannot show: which of two
	// faults is the reason given, and what is said of an item that is wrong in
	// two ways.
	type change struct {
		place  []any
		value  any
		remove bool
	}
	item := func(i int, more ...any) []any { return append([]any{"items", i}, more...) }
	changes := []change{
		{item(1, "kind"), "example.unknown", false}, {item(1, "kind"), "Not A Kind", false}, {item(1, "kind"), nil, true},
		{item(1, "name"), "Two  spaces", false}, {item(1, "name"), identifierOf("an asset"), false}, {item(1, "name"), nil, true},
		{item(1, "name"), "Builder", false}, {item(2, "name"), "READER", false}, {item(0, "name"), "Public notes", false},
		{item(1, "note"), keyShaped("a GitHub token"), false}, {item(1, "note"), nil, false}, {item(1, "note"), 1.5, false},
		{item(1, "note"), strings.Repeat("0f1e2d3c", 8), false}, {item(1, "note"), identifierOf("an asset"), false},
		{item(1, "colour"), "green", false}, {item(1, "permissions"), []any{"machine.provide"}, false}, {item(1, "limits"), nil, true},
		{item(1, "extensions"), object{"example.other": object{}}, false}, {item(1, "credential"), "Another sign-in", false},
		{item(2, "reports_to"), "Board", false}, {item(2, "reports_to"), "Reader", false}, {item(0, "kind"), "website", false},
		{item(3, "origin"), "https://Portal.example", false}, {item(3, "policy", "mode"), "anyone", false},
		{[]any{"about"}, nil, false}, {[]any{"about"}, 1.5, false}, {[]any{"about"}, keyShaped("a live key"), false},
		{[]any{"defaults"}, true, false}, {[]any{"format"}, "identity-agent-set-up/2", false}, {[]any{"credentials_needed"}, nil, true},
		{[]any{"seal"}, object{"by": "nobody"}, false}, {[]any{"made_at"}, "0000-01-01T00:00:00Z", false},
	}
	for i, one := range changes {
		for j, two := range changes {
			if i == j {
				continue
			}
			m := put(put(clone(t, bases["the full file"]), one.place, clone(t, one.value), one.remove), two.place, clone(t, two.value), two.remove)
			file(fmt.Sprintf("the full file: change %d and then change %d", i, j), m, nil)
		}
	}

	// Knowing permissions and the time, on the file that has both.
	mutations(t, bases["the full file"], func(what string, m any) {
		if strings.Contains(what, "permissions") || strings.Contains(what, "grant_end") {
			file("the full file, knowing two capabilities at a time: "+what, m, func(v *fileVector) {
				v.Knows, v.Now = []string{"code.repository.read", "code.repository.write"}, "2027-06-30T00:00:00Z"
			})
		}
	})

	// Chosen lists, as a device is handed them.
	needs := []string{"code.repository.write", "machine.provide"}
	first := approved(t, aFullFile(), nil)
	var list any
	_ = json.Unmarshal(first.Bytes(), &list)
	mutations(t, list, func(what string, m any) {
		if !sampled() {
			return
		}
		raw, _ := json.Marshal(m)
		canonical, err := update.Canonicalize(raw)
		if err != nil {
			t.Fatal(err)
		}
		for spelling, b := range map[string][]byte{"": canonical, ", as plain JSON": raw} {
			v := listVector{Name: "list: " + what + spelling, List: string(b), NeedsAcknowledging: needs}
			if _, err := ReadApproval(b, needing(needs)); err != nil {
				v.Refused = CodeOf(err)
			}
			set.Lists = append(set.Lists, v)
		}
	})

	// Choices, from the full file and from the same file sealed.
	fullVector := judged(t, fileVector{Name: fullFile, File: string(text(t, aFullFile()))})
	sealedVector := judged(t, fileVector{Name: sealedFullFile, File: string(sealed(t, aFullFile(), "exporter", "exporter"))})
	set.Files = append(set.Files, fullVector, sealedVector)
	choice := object{"identity_agent": identifierOf("importer"), "proposal": "proposal-0123456789abcdef", "nonce": "nonce-0123456789abcdefghij",
		"items": []any{object{"index": 0, "acknowledged": []any{}}, object{"index": 1, "acknowledged": []any{}},
			object{"index": 2, "acknowledged": []any{"code.repository.write", "machine.provide"}}, object{"index": 3, "acknowledged": []any{}}},
		"utility_apps": object{}, "credentials": object{}}
	mutations(t, clone(t, choice), func(what string, m any) {
		raw, _ := json.Marshal(m)
		var c vectorChoice
		if json.Unmarshal(raw, &c) != nil || c.UtilityApps == nil || c.Credentials == nil || c.Items == nil {
			return // not a choice a caller can make: the vectors hold choices, not documents
		}
		if !sampled() {
			return
		}
		for i := range c.Items {
			if c.Items[i].Acknowledged == nil {
				return
			}
			for _, p := range c.Items[i].Acknowledged {
				if _, err := json.Marshal(p); err != nil {
					return
				}
			}
		}
		for _, from := range []fileVector{fullVector, sealedVector} {
			out := approvalVector{Name: "choice from " + from.Name + ": " + what, From: from.Name, Choice: c, NeedsAcknowledging: needs}
			r, err := Read(from.bytes(), optionsOf(t, from))
			if err != nil {
				t.Fatal(err)
			}
			if a, err := r.Approve(c.choice(r, from), needing(needs)); err != nil {
				out.Refused = CodeOf(err)
			} else {
				out.Bytes, out.Digest = string(a.Bytes()), a.Digest()
			}
			set.Approvals = append(set.Approvals, out)
		}
	})

	dir := t.TempDir()
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "mutated.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unicode-15.0.json"), unicodeDataJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d files, %d choices and %d lists", len(set.Files), len(set.Approvals), len(set.Lists))
	contractcheck.IndependentlyWith(t, "../contracts/check_set_up_file_vectors.py", path, "blake3")
}
