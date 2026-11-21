package setupfile

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/strictjson"
)

// shape is what a piece of text is shaped like, whatever it says it is. The
// order is of how much each matters: the greatest found is the text's shape.
type shape int

const (
	plainShape shape = iota
	// identifierShape is text shaped like an identifier or a digest: of an
	// asset, a grant, a machine, a key or a schema.
	identifierShape
	// likelySecretShape is text that may be a key or a token, by a rule of
	// thumb: long, and mixed or hexadecimal. It blocks an item, and never a
	// file.
	likelySecretShape
	// secretShape is text in a spelling only a key, a seed or a token has. It
	// refuses a file.
	secretShape
)

// The spellings only a secret has. They are published
// (docs/set-up-file.md, "Text shaped like a secret or an identifier"), and an
// importer applies exactly these, so that a file is never refused for a
// reason its exporter could not have known.
var knownSecrets = regexp.MustCompile(strings.Join([]string{
	`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`,
	`\bgh[pousr]_[A-Za-z0-9]{20,}`,
	`\bgithub_pat_[A-Za-z0-9_]{20,}`,
	`\bglpat-[A-Za-z0-9_-]{20,}`,
	`\bnpm_[A-Za-z0-9]{36}`,
	`\b[sr]k_live_[A-Za-z0-9]{10,}`,
	`\bxox[abprs]-[A-Za-z0-9-]{10,}`,
	`\bAKIA[0-9A-Z]{16}\b`,
	`\bAIza[0-9A-Za-z_-]{35}`,
	`\bAGE-SECRET-KEY-1[A-Z0-9]{20,}`,
	`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`,
	`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.`,
}, "|"))

// A token that begins "sk-" is one when its last part, after the last "-" or
// "_", is 20 or more letters and digits and holds a digit: a slug that begins
// the same way ends in a word.
var skToken = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]+`)

var twentyOrMore = regexp.MustCompile(`^[A-Za-z0-9]{20,}$`)

// A web address that carries a user and a password, the password caught. It
// is a secret unless the password is a placeholder.
var passwordInAddress = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\t\n\f\r /?#@:]+:([^\t\n\f\r /?#@]+)@`)

// A placeholder stands where a password would, and is written so that
// nobody takes it for one: a word that says so, in any case; only "x" or "*";
// a variable ($NAME or ${NAME}, in capitals, digits and underscores); a name
// in closed brackets (<...>, {...}, {{...}}, [...]); or %s. Something that
// only begins like one of these is a password.
var placeholder = regexp.MustCompile(`^((?i:password|pass|passwd|pwd|secret|token|changeme|redacted|example|your[-_]password|[x*]+)` +
	`|\$[A-Z0-9_]+|\$\{[A-Z0-9_]+\}|<[^<>]+>|\{[^{}]+\}|\{\{[^{}]+\}\}|\[[^\[\]]+\]|%s)$`)

var aRun = regexp.MustCompile(`[A-Za-z0-9_-]+`)

var (
	allHex    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	aLetter   = regexp.MustCompile(`[A-Za-z]`)
	anUpper   = regexp.MustCompile(`[A-Z]`)
	aLower    = regexp.MustCompile(`[a-z]`)
	theDigits = regexp.MustCompile(`[0-9]+`)
)

func mixed(run string) bool {
	return anUpper.MatchString(run) && aLower.MatchString(run) && theDigits.MatchString(run)
}

// ShapeOf says what text is shaped like, by the published rules. A run is the
// longest stretch of ASCII letters, digits, "-" and "_", so a web address or
// a sentence is read word by word. Text is judged as a reader sees it, with
// every character that is not seen as itself taken out but those that end a
// word (withoutUnseen). It is judged a secret also when its compatibility
// form (Normalization Form KC, with the same characters taken out) is one, so
// that a key spelt in fullwidth or mathematical letters is still a key.
//
//   - secret: a spelling only a secret has. A private key block; a token of a
//     known beginning; a web address carrying a user and a password that is
//     not a placeholder; a mixed run of 44 characters that is an Ed25519 seed
//     in CESR (the code A, in canonical qb64); a run of 24 that is a salt in
//     CESR (the code 0A, in canonical qb64).
//   - likelySecret: a rule of thumb. A run of 64 or more hexadecimal
//     characters holding a letter and a digit, or a run of 40 or more holding
//     an upper-case letter, a lower-case letter and three separate groups of
//     digits, that is not shaped like an identifier.
//   - identifier: a run of 44 characters under the CESR code E, D or B in
//     canonical qb64 (a digest, a key, an identifier), a run of 48 under 1AAI,
//     or a run of 32 to 63 hexadecimal characters holding a letter and a
//     digit.
//
// This is a floor and not a guarantee: a secret in a spelling nobody listed
// passes, and so does one with a letter of another script that looks like a
// Latin one. What keeps secrets out of a file is that an exporter never reads one
// into it.
func ShapeOf(text string) (secret, likelySecret, identifier bool) {
	s := shapeOf(text)
	return s == secretShape, s == likelySecretShape, s == identifierShape
}

func shapeOf(text string) shape {
	found := shapeSeen(withoutUnseen(text))
	if found != secretShape && shapeSeen(withoutUnseen(nfkc(text))) == secretShape {
		return secretShape
	}
	return found
}

// shapeSeen is the shape of text a reader sees all of.
func shapeSeen(text string) shape {
	if knownSecrets.MatchString(text) {
		return secretShape
	}
	for _, token := range skToken.FindAllString(text, -1) {
		if last := token[strings.LastIndexAny(token, "-_")+1:]; twentyOrMore.MatchString(last) && theDigits.MatchString(last) {
			return secretShape
		}
	}
	for _, m := range passwordInAddress.FindAllStringSubmatch(text, -1) {
		if !placeholder.MatchString(m[1]) {
			return secretShape
		}
	}
	found := plainShape
	for _, run := range aRun.FindAllString(text, -1) {
		hexadecimal := allHex.MatchString(run) && theDigits.MatchString(run) && aLetter.MatchString(run)
		switch {
		case len(run) == 44 && run[0] == 'A' && mixed(run) && isQB64("E", "E"+run[1:]), aSalt(run):
			return secretShape
		case len(run) == 44 && strings.ContainsRune("EDB", rune(run[0])) && isQB64("E", "E"+run[1:]),
			len(run) == 48 && strings.HasPrefix(run, iacrypto.CodeP256N):
			found = max(found, identifierShape)
		case hexadecimal && len(run) >= 64:
			found = max(found, likelySecretShape)
		case hexadecimal && len(run) >= 32:
			found = max(found, identifierShape)
		case len(run) >= 40 && anUpper.MatchString(run) && aLower.MatchString(run) && len(theDigits.FindAllString(run, -1)) >= 3:
			found = max(found, likelySecretShape)
		}
	}
	return found
}

func isQB64(code, s string) bool {
	_, err := iacrypto.DecodeQB64(code, s, 32)
	return err == nil
}

// aSalt is whether a run is a salt in CESR: the whole run is 24 characters
// under the code 0A, decoding to 16 bytes in canonical qb64.
func aSalt(run string) bool {
	if len(run) != 24 || !strings.HasPrefix(run, "0A") {
		return false
	}
	_, err := iacrypto.DecodeQB64("0A", run, 16)
	return err == nil
}

// checkName says why text cannot be a name, as a code and a sentence, or
// returns "". A name is what a person calls a thing:
//
//   - 1 to MaxName bytes, on one line, every character one that reads as it is
//     written (shown);
//   - no space before or after it, no two spaces together, and no "@" (a name
//     is written before one where an AI agent is addressed);
//   - in Normalization Form C: an accent joined to its letter;
//   - no word that mixes letters of Latin, Greek and Cyrillic;
//   - not shaped like an identifier or a secret.
//
// A name may be spelt as its language spells it. Two spellings of the same
// letters are one name (foldName), so neither can stand beside the other.
func checkName(name string) (code, text string) {
	switch {
	case name == "" || len(name) > MaxName:
		return BadName, fmt.Sprintf("a name is 1 to %d bytes", MaxName)
	case !shownLine(name) || name != strings.Trim(name, " ") || strings.Contains(name, "  ") || strings.Contains(name, "@"):
		return BadName, `a name is on one line, with no space before or after it, no two spaces together, no "@" and no character that is not seen as itself`
	case nfc(name) != name:
		return BadName, "a name is written with each accent joined to its letter (Normalization Form C)"
	case mixesLookAlikeScripts(name):
		return BadName, "a word of a name does not mix Latin, Greek and Cyrillic letters, which are taken for one another"
	case shapeOf(name) != plainShape:
		return NameIdentifier, "this is shaped like an identifier, where a name is required"
	}
	return "", ""
}

// CheckName is the rule of a name, for a kind or an extension that holds
// names of its own: nil, or why the text is not a name.
func CheckName(name string) error {
	if code, text := checkName(name); code != "" {
		return &FieldError{Code: code, Text: text}
	}
	return nil
}

// Text reads a member's value as text. It is text only when it is a JSON
// string: null, which a lenient reader takes for an empty string, is not.
func Text(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// refusedWhole walks everything a file holds but its seal and refuses the
// file, in three passes so that the reason given does not depend on the order
// of the file's members: first for text in a spelling only a secret has, in a
// value or a member's name; then for a null; then for a number that is not a
// whole number every reader reads alike. The place is said by position, never
// by a member's name.
func refusedWhole(v any) *Refusal {
	var walk func(v any, where string, pass int) *Refusal
	walk = func(v any, where string, pass int) *Refusal {
		switch t := v.(type) {
		case nil:
			if pass == 1 {
				return refuse(NullValue, where, "a set-up file never holds null: a member that has no value is left out")
			}
		case string:
			if pass == 0 && shapeOf(t) == secretShape {
				return refuse(SecretShaped, where, "something here is a key or a token, and a set-up file never holds one")
			}
		case json.Number:
			if _, err := strictjson.WholeNumber(t); pass == 2 && err != nil {
				return refuse(BadNumber, where, "a number in a set-up file is a whole number, written plainly")
			}
		case []any:
			for i, e := range t {
				if r := walk(e, fmt.Sprintf("%s[%d]", where, i), pass); r != nil {
					return r
				}
			}
		case map[string]any:
			for i, k := range sorted(t) {
				here := at(where, k, i, nil)
				if pass == 0 && shapeOf(k) == secretShape {
					return refuse(SecretShaped, here, "a member's name here is a key or a token")
				}
				if r := walk(t[k], here, pass); r != nil {
					return r
				}
			}
		}
		return nil
	}
	for pass := 0; pass < 3; pass++ {
		if r := walk(v, "", pass); r != nil {
			return r
		}
	}
	return nil
}

// textRules are the members of an item a kind declared something of.
type textRules struct {
	// identifiers hold "", "self" or an identifier and nothing else.
	identifiers map[string]bool
	// prose is text a person wrote for a reader: instructions, a note. Text
	// shaped like an identifier there is flagged, and does not block.
	prose map[string]bool
	// known is false for an item whose own fields could not be read, which is
	// blocked already and whose declared members are not known.
	known bool
	// names are the kind's own member names, which a finding may say.
	names map[string]bool
}

var anIndex = regexp.MustCompile(`\[[0-9]+\]`)

// judgeText says what the text at one place is: nothing, a flag, or a reason
// the item is blocked. where is the place by the file's own member names,
// which the rules are declared by and which is never said.
func judgeText(t, where string, rules textRules) (code, text string, blocks bool) {
	member := anIndex.ReplaceAllString(where, "")
	switch {
	case rules.identifiers[where]:
		switch {
		case t == "" || t == Self:
			return "", "", false
		case iacrypto.IsIdentifierQB64(t):
			return NeedsAccessHere, "this names something by an identifier from elsewhere, which this organisation must itself know", false
		}
		return BadField, `this holds an identifier, "self" or nothing`, true
	case where == "name" || where == "kind" || strings.HasPrefix(where, "permissions["):
		// Judged where they are read, by the rules of a name, a kind and a
		// permission.
		return "", "", false
	case len(t) > MaxText:
		return TextTooLong, fmt.Sprintf("this text is longer than %d bytes", MaxText), true
	case !shownText(t):
		return HiddenCharacter, "this text has a character that is not seen as itself", true
	}
	switch shapeOf(t) {
	case likelySecretShape:
		return LooksLikeASecret, "something here is long and random enough to be a key or a token", true
	case identifierShape:
		switch {
		case !rules.known || strings.HasPrefix(where, "limits."):
			// A limit's value names something outside the Identity Agent,
			// which may be an identifier there; every limit is flagged for
			// the person to look at.
		case rules.prose[member]:
			return IdentifierInText, "this text holds something shaped like an identifier or a digest", false
		default:
			return IdentifierShaped, "something here is shaped like an identifier or a digest, and a set-up file names things by name", true
		}
	}
	return "", "", false
}

// itemText walks one item and says what its text is flagged or blocked for.
func itemText(v any, rules textRules) []Finding {
	var out []Finding
	// raw is the place by the file's member names, for the rules; said is the
	// place as a finding says it.
	var walk func(v any, raw, said string)
	walk = func(v any, raw, said string) {
		switch t := v.(type) {
		case string:
			if code, text, blocks := judgeText(t, raw, rules); code != "" {
				out = append(out, Finding{Code: code, Where: said, Text: text, Blocks: blocks})
			}
		case []any:
			for i, e := range t {
				walk(e, fmt.Sprintf("%s[%d]", raw, i), fmt.Sprintf("%s[%d]", said, i))
			}
		case map[string]any:
			for i, k := range sorted(t) {
				here := at(said, k, i, rules.names)
				if len(k) > MaxMember || !shownLine(k) || shapeOf(k) != plainShape {
					out = append(out, Finding{Code: BadField, Where: here, Text: "a member's name here is not a plain word", Blocks: true})
				}
				next := k
				if raw != "" {
					next = raw + "." + k
				}
				walk(t[k], next, here)
			}
		}
	}
	walk(v, "", "")
	return out
}
