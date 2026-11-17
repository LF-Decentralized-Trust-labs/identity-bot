// Package statements is the format of a statement an app hands a person to sign with their own Identity
// Agent (Ask action 6, "Sign a statement"), and the rules the Identity Agent applies before it shows one.
// The format is open and has byte-exact test vectors (docs/statement-signature.md,
// testdata/vectors.json) so that anybody who verifies such a signature, or builds the statement, gets
// the same bytes.
//
// Three things live here and nowhere else:
//
//   - The generic rules every statement meets before it can be shown or signed (Check).
//   - The envelope the Identity Agent signs: a fixed header, the asker's identifier, then the
//     statement exactly as shown (Envelope).
//   - Registered display forms (decision-approval/1 is the first), which change how a statement
//     is shown and never whether it can be signed (Show).
package statements

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zeebo/blake3"

	"identity-agent-core/iacrypto"
)

// Limits on any statement, so what a person reads is what is signed.
const (
	MaxBytes = 2048
	MaxLines = 24
	// MaxTitle is the longest sentence a decision is, in characters.
	MaxTitle = 600
)

// EnvelopeHeader is the first line of every signed envelope. No KERI event can begin with it
// (events begin with "{"), so a signature of an envelope is never a signature of an event of a key
// log or of anything else an Identity Agent understands.
const EnvelopeHeader = "statement-signature/1"

// DecisionApprovalForm is the first line of the registered decision-approval statement.
const DecisionApprovalForm = "decision-approval/1"

var headerShape = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}/[0-9]{1,4}$`)

var askerShape = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Check says why statement cannot be shown and signed, or returns its header (its first line).
func Check(statement string) (header string, err error) {
	if statement == "" {
		return "", errors.New("there is no statement to sign")
	}
	if len(statement) > MaxBytes {
		return "", fmt.Errorf("the statement is longer than %d bytes", MaxBytes)
	}
	if !utf8.ValidString(statement) {
		return "", errors.New("the statement is not valid UTF-8")
	}
	for _, r := range statement {
		if r == '\n' {
			continue
		}
		if hidden(r) {
			return "", fmt.Errorf("the statement has a character that cannot be shown as it is (U+%04X)", r)
		}
	}
	lines := strings.Split(statement, "\n")
	if len(lines) > MaxLines {
		return "", fmt.Errorf("the statement has more than %d lines", MaxLines)
	}
	if lines[len(lines)-1] == "" {
		return "", errors.New("the statement ends with a line break")
	}
	if !headerShape.MatchString(lines[0]) {
		return "", errors.New("the statement's first line is not a name and version, like decision-approval/1")
	}
	return lines[0], nil
}

// Plain is whether text has no character that is read differently from how it is signed, line breaks
// included: what may be shown on one line.
func Plain(text string) bool {
	for _, r := range text {
		if r == '\n' || hidden(r) {
			return false
		}
	}
	return utf8.ValidString(text)
}

// hidden is a character that is read differently from how it is signed: a control character, a line
// or paragraph separator, a mark that reorders the text around it, or one that takes no space.
func hidden(r rune) bool {
	switch {
	case unicode.IsControl(r):
		return true
	case r == 0x2028 || r == 0x2029:
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x200E || r == 0x200F || r == 0x061C:
		return true
	// Format, private-use and unassigned characters, and those that take no space or fill one with
	// nothing: a person cannot see them, so they could carry what they do not read.
	case unicode.In(r, unicode.Cf, unicode.Co, unicode.Cs, unicode.Variation_Selector), !unicode.IsPrint(r) && r != ' ':
		return true
	case r == 0x034F, r >= 0x180B && r <= 0x180E, r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0,
		r == 0x2800, r == 0xFFFC, r == 0x17B4, r == 0x17B5, r >= 0xE0100 && r <= 0xE01EF:
		return true
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF, r >= 0xFFF9 && r <= 0xFFFB:
		return true
	}
	return false
}

// Envelope is what is signed: a fixed, public header, the asker's identifier, a blank line, then
// the statement bytes exactly as shown. UTF-8, "\n" only, no trailing newline. Naming the asker
// inside the signed bytes makes a signature made for one verifier useless to another.
func Envelope(askerAID, statement string) ([]byte, error) {
	if !askerShape.MatchString(askerAID) {
		return nil, errors.New("the asker's identifier is not one")
	}
	if _, err := Check(statement); err != nil {
		return nil, err
	}
	return []byte(EnvelopeHeader + "\nasker: " + askerAID + "\n\n" + statement), nil
}

// Row is one labelled line of a registered form's reading.
type Row struct{ Label, Value string }

// Shown is how a statement is shown to the person. Verbatim is always the exact statement; Rows is
// a clearer reading of a registered form, and is empty for any other statement.
type Shown struct {
	Header   string
	Form     string // the registered form's name, or "" for a statement shown only as text
	Heading  string // what the statement is, in a few words
	Rows     []Row
	Verbatim string
}

// Show applies the generic rules, then a registered form's own when the header names one. The
// title is a decision approval's sentence, which the statement carries only as a hash: when it is
// given it must be the sentence the hash is of, or the statement is refused. Nothing in Shown is
// taken from anywhere but the checked statement and that checked title.
func Show(statement, title string) (Shown, error) {
	header, err := Check(statement)
	if err != nil {
		return Shown{}, err
	}
	s := Shown{Header: header, Heading: "A statement for you to sign", Verbatim: statement}
	if title != "" && header != DecisionApprovalForm {
		return Shown{}, errors.New("a title came with a statement that has no sentence to check it against")
	}
	if header != DecisionApprovalForm {
		return s, nil
	}
	d, err := ReadDecisionApproval(statement)
	if err != nil {
		return Shown{}, err
	}
	s.Form, s.Heading = DecisionApprovalForm, "Your approval of a decision"
	if title != "" {
		if err := CheckTitle(d, title); err != nil {
			return Shown{}, err
		}
		s.Rows = append(s.Rows, Row{"Decision " + d.ID, quote(title)})
	} else {
		s.Rows = append(s.Rows, Row{"Decision " + d.ID, "(its sentence was not sent; its fingerprint is " + d.TitleHash + ")"})
	}
	s.Rows = append(s.Rows,
		Row{"Made by", quote(d.DecidedBy)},
		Row{"Rated", d.Impact},
		Row{"Minutes to undo", d.UndoMinutes},
		Row{"You are saying", "you approve it"})
	return s, nil
}

func quote(v string) string { return strconv.Quote(v) }

// DecisionApproval is what a decision-approval/1 statement says, read back.
type DecisionApproval struct {
	ID          string
	TitleHash   string
	DecidedBy   string
	Impact      string
	UndoMinutes string
}

var impacts = map[string]bool{"small": true, "moderate": true, "architectural": true}

// ReadDecisionApproval reads the statement strictly: seven lines joined by single newlines, in
// this order, and nothing else, so another line, another order or a trailing space is refused
// rather than tidied.
func ReadDecisionApproval(statement string) (DecisionApproval, error) {
	var d DecisionApproval
	lines := strings.Split(statement, "\n")
	if len(lines) != 7 {
		return d, errors.New("that is not a decision approval: it has the wrong number of lines")
	}
	if lines[0] != DecisionApprovalForm {
		return d, errors.New("that is not a decision approval: it does not begin " + DecisionApprovalForm)
	}
	field := func(i int, key string) (string, error) {
		v, ok := strings.CutPrefix(lines[i], key+"=")
		if !ok || v == "" {
			return "", fmt.Errorf("that is not a decision approval: line %d is not %s=...", i+1, key)
		}
		return v, nil
	}
	var err error
	if d.ID, err = field(1, "decision"); err != nil {
		return d, err
	}
	if d.TitleHash, err = field(2, "title-hash"); err != nil {
		return d, err
	}
	if d.DecidedBy, err = field(3, "decided-by"); err != nil {
		return d, err
	}
	if d.Impact, err = field(4, "impact"); err != nil {
		return d, err
	}
	if d.UndoMinutes, err = field(5, "undo-minutes"); err != nil {
		return d, err
	}
	if lines[6] != "verdict=approve" {
		return d, errors.New("that is not an approval: the last line is not verdict=approve")
	}
	if !digits(d.ID) || !digits(d.UndoMinutes) {
		return d, errors.New("that is not a decision approval: the decision and its undo minutes are numbers")
	}
	if !impacts[d.Impact] {
		return d, errors.New("that is not a decision approval: the impact is small, moderate or architectural")
	}
	if utf8.RuneCountInString(d.DecidedBy) > 200 {
		return d, errors.New("that is not a decision approval: decided-by is too long")
	}
	return d, nil
}

func digits(s string) bool {
	if s == "" || len(s) > 12 || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// TitleHash is the statement's text form of a decision's sentence: the BLAKE3-256 digest as a
// CESR E value.
func TitleHash(title string) (string, error) {
	sum := blake3.Sum256([]byte(title))
	return iacrypto.MatterFixedQB64("E", sum[:])
}

// CheckTitle says why title is not the sentence statement d is of.
func CheckTitle(d DecisionApproval, title string) error {
	if strings.TrimSpace(title) == "" || utf8.RuneCountInString(title) > MaxTitle || strings.ContainsRune(title, '\n') {
		return errors.New("the decision's title is one line of at most 600 characters")
	}
	for _, r := range title {
		if hidden(r) {
			return errors.New("the decision's title has a character that cannot be shown as it is")
		}
	}
	h, err := TitleHash(title)
	if err != nil {
		return err
	}
	if h != d.TitleHash {
		return errors.New("that title is not the sentence the statement is of")
	}
	return nil
}
