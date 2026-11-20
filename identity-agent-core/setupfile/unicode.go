package setupfile

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

// The Unicode facts this package judges text by are pinned in one published
// file, made by tools/setupunicode from the Unicode Character Database
// (unicode-15.0.SOURCE.txt says from which files, and under which licence).
// Nothing here reads the toolchain's own Unicode tables: not which characters
// are seen, not normalization, not case. So a verdict cannot change with a
// toolchain, and an implementation in another language reads the same facts.
//
//go:embed unicode-15.0.json
var unicodeDataJSON []byte

// span is [first, last, word]: a range of characters that share a word.
type span struct {
	first, last rune
	word        string
}

func (s *span) UnmarshalJSON(raw []byte) error {
	var parts [3]any
	if err := json.Unmarshal(raw, &parts); err != nil {
		return err
	}
	first, _ := parts[0].(float64)
	last, _ := parts[1].(float64)
	s.first, s.last = rune(first), rune(last)
	s.word, _ = parts[2].(string)
	return nil
}

// unicodeData is unicode-15.0.json, whose "members" says what each list is.
type unicodeData struct {
	Unicode string    `json:"unicode"`
	Seen    [][2]rune `json:"seen"`
	Letters [][2]rune `json:"letters"`
	Marks   [][2]rune `json:"marks"`
	Script  []span    `json:"script"`
	CCC     [][3]rune `json:"ccc"`
	NFD     [][]rune  `json:"nfd"`
	NFKD    [][]rune  `json:"nfkd"`
	Compose [][3]rune `json:"compose"`
	Fold    [][2]rune `json:"fold"`
	Joining []span    `json:"joining"`
	Emoji   [][2]rune `json:"emoji"`
}

// pinnedData is the facts, read for look-up.
type pinnedData struct {
	unicodeData
	nfd, nfkd map[rune][]rune
	compose   map[[2]rune]rune
	fold      map[rune]rune
}

// pinned reads the facts the first time anything asks for them, once, so a
// program that links this package and never reads a file does not pay for
// them. It is safe for callers at the same time.
var pinned = sync.OnceValue(func() *pinnedData {
	d := &pinnedData{}
	if err := json.Unmarshal(unicodeDataJSON, &d.unicodeData); err != nil {
		panic("setupfile: unicode-15.0.json: " + err.Error())
	}
	d.nfd, d.nfkd = map[rune][]rune{}, map[rune][]rune{}
	for _, e := range d.NFD {
		d.nfd[e[0]] = e[1:]
	}
	for _, e := range d.NFKD {
		d.nfkd[e[0]] = e[1:]
	}
	d.compose = make(map[[2]rune]rune, len(d.Compose))
	for _, p := range d.Compose {
		d.compose[[2]rune{p[0], p[1]}] = p[2]
	}
	d.fold = make(map[rune]rune, len(d.Fold))
	for _, p := range d.Fold {
		d.fold[p[0]] = p[1]
	}
	return d
})

func inRanges(ranges [][2]rune, r rune) bool {
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i][1] >= r })
	return i < len(ranges) && ranges[i][0] <= r
}

func wordOf(spans []span, r rune) string {
	i := sort.Search(len(spans), func(i int) bool { return spans[i].last >= r })
	if i < len(spans) && spans[i].first <= r {
		return spans[i].word
	}
	return ""
}

func combiningClass(r rune) rune {
	c := pinned().CCC
	i := sort.Search(len(c), func(i int) bool { return c[i][1] >= r })
	if i < len(c) && c[i][0] <= r {
		return c[i][2]
	}
	return 0
}

// seen is whether a character is seen as itself.
func seen(r rune) bool     { return inRanges(pinned().Seen, r) }
func isLetter(r rune) bool { return inRanges(pinned().Letters, r) }
func isMark(r rune) bool   { return inRanges(pinned().Marks, r) }

// Characters that are not seen as themselves and are let through where
// writing needs them.
const (
	zwnj               = 0x200C // zero-width non-joiner
	zwj                = 0x200D // zero-width joiner
	textSelector       = 0xFE0E // variation selector 15
	emojiSelector      = 0xFE0F // variation selector 16
	noBreakSpace       = 0x00A0
	narrowNoBreakSpace = 0x202F
	softHyphen         = 0x00AD
	viramaClass        = 9
)

// afterAVirama is the context of UAX #31 (section 2.3, rules A2 and B) before
// a joiner: a letter, any marks, a virama, and then only marks of a class
// other than 0.
func afterAVirama(before []rune) bool {
	i := len(before) - 1
	for i >= 0 && combiningClass(before[i]) != 0 && combiningClass(before[i]) != viramaClass {
		i--
	}
	if i < 0 || combiningClass(before[i]) != viramaClass {
		return false
	}
	for i--; i >= 0 && isMark(before[i]); i-- {
	}
	return i >= 0 && isLetter(before[i])
}

// joinerAllowed is whether a zero-width joiner or non-joiner at place i is
// where Unicode's identifier rules allow one (UAX #31, section 2.3):
//
//   - A1, a non-joiner between two characters that would otherwise join: a
//     character of Joining_Type L or D and any of type T before it, and any of
//     type T and a character of type R or D after it;
//   - A2, a non-joiner after a virama (see afterAVirama) and before a letter;
//   - B, a joiner after a virama.
func joinerAllowed(text []rune, i int) bool {
	before, after := text[:i], text[i+1:]
	if afterAVirama(before) {
		return text[i] == zwj || len(after) > 0 && isLetter(after[0])
	}
	if text[i] != zwnj {
		return false
	}
	j := len(before) - 1
	for j >= 0 && wordOf(pinned().Joining, before[j]) == "T" {
		j--
	}
	k := 0
	for k < len(after) && wordOf(pinned().Joining, after[k]) == "T" {
		k++
	}
	if j < 0 || k == len(after) {
		return false
	}
	left, right := wordOf(pinned().Joining, before[j]), wordOf(pinned().Joining, after[k])
	return (left == "L" || left == "D") && (right == "R" || right == "D")
}

// joinerInText is where text of several lines, which is not a name, also takes
// a joiner or a non-joiner, because ordinary writing puts one there:
//
//   - a joiner between two emoji, neither of them ASCII (a variation selector
//     may stand between the first and the joiner);
//   - a joiner between a letter and a virama, in either order;
//   - a non-joiner after a letter of the Arabic script.
func joinerInText(text []rune, i int) bool {
	if i == 0 {
		return false
	}
	before := text[i-1]
	if text[i] == zwnj {
		return isLetter(before) && wordOf(pinned().Script, before) == "ARABIC"
	}
	if i+1 == len(text) {
		return false
	}
	after := text[i+1]
	if (before == textSelector || before == emojiSelector) && i >= 2 {
		before = text[i-2]
	}
	virama := func(r rune) bool { return combiningClass(r) == viramaClass }
	// The digits, "#" and "*" have the Emoji property too, and a joiner
	// between two of them would hide inside a key: no ASCII neighbour counts.
	emoji := func(r rune) bool { return r >= utf8.RuneSelf && inRanges(pinned().Emoji, r) }
	return emoji(before) && emoji(after) ||
		isLetter(before) && virama(after) || virama(before) && isLetter(after)
}

// drawnOnly is whether a character changes at most how the characters beside
// it are drawn: a variation selector 15 or 16, a joiner or a non-joiner.
func drawnOnly(r rune) bool {
	return r == textSelector || r == emojiSelector || r == zwj || r == zwnj
}

// withoutUnseen is text as a reader sees it: without the characters drawnOnly
// says, and without a soft hyphen, which is drawn only where a line breaks.
// Text is judged by its shape in this form, so that none of them can split a
// key that looks whole on a screen.
func withoutUnseen(text string) string {
	return strings.Map(func(r rune) rune {
		if drawnOnly(r) || r == softHyphen {
			return -1
		}
		return r
	}, text)
}

// shown is whether every character of text reads as it is written: valid
// UTF-8, each character seen as itself, or one of the few that are not and
// that writing needs, where it needs them:
//
//   - a zero-width joiner or non-joiner where joinerAllowed says;
//   - a variation selector 15 or 16 directly after an emoji.
//
// In text of several lines (lines true) also a line feed, a tab, a carriage
// return directly before a line feed, a no-break space, a narrow no-break
// space, a soft hyphen, and a joiner where joinerInText says.
func shown(text string, lines bool) bool {
	if !utf8.ValidString(text) {
		return false
	}
	rs := []rune(text)
	for i, r := range rs {
		switch {
		case seen(r):
		case r == zwj || r == zwnj:
			if !joinerAllowed(rs, i) && !(lines && joinerInText(rs, i)) {
				return false
			}
		case r == textSelector || r == emojiSelector:
			if i == 0 || !inRanges(pinned().Emoji, rs[i-1]) {
				return false
			}
		case lines && (r == '\n' || r == '\t' || r == noBreakSpace || r == narrowNoBreakSpace || r == softHyphen):
		case lines && r == '\r' && i+1 < len(rs) && rs[i+1] == '\n':
		default:
			return false
		}
	}
	return true
}

// shownLine is text on one line; shownText is text of several.
func shownLine(text string) bool { return shown(text, false) }
func shownText(text string) bool { return shown(text, true) }

// Hangul syllables are decomposed and composed by arithmetic, not by a table.
const (
	hangulS, hangulL, hangulV, hangulT = 0xAC00, 0x1100, 0x1161, 0x11A7
	hangulLs, hangulVs, hangulTs       = 19, 21, 28
)

// decomposed is text fully decomposed, canonically or by compatibility too,
// with its combining marks in canonical order.
func decomposed(text string, compatibility bool) []rune {
	var out []rune
	for _, r := range text {
		switch seq, both := pinned().nfkd[r]; {
		case r >= hangulS && r < hangulS+hangulLs*hangulVs*hangulTs:
			s := r - hangulS
			out = append(out, hangulL+s/(hangulVs*hangulTs), hangulV+s%(hangulVs*hangulTs)/hangulTs)
			if t := s % hangulTs; t != 0 {
				out = append(out, hangulT+t)
			}
		case compatibility && both:
			out = append(out, seq...)
		case pinned().nfd[r] != nil:
			out = append(out, pinned().nfd[r]...)
		default:
			out = append(out, r)
		}
	}
	// Canonical ordering: a mark moves before the marks of a higher class
	// that precede it, never past a character of class 0.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && combiningClass(out[j]) != 0 && combiningClass(out[j-1]) > combiningClass(out[j]); j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// normalized is text in Normalization Form C, or KC: decomposed, and then
// each character composed with the starter before it wherever a primary
// composite exists and nothing between the two blocks it.
func normalized(text string, compatibility bool) string {
	rs := decomposed(text, compatibility)
	out := make([]rune, 0, len(rs))
	starter, last := -1, rune(-1) // where the last starter is, and the class of the character just written
	for _, r := range rs {
		class := combiningClass(r)
		if starter >= 0 {
			s := out[starter]
			blocked := starter != len(out)-1 && (last == 0 || last >= class)
			composite, pair := pinned().compose[[2]rune{s, r}]
			switch {
			case blocked:
			case pair:
				out[starter] = composite
				continue
			case s >= hangulL && s < hangulL+hangulLs && r >= hangulV && r < hangulV+hangulVs:
				out[starter] = hangulS + ((s-hangulL)*hangulVs+(r-hangulV))*hangulTs
				continue
			case s >= hangulS && s < hangulS+hangulLs*hangulVs*hangulTs && (s-hangulS)%hangulTs == 0 && r > hangulT && r < hangulT+hangulTs:
				out[starter] = s + (r - hangulT)
				continue
			}
		}
		if class == 0 {
			starter = len(out)
		}
		out = append(out, r)
		last = class
	}
	return string(out)
}

func nfc(text string) string  { return normalized(text, false) }
func nfkc(text string) string { return normalized(text, true) }

// foldName is the form two names share exactly when they are one name to a
// person reading them: spaces trimmed from its ends, written in Normalization
// Form KC, each character replaced by its simple case folding, written in
// that form again, and without variation selectors, joiners or non-joiners,
// which change at most how the letters beside them are drawn. So a name spelt
// with fullwidth, bold or ligature letters, in another case, or with a joiner
// more or fewer, is the same name as the plain one, and never a second name.
// That takes two words a joiner tells apart for one, which errs the safe way.
func foldName(s string) string {
	folded := strings.Map(func(r rune) rune {
		if drawnOnly(r) {
			return -1
		}
		if f, ok := pinned().fold[r]; ok {
			return f
		}
		return r
	}, nfkc(strings.Trim(s, " ")))
	return nfkc(folded)
}

// SameName says whether two names are one name to a person reading them. For
// names in plain letters it is the comparison the core makes between the
// names of AI agents and of utility apps (asset.SameAgentName: trimmed, and
// without case), which a test holds it to. It also takes two spellings of the
// same letters for one name, which that comparison does not.
func SameName(a, b string) bool { return foldName(a) == foldName(b) }

// The three scripts whose letters are most often taken for one another.
var lookAlikeScripts = map[string]bool{"LATIN": true, "GREEK": true, "CYRILLIC": true}

// mixesLookAlikeScripts is whether one word of a name holds letters of more
// than one of Latin, Greek and Cyrillic. A word is a run of letters and
// marks. A name may hold a word of one and a word of another.
func mixesLookAlikeScripts(name string) bool {
	found := map[string]bool{}
	for _, r := range nfkc(name) + " " {
		switch {
		case isLetter(r):
			if s := wordOf(pinned().Script, r); lookAlikeScripts[s] {
				found[s] = true
			}
		case isMark(r) || r == zwj || r == zwnj:
		default:
			if len(found) > 1 {
				return true
			}
			found = map[string]bool{}
		}
	}
	return false
}
