// Command setupunicode makes the Unicode facts a set-up file's text is judged
// by (setupfile/unicode-15.0.json) from the data files of one version of the
// Unicode Character Database, fetched into one directory:
//
//	UnicodeData.txt  CaseFolding.txt  CompositionExclusions.txt
//	extracted/DerivedJoiningType.txt  emoji/emoji-data.txt
//
// from https://www.unicode.org/Public/<version>/ucd/ (the last two may sit
// beside the others, without their folders).
//
//	go run ./tools/setupunicode -in <dir> -out setupfile -version 15.0.0
//
// It writes unicode-<major.minor>.json, one range or one character to a line
// so that moving to a later version is a diff a person can read, and
// unicode-<major.minor>.SOURCE.txt beside it: where each file came from, its
// SHA-256 as read, and the Unicode licence's copyright and permission notice,
// word for word (unicode-license.txt, beside this file, is
// https://www.unicode.org/license.txt as fetched with the data).
//
// Nothing here is taken from the Go toolchain's own Unicode tables, so the
// same input gives the same file whatever toolchain runs it.
package main

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// licence is the Unicode licence as fetched, written out word for word.
//
//go:embed unicode-license.txt
var licence string

const base = "https://www.unicode.org/Public/%s/ucd/"

// files are the data files read, by their path under the version's ucd folder.
var files = []string{"UnicodeData.txt", "CaseFolding.txt", "CompositionExclusions.txt", "extracted/DerivedJoiningType.txt", "emoji/emoji-data.txt"}

type character struct {
	category string
	script   string // the first word of the character's name
	ccc      int
	canon    []int // its canonical decomposition, one step
	compat   []int // its compatibility decomposition, one step
}

// fail stops the run. The data files are read whole or not at all.
func fail(args ...any) { panic(fmt.Sprint(args...)) }

func hexes(s string) []int {
	var out []int
	for _, f := range strings.Fields(s) {
		n, err := strconv.ParseInt(f, 16, 32)
		if err != nil {
			fail("not a code point:", f)
		}
		out = append(out, int(n))
	}
	return out
}

// lines are a data file's lines without comments, split at semicolons.
func lines(dir, name string, sums map[string]string) [][]string {
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		raw, err = os.ReadFile(filepath.Join(dir, filepath.Base(name)))
	}
	if err != nil {
		fail(err)
	}
	sum := sha256.Sum256(raw)
	sums[name] = hex.EncodeToString(sum[:])
	var out [][]string
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ";")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		out = append(out, fields)
	}
	return out
}

// span is "0041" or "0041..005A".
func span(s string) (int, int) {
	first, last, isRange := strings.Cut(s, "..")
	a := hexes(first)[0]
	if !isRange {
		return a, a
	}
	return a, hexes(last)[0]
}

// The characters a signed statement does not take although they are letters,
// marks, numbers, punctuation or symbols (docs/statement-signature.md): the
// variation selectors and the invisible fillers.
var notSeen = [][2]int{{0x034F, 0x034F}, {0x115F, 0x1160}, {0x17B4, 0x17B5}, {0x180B, 0x180F}, {0x2800, 0x2800}, {0x3164, 0x3164},
	{0xFE00, 0xFE0F}, {0xFFA0, 0xFFA0}, {0xFFFC, 0xFFFC}, {0xE0100, 0xE01EF}}

func main() {
	in := flag.String("in", "", "the directory holding the data files")
	out := flag.String("out", "", "where to write the facts (the setupfile package)")
	version := flag.String("version", "", "the Unicode version the files are of, as 15.0.0")
	flag.Parse()
	if *in == "" || *out == "" || len(strings.Split(*version, ".")) != 3 {
		fmt.Fprintln(os.Stderr, "usage: setupunicode -in DIR -out DIR -version 15.0.0")
		os.Exit(2)
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, r)
			os.Exit(1)
		}
	}()
	fmt.Println(make15(*in, *out, *version))
}

// make15 reads the data files in one directory and writes the facts and
// their source note into another. It says what it wrote.
func make15(inDir, outDir, unicodeVersion string) string {
	in, out, version := &inDir, &outDir, &unicodeVersion
	sums := map[string]string{}
	chars := map[int]*character{}

	rows := lines(*in, "UnicodeData.txt", sums)
	for i := 0; i < len(rows); i++ {
		f := rows[i]
		first := hexes(f[0])[0]
		last := first
		name := f[1]
		if strings.HasSuffix(name, ", First>") {
			i++
			last = hexes(rows[i][0])[0]
			name = strings.TrimSuffix(strings.TrimPrefix(name, "<"), ", First>")
		}
		ccc, _ := strconv.Atoi(f[3])
		c := character{category: f[2], script: strings.ToUpper(strings.Fields(name + " ?")[0]), ccc: ccc}
		if d := f[5]; strings.HasPrefix(d, "<") {
			_, rest, _ := strings.Cut(d, ">")
			c.compat = hexes(rest)
		} else if d != "" {
			c.canon = hexes(d)
		}
		for cp := first; cp <= last; cp++ {
			one := c
			chars[cp] = &one
		}
	}
	// Hangul syllables are decomposed and composed by arithmetic, not listed.
	hangul := func(cp int) bool { return cp >= 0xAC00 && cp <= 0xD7A3 }

	excluded := map[int]bool{}
	for _, f := range lines(*in, "CompositionExclusions.txt", sums) {
		excluded[hexes(f[0])[0]] = true
	}
	class := func(cp int) int {
		if c := chars[cp]; c != nil {
			return c.ccc
		}
		return 0
	}
	var full func(cp int, compat bool) []int
	full = func(cp int, compat bool) []int {
		c := chars[cp]
		var step []int
		switch {
		case c == nil || hangul(cp):
		case c.canon != nil:
			step = c.canon
		case compat && c.compat != nil:
			step = c.compat
		}
		if step == nil {
			return []int{cp}
		}
		var out []int
		for _, s := range step {
			out = append(out, full(s, compat)...)
		}
		return out
	}

	var seen, letters, marks, emoji [][]int
	var ccc, nfd, nfkd, compose, fold [][]int
	type named struct {
		first, last int
		word        string
	}
	var script, joining []named
	grow := func(rs *[][]int, cp int) {
		if n := len(*rs); n > 0 && (*rs)[n-1][1] == cp-1 {
			(*rs)[n-1][1] = cp
		} else {
			*rs = append(*rs, []int{cp, cp})
		}
	}
	all := make([]int, 0, len(chars))
	for cp := range chars {
		all = append(all, cp)
	}
	sort.Ints(all)
	for _, cp := range all {
		c := chars[cp]
		major := c.category[:1]
		hidden := false
		for _, r := range notSeen {
			hidden = hidden || cp >= r[0] && cp <= r[1]
		}
		if (strings.Contains("LMNPS", major) || cp == 0x20) && !hidden {
			grow(&seen, cp)
		}
		if major == "L" {
			grow(&letters, cp)
		}
		if major == "M" {
			grow(&marks, cp)
		}
		if major == "L" || major == "M" {
			if n := len(script); n > 0 && script[n-1].last == cp-1 && script[n-1].word == c.script {
				script[n-1].last = cp
			} else {
				script = append(script, named{cp, cp, c.script})
			}
		}
		if c.ccc != 0 {
			if n := len(ccc); n > 0 && ccc[n-1][1] == cp-1 && ccc[n-1][2] == c.ccc {
				ccc[n-1][1] = cp
			} else {
				ccc = append(ccc, []int{cp, cp, c.ccc})
			}
		}
		if hangul(cp) {
			continue
		}
		canon, compat := full(cp, false), full(cp, true)
		if len(canon) != 1 || canon[0] != cp {
			nfd = append(nfd, append([]int{cp}, canon...))
		}
		if fmt.Sprint(compat) != fmt.Sprint(canon) {
			nfkd = append(nfkd, append([]int{cp}, compat...))
		}
		// A primary composite: a canonical pair that is not excluded, whose
		// first character is a starter, and that is itself a starter.
		if len(c.canon) == 2 && !excluded[cp] && c.ccc == 0 && class(c.canon[0]) == 0 {
			compose = append(compose, []int{c.canon[0], c.canon[1], cp})
		}
	}
	sort.Slice(compose, func(i, j int) bool {
		if compose[i][0] != compose[j][0] {
			return compose[i][0] < compose[j][0]
		}
		return compose[i][1] < compose[j][1]
	})
	for _, f := range lines(*in, "CaseFolding.txt", sums) {
		if f[1] == "C" || f[1] == "S" { // simple case folding
			fold = append(fold, []int{hexes(f[0])[0], hexes(f[2])[0]})
		}
	}
	for _, f := range lines(*in, "extracted/DerivedJoiningType.txt", sums) {
		if strings.Contains("DLRT", f[1]) && len(f[1]) == 1 {
			a, b := span(f[0])
			joining = append(joining, named{a, b, f[1]})
		}
	}
	sort.Slice(joining, func(i, j int) bool { return joining[i].first < joining[j].first })
	var emojis []int
	for _, f := range lines(*in, "emoji/emoji-data.txt", sums) {
		if f[1] == "Emoji" {
			for a, b := span(f[0]); a <= b; a++ {
				emojis = append(emojis, a)
			}
		}
	}
	sort.Ints(emojis)
	for _, cp := range emojis {
		grow(&emoji, cp)
	}

	short := strings.Join(strings.Split(*version, ".")[:2], ".")
	var b strings.Builder
	list := func(name string, n int, line func(i int) string, last bool) {
		fmt.Fprintf(&b, " %q: [\n", name)
		for i := 0; i < n; i++ {
			comma := ","
			if i == n-1 {
				comma = ""
			}
			fmt.Fprintf(&b, "  %s%s\n", line(i), comma)
		}
		if last {
			b.WriteString(" ]\n")
		} else {
			b.WriteString(" ],\n")
		}
	}
	ints := func(rows [][]int) (int, func(int) string) {
		return len(rows), func(i int) string {
			parts := make([]string, len(rows[i]))
			for j, v := range rows[i] {
				parts[j] = strconv.Itoa(v)
			}
			return "[" + strings.Join(parts, ",") + "]"
		}
	}
	words := func(rows []named) (int, func(int) string) {
		return len(rows), func(i int) string { return fmt.Sprintf("[%d,%d,%q]", rows[i].first, rows[i].last, rows[i].word) }
	}
	sourceName := "unicode-" + short + ".SOURCE.txt"
	b.WriteString("{\n")
	fmt.Fprintf(&b, " \"unicode\": %q,\n", *version)
	fmt.Fprintf(&b, " \"about\": %q,\n", "Facts of the Unicode Character Database, version "+*version+", that a set-up file's text is judged by (docs/set-up-file.md). "+
		"Made by tools/setupunicode from the Unicode data files named in "+sourceName+", which are Copyright (c) Unicode, Inc. and used under the Unicode License v3 (https://www.unicode.org/license.txt). "+
		"Code points are decimal. A range is [first, last], both included.")
	fmt.Fprintf(&b, " \"members\": %q,\n", "seen: the characters seen as themselves. letters, marks: General_Category L and M. script: [first, last, word], the first word of the name of each letter and mark. "+
		"ccc: [first, last, class], Canonical_Combining_Class where it is not 0. nfd: [character, then its full canonical decomposition]. nfkd: [character, then its full compatibility decomposition], where that is not its canonical one. "+
		"compose: [first, second, composite], the primary composites. fold: [character, what it folds to], simple case folding (statuses C and S). joining: [first, last, Joining_Type], for D, L, R and T. emoji: the Emoji property. "+
		"Hangul syllables are decomposed and composed by arithmetic and are not listed.")
	list("seen", len(seen), ints2(seen), false)
	list("letters", len(letters), ints2(letters), false)
	list("marks", len(marks), ints2(marks), false)
	n, f := words(script)
	list("script", n, f, false)
	n, f = ints(ccc)
	list("ccc", n, f, false)
	n, f = ints(nfd)
	list("nfd", n, f, false)
	n, f = ints(nfkd)
	list("nfkd", n, f, false)
	n, f = ints(compose)
	list("compose", n, f, false)
	n, f = ints(fold)
	list("fold", n, f, false)
	n, f = words(joining)
	list("joining", n, f, false)
	list("emoji", len(emoji), ints2(emoji), true)
	b.WriteString("}\n")
	if err := os.WriteFile(filepath.Join(*out, "unicode-"+short+".json"), []byte(b.String()), 0o644); err != nil {
		fail(err)
	}

	var note strings.Builder
	fmt.Fprintf(&note, "unicode-%s.json was made by tools/setupunicode from these files of the\nUnicode Character Database, version %s:\n\n", short, *version)
	for _, name := range files {
		fmt.Fprintf(&note, "  %s\n    %s%s\n    SHA-256 %s\n", name, fmt.Sprintf(base, *version), name, sums[name])
	}
	note.WriteString(`
The data files are used under the Unicode licence, whose copyright and
permission notice follows word for word, as https://www.unicode.org/license.txt
gave it when the files were fetched. The facts derived are a selection and a
rearrangement of the files' contents, and nothing was added to them.

`)
	note.WriteString(licence)
	note.WriteString(`
What was taken:
  seen      General_Category L, M, N, P, S and U+0020, less the variation
            selectors and the invisible fillers a signed statement refuses
            (docs/statement-signature.md)
  letters, marks, script, ccc, nfd, nfkd, compose
            UnicodeData.txt (and CompositionExclusions.txt for compose)
  fold      CaseFolding.txt, statuses C and S
  joining   extracted/DerivedJoiningType.txt, values D, L, R and T
  emoji     emoji/emoji-data.txt, property Emoji

To move to a later version: fetch that version's files, run the tool with its
-version, and read the diff. A character that becomes seen, a decomposition
that is added, each is one line.
`)
	if err := os.WriteFile(filepath.Join(*out, sourceName), []byte(note.String()), 0o644); err != nil {
		fail(err)
	}
	return fmt.Sprintf("%d seen ranges, %d decompositions, %d composites, %d folds; see %s", len(seen), len(nfd)+len(nfkd), len(compose), len(fold), filepath.Join(*out, sourceName))
}

func ints2(rows [][]int) func(int) string {
	return func(i int) string { return fmt.Sprintf("[%d,%d]", rows[i][0], rows[i][1]) }
}
