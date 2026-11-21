package setupfile

// Writing a reader must take, and writing it must not, each with what it is.
// The characters are written as escapes so that this file holds nothing a
// person cannot see.

// writtenNames are names as their languages write them.
var writtenNames = [][2]string{
	{"Persian, with the non-joiner its spelling needs", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645"},
	{"Thai", "\u0e1c\u0e39\u0e49\u0e0a\u0e48\u0e27\u0e22"},
	{"Lao", "\u0e9c\u0eb9\u0ec9\u0e8a\u0ec8\u0ea7\u0e8d"},
	{"Sinhala, with the joiner its spelling needs", "\u0dc1\u0dca\u200d\u0dbb\u0dd3 \u0dbd\u0d82\u0d9a\u0dcf"},
	{"Bengali", "\u09b8\u09b9\u0995\u09be\u09b0\u09c0"},
	{"Chinese", "\u52a9\u7406"},
	{"Japanese", "\u30a2\u30b7\u30b9\u30bf\u30f3\u30c8 \u4e00\u53f7"},
	{"Korean", "\ub3c4\uc6b0\ubbf8"},
	{"Russian", "\u041f\u043e\u043c\u043e\u0449\u043d\u0438\u043a"},
	{"Greek", "\u0392\u03bf\u03b7\u03b8\u03cc\u03c2"},
	{"French", "\u00c9l\u00e8ve n\u00b0 2 \u00abAssistant\u00bb"},
	{"Spanish, with an ordinal", "Se\u00f1or \u00d1and\u00fa 1.\u00ba"},
	{"Portuguese, with an ordinal", "Cora\u00e7\u00e3o 2.\u00aa"},
	{"Italian", "Perch\u00e9 no"},
	{"a trade mark sign", "Acme\u2122"},
	{"an ellipsis", "Wait\u2026"},
	{"a numero sign", "\u2116 5"},
	{"a superscript and a fraction", "x\u00b2 \u00bd"},
	{"a micro sign", "\u00b5-service"},
	{"fullwidth punctuation", "\u52a9\u7406\uff08\u4e00\uff09"},
	{"halfwidth katakana", "\uff71\uff7c\uff7d\uff80\uff9d\uff84"},
	{"compatibility jamo", "\u3131\u3134"},
	{"an emoji with its selector", "Team \u2764\ufe0f"},
	{"a Latin word and a Cyrillic word", "Acme \u043e\u0442\u0434\u0435\u043b"},
	{"a Latin word and a Greek word", "Acme \u03bf\u03bc\u03ac\u03b4\u03b1"},
}

// notNames are text that is not a name.
var notNames = [][2]string{
	{"a word mixing Latin and Cyrillic letters", "Re\u0430der"},
	{"a word mixing Latin and Greek letters", "Re\u03b1der"},
	{"a word mixing them after it is written plainly", "\uff32\u0435ader"},
	{"an accent apart from its letter", "Cafe\u0301"},
	{"the Kelvin sign, which is the letter K written again", "\u212a2"},
	{"a compatibility ideograph, which is another character written again", "\uf900"},
	{"a non-joiner between Latin letters", "Rea\u200cder"},
	{"a joiner between emoji", "\U0001f468\u200d\U0001f469"},
	{"a joiner between a letter and its virama", "\u09b0\u200d\u09cd\u09af"},
	{"a non-joiner after an Arabic letter at the end of a word", "\u062e\u0627\u0646\u0647\u200c"},
	{"a selector after a letter", "A\ufe0f"},
	{"a no-break space", "No\u00a0break"},
	{"a soft hyphen", "co\u00adoperate"},
	{"a zero-width space", "Zero\u200bwidth"},
	{"a right-to-left override", "Turned\u202earound"},
	{"a bell", "Bell\u0007"},
	{"a letter assigned after the pinned version", "Later \u1c89"},
	{"two spaces", "Two  spaces"},
	{"an at sign", "named@elsewhere"},
}

// oneName are two spellings that are one name.
var oneName = [][3]string{
	{"fullwidth letters", "Reader", "\uff32\uff45\uff41\uff44\uff45\uff52"},
	{"mathematical bold letters", "Reader", "\U0001d411\U0001d41e\U0001d41a\U0001d41d\U0001d41e\U0001d42b"},
	{"a ligature", "Office", "Of\ufb01ce"},
	{"another case", "Reader", "READER"},
	{"the long s", "Mass", "Ma\u017fs"},
	{"an ordinal and a plain letter", "1.\u00ba", "1.o"},
	{"halfwidth and fullwidth katakana", "\u30a2\u30b7", "\uff71\uff7c"},
	{"an emoji with and without its selector", "Team \u2764", "Team \u2764\ufe0f"},
	{"Persian with and without its non-joiner", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", "\u0645\u06cc\u062e\u0648\u0627\u0647\u0645"},
	{"Hindi with and without a joiner after its virama", "\u0915\u094d\u0937", "\u0915\u094d\u200d\u0937"},
	{"Tamil with and without a non-joiner after its pulli", "\u0b95\u0bcd\u0bb7", "\u0b95\u0bcd\u200c\u0bb7"},
	{"Sinhala with and without its joiner", "\u0dc1\u0dca\u0dbb\u0dd3", "\u0dc1\u0dca\u200d\u0dbb\u0dd3"},
	{"a final and a medial sigma", "\u03bf\u03b4\u03bf\u03c3", "\u03bf\u03b4\u03bf\u03c2"},
}

// twoNames are two names that are not one.
var twoNames = [][3]string{
	{"a sharp s and two", "Stra\u00dfe", "STRASSE"},
	{"a dotted capital I and a plain i", "\u0130stanbul", "istanbul"},
	{"one space and none", "Reader One", "ReaderOne"},
	{"a hyphen and a space", "reader-one", "reader one"},
}

// writtenText is text that is not a name and is still text; notText is not.
var writtenText = [][2]string{
	{"French, with a no-break space and a narrow one", "Prix : 10\u202f000\u00a0\u20ac \u2014 \u00ab\u00a0oui\u00a0\u00bb"},
	{"a soft hyphen", "co\u00adoperate"},
	{"lines ended as some systems end them", "line one\r\nline two"},
	{"a compatibility ideograph", "\uf900"},
	{"a joiner between two emoji", "\U0001f468\u200d\U0001f469"},
	{"a joiner between an emoji with its selector and another", "\u2764\ufe0f\u200d\U0001f525"},
	{"a joiner between two emoji, beside digits", "1 \U0001f469\u200d\U0001f4bb 2"},
	{"Bengali, with a joiner between a letter and its virama", "\u09b0\u200d\u09cd\u09af\u09be\u09ac"},
	{"Kannada, with a joiner between a letter and its virama", "\u0cb0\u200d\u0ccd\u0caf"},
	{"a non-joiner after an Arabic letter at the end of a word", "\u062e\u0627\u0646\u0647\u200c \u0627\u0645"},
	{"an accent apart from its letter", "Cafe\u0301"},
}

var notText = [][2]string{
	{"a carriage return with no line feed", "line one\rline two"},
	{"a zero-width space", "Zero\u200bwidth"},
	{"a right-to-left override", "Left\u202eright"},
	{"a non-joiner between Latin letters", "Rea\u200cder"},
	{"a joiner between Latin letters", "Rea\u200dder"},
	{"a joiner after an emoji and before a letter", "\U0001f468\u200da"},
	{"a joiner between two digits", "1\u200d2"},
	{"a joiner between a digit and an emoji", "1\u200d\U0001f525"},
	{"a joiner between a number sign and an asterisk", "#\u200d*"},
	{"a left-to-right mark", "left\u200eright"},
	{"a thin space", "10\u2009000"},
	{"a figure space", "10\u2007000"},
	{"an em space", "wide\u2003space"},
}
