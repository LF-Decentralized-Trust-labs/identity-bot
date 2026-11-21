# Set-up file (v1)

An Identity Agent's set-up can be written to one file and proposed from one
([ADR-088](adr/088-an-identity-agents-set-up-is-exported-to-one-file-and-imported-only-by-a-signed-approval.md)).
This is the format of that file, the rules a reader follows, the seal a file may carry, and the bytes an approval
signs. Anyone who writes such a file or reads one needs it, so it is open and has byte-exact vectors:
[`identity-agent-core/setupfile/set-up-file-vectors.json`](../identity-agent-core/setupfile/set-up-file-vectors.json),
rebuilt by the core's tests (`identity-agent-core/setupfile`) and read by an independent checker written from this
document (`identity-agent-core/contracts/check_set_up_file_vectors.py`).

**A file gives no authority.** Reading one yields a list to show a person. What is created is decided by a signed
approval of the items the owner chose, and every identity and grant is made new by the importing Identity Agent.

**ADR-088 is proposed, and so is this.** The record's decisions are taken. Much of
the detail below was chosen while writing the reader and has been decided by nobody yet: each such value and rule is
listed under "Starting values and rules proposed here", at the end, and is a proposal until it is decided.

## The file

One JSON object, UTF-8, at most **4 MiB**. Its members:

| Member | Required | What it is |
|---|---|---|
| `format` | yes | `identity-agent-set-up/1`. See "Versions". |
| `items` | yes | A list of at most **500** items. It may be empty. |
| `made_at` | no | When the file was made: a time (see "Times"). |
| `about` | no | A note about the file: text of at most 2048 bytes. |
| `credentials_needed` | no | A list of at most **200** credentials the importer will need, each an object with `name` and, optionally, `about`, and no other member. `name` is a name (see "Names"), and no two are one name. `about` is text of at most 2048 bytes. |
| `seal` | no | See "The seal". |

Any other member refuses the file.

**`null` is never a value**, anywhere in a file: not of a member, not in a list. A member that has no value is left
out. Readers disagree about what a null means (an empty string, nothing, zero), so a file holding one is refused.

### An item

An object. Every item may carry these five members, whatever its kind:

| Member | Required | What it is |
|---|---|---|
| `kind` | yes | What the item is: lower-case words of letters, digits and `_`, joined by dots (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`), at most 64 bytes. See "Kinds and extensions". |
| `name` | yes | What a person calls it. See "Names". |
| `permissions` | no | A list of at most **200** permissions, none twice. Absent means none. |
| `limits` | no | Limits on those permissions. Absent means none. |
| `grant_end` | no | When the item's grant ends: a time. Absent means it holds until revoked. |

Every other member is the kind's own, except `extensions`.

**A permission** is written one of two ways:

- a capability identifier, as a string: two or more lower-case words joined by dots
  (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`), at most 128 bytes and not shaped like an identifier or a secret, such as
  `code.repository.read`;
- a permission on a utility app, as an object with exactly the members `utility_app` and `permission`: the utility
  app's **name**, and one lower-case word (`^[a-z][a-z0-9_]{0,63}$`). The utility app's identifier is never written,
  because it means nothing to another Identity Agent.

Two permissions on a utility app are one permission when the word is the same and the two names are one name.

**Which utility app a name means.** A permission on a utility app, or a field a kind declares to name one, names
either a utility-app item of the same file, or a utility app the importing Identity Agent already has. An item of any
other kind that happens to have the name is **not** the utility app: a website called "Board" does not satisfy a
permission on the utility app "Board". A reader lists the utility apps an item names (`utility_apps`), which of them
are utility-app items of the file (`depends_on`), and flags the item `needs_set_up_here` for any that is not. Which one
is meant is fixed when the list is signed (see "The chosen list").

**Limits** are an object: capability identifier, then argument, then the list of values that argument may take, each
a string:

    "limits": {"code.repository.read": {"repository": ["example/handbook", "example/site"]}}

This is the shape of the constraints in a grant (ADR-045), with every value a string. A limit is on a **capability**
the item asks for; a permission on a utility app is not a capability and takes no limit. A limit names 1 to 32
arguments, each one lower-case word, each with 1 to 256 different values, each value 1 to 256 bytes of text on one
line. A limit's value names something outside the Identity Agent (a repository, a DNS zone), so every limit is flagged
`needs_access_here`: the importing organisation must itself be able to reach it.

### The Unicode facts, pinned

Text a person reads and then approves must hold nothing they cannot see, and a name must not be another name written
another way. Both are questions about characters, and a library's answer changes with its version. So every Unicode
fact this format uses is published in one file,
[`unicode-15.0.json`](../identity-agent-core/setupfile/unicode-15.0.json), at **Unicode 15.0.0**, and every
implementation reads that file and never its own tables: not for which characters are seen, not for normalization,
not for case. A character assigned after Unicode 15.0.0 is not in it, whatever a later library knows.

The file is made by `identity-agent-core/tools/setupunicode` from five data files of the Unicode Character Database
(`UnicodeData.txt`, `CaseFolding.txt`, `CompositionExclusions.txt`, `extracted/DerivedJoiningType.txt` and
`emoji/emoji-data.txt`, under `https://www.unicode.org/Public/15.0.0/ucd/`).
[`unicode-15.0.SOURCE.txt`](../identity-agent-core/setupfile/unicode-15.0.SOURCE.txt) gives each file's SHA-256 as
read. The data files are Copyright © Unicode, Inc. and are used under the
[Unicode License v3](https://www.unicode.org/license.txt). The file is written one range or one character to a line,
so that moving to a later version is a diff a person can read.

Its members (code points in decimal; a range is `[first, last]`, both included):

| Member | What it is |
|---|---|
| `seen` | The characters seen as themselves. |
| `letters`, `marks` | General_Category L and M. |
| `script` | `[first, last, word]`: the first word of the name of each letter and mark (`LATIN`, `GREEK`, `CYRILLIC`, …). |
| `ccc` | `[first, last, class]`: Canonical_Combining_Class, where it is not 0. |
| `nfd` | `[character, …]`: the character's full canonical decomposition. |
| `nfkd` | `[character, …]`: its full compatibility decomposition, where that is not its canonical one. |
| `compose` | `[first, second, composite]`: the primary composites. |
| `fold` | `[character, what it folds to]`: simple case folding (statuses C and S). |
| `joining` | `[first, last, type]`: Joining_Type, for D, L, R and T. |
| `emoji` | The Emoji property. |

Hangul syllables are decomposed and composed by arithmetic, as the Unicode Standard gives it, and are not listed.

**A character is seen as itself** under the rule a signed statement is held to
([statement-signature.md](statement-signature.md)), fixed at this version: its General_Category is a letter, a mark,
a number, punctuation or a symbol, or it is U+0020, and it is not a variation selector or one of the invisible fillers
that rule names. So a control character, a format character (bidirectional marks, zero-width characters, joiners), a
private-use, surrogate or unassigned character, a line or paragraph separator and a space other than U+0020 are not
seen.

**A few characters that are not seen are let through where writing needs them:**

- **A zero-width non-joiner (U+200C) and a zero-width joiner (U+200D)**, where Unicode's identifier rules allow one
  ([UAX #31](https://www.unicode.org/reports/tr31/tr31-37.html), section 2.3, for Unicode 15.0):
  - *A1*, a non-joiner between two characters that would otherwise join: before it, a character of Joining_Type L or D
    and then any of type T; after it, any of type T and then a character of type R or D (Persian);
  - *A2*, a non-joiner after a virama and before a letter;
  - *B*, a joiner after a virama (Sinhala, and the scripts of India).

  "After a virama" is: a letter, then any marks, then a character of class 9, then only marks of a class other than 0.
  In a name, a joiner anywhere else is not let through, which includes a joiner between emoji.
- **A variation selector 15 or 16 (U+FE0E, U+FE0F)** directly after a character that has the Emoji property.
- **In text of several lines only** (never in a name): a line feed, a tab, a carriage return directly before a line
  feed, a no-break space (U+00A0), a narrow no-break space (U+202F), a soft hyphen (U+00AD), and three more places
  for a joiner, where ordinary writing puts one:
  - a joiner between two characters that have the Emoji property, neither of them ASCII (a variation selector 15 or
    16 may stand between the first and the joiner). The digits, `#` and `*` have the Emoji property too, and a joiner
    between two of them would sit unseen inside a key;
  - a joiner between a letter and a character of class 9, in either order (the Bengali and Kannada spellings);
  - a non-joiner directly after a letter whose `script` word is `ARABIC`.

  The bidirectional marks, and the thin, figure and em spaces, stay refused in text as in names.

Text that holds only such characters is called *shown* below: on one line, or of several lines.

**Normalization.** Normalization Form C and Form KC are made as the Unicode Standard defines them (UAX #15), from
`nfd`, `nfkd`, `ccc` and `compose`: decompose each character fully (by compatibility too, for KC); put each run of
marks in order of class, stably; then compose each character with the last character of class 0 before it, wherever
the two are a pair in `compose` (or a Hangul pair) and nothing between them is of class 0 or of the character's own
class or higher.

### Names

A name is what a person calls a thing, and it may be spelt as its language spells it. It is:

- 1 to **64 bytes** of UTF-8, shown on one line;
- without a space before or after it, without two spaces together, and without `@`;
- **in Normalization Form C**: an accent is joined to its letter where Unicode has the joined character;
- without a **word** that mixes letters of Latin, Greek and Cyrillic (below);
- not shaped like an identifier or a secret (see "Text shaped like a secret or an identifier").

So an ordinal (`1.º`), `™`, `…`, `№`, `²`, `½`, a micro sign, fullwidth punctuation, halfwidth katakana and
compatibility jamo are all writable in a name. A character whose canonical form is another character (the Kelvin
sign, a CJK compatibility ideograph) is not: it is that other character written again, and is not in Form C.

**Two names are one name** when they have the same *folded form*: the name with spaces trimmed from its ends, written
in Normalization Form KC, each character replaced by what `fold` gives for it, written in Form KC again, with every
variation selector 15 or 16, joiner and non-joiner taken out. So a name spelt with fullwidth, bold or ligature
letters, in another case, or with a joiner more or fewer, **is the same name** as the plain one, never a second name.
A joiner changes at most how the letters beside it are drawn, and two names that differ only by one look alike. That
also takes two Persian words that a non-joiner tells apart for one name, which errs the safe way: a second item is
blocked, and nothing is created under a name that reads like another. No two items of a file have one name, whatever their
kinds. Of two that do, the later is blocked.

**Mixed scripts, by word.** A word is a run of letters and marks (a joiner or non-joiner does not end one). The name
is first written in Form KC. A word that holds letters whose `script` word is more than one of `LATIN`, `GREEK` and
`CYRILLIC` is refused. A name may hold a Latin word and a Cyrillic or Greek word ("Acme отдел").

This catches the common look-alike, one borrowed letter in a word, and **not every one**. It does not catch a whole
word in one script that reads as a word in another, a digit used for a letter, or look-alikes in other scripts, and
there is no table of confusable characters. **What protects a grant is not this rule.** It is that the signed list
binds every name it relies on to one thing (see "The chosen list"), and that an existing name is never overwritten.

### Times

UTC, to the second, in exactly this spelling: `2026-11-20T09:00:00Z`. The year is 0001 to 9999, and the time is one
that exists.

### Text and numbers

Every string in an item is at most **64 KiB**, and is shown, as text of several lines. A kind may hold its own text
to less. A member's name inside an item is at most 128 bytes, shown on one line, and not shaped like an identifier or
a secret.

Text is not required to be in a normalization form: only names are.

Every number in a file is a whole number written plainly (`7`, never `7.0`, `7e0` or `-0`) and no larger than
2^53 - 1 either way, so that every reader reads the same number and the canonical form is unambiguous.

## What a file never holds

- a key, a seed, a token, or a digest of one;
- the identifier of an asset, a grant, a machine or a controller;
- members, employees or invites;
- conversations, activity, or anything an AI agent remembered;
- anything revoked;
- a setting that is the owner's alone: owners, signers, controllers, witnesses, recovery.

**A credential is named, never carried.** An item that needs one refers to it by a name in `credentials_needed`.

**The exporting organisation's own identifier is written `self`**, wherever a member names an identity.

**An identifier from elsewhere** may appear in two places only: as a limit's value, and in a member its kind declares
to hold one (below, a website's `required_cred_schema` and `required_cred_issuer`). Each is flagged
`needs_access_here`. Such a member holds `""`, `"self"` or an identifier and nothing else.

**What keeps a secret out of a file is the exporter.** An exporter writes names and settings and never reads a secret
into a file. The check below is a floor under that, for a secret a person typed into a note or an instruction. It is
not a guarantee: a secret in a spelling nobody listed passes, and so does one spelt with a letter of another script
that looks like a Latin one.

### Text shaped like a secret or an identifier

Text is judged by its shape, whatever it claims to be. A **run** is the longest stretch of ASCII letters, digits, `-`
and `_`, so a sentence or a web address is judged word by word. A run is *mixed* when it holds an upper-case letter, a
lower-case letter and a digit. Text has the gravest shape found in it. A *token character* is a letter, a digit, `-`
or `_`; letters and digits are ASCII. Text is judged as a reader sees it: with every character that is not seen as
itself (the `seen` list of the pinned facts) taken out first, but a tab, a line feed, a carriage return, a no-break
space (U+00A0) and a narrow no-break space (U+202F), which end a word where they stand. That takes out the joiners,
the variation selectors and the soft hyphen, and also zero-width spaces, word joiners, byte order marks, marks of
direction, fillers and tag characters, so that none of them can split a key that looks whole on a screen. Text is a
secret also when its Normalization Form KC, with the same characters taken out, is one, so that a key spelt in
fullwidth or mathematical letters is still a key.

**A spelling only a secret has refuses the file.** These, and no others, so that a file one exporter writes is never
refused by another's importer for a reason its exporter could not have known:

- a private key block: `-----BEGIN`, a space, any upper-case letters, digits and spaces, `PRIVATE KEY`, optionally
  ` BLOCK`, then `-----` (so `-----BEGIN PGP PRIVATE KEY BLOCK-----` is one);
- a token of a known beginning, at a word boundary: `ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_` and 20 or more letters and
  digits; `github_pat_` and 20 or more letters, digits and `_`; `glpat-` and 20 or more token characters; `npm_` and 36
  letters and digits; `sk_live_` or `rk_live_` and 10 or more letters and digits; `xoxa-`, `xoxb-`, `xoxp-`, `xoxr-` or
  `xoxs-` and 10 or more letters, digits and `-`; `AKIA` and exactly 16 upper-case letters and digits; `AIza` and 35
  token characters; `AGE-SECRET-KEY-1` and 20 or more upper-case letters and digits; `SG.`, 22 token characters, a
  dot and 43 token characters;
- **`sk-`** at a word boundary, followed by token characters, where **the part after the last `-` or `_` is 20 or
  more letters and digits and holds a digit**. So `sk-` and 32 hexadecimal characters is one, and `sk-or-v1-` and 64
  is one, and `sk-Report-2026-final-version-x` and `sk-notes-internationalisationguide` are not;
- a JSON Web Token: `eyJ` and 8 or more token characters, a dot, the same again, and a dot;
- **a web address that carries a user and a password that is not a placeholder**: a scheme (a letter, then letters,
  digits, `+`, `.` or `-`), `://`, a user, `:`, a password and `@`, where neither the user nor the password holds a
  space, a tab, a line break, `/`, `?`, `#` or `@`, and the user holds no `:`. The password is a placeholder, and the
  address is not a secret, when the whole of it is: in any case, one of `password`, `pass`, `passwd`, `pwd`, `secret`,
  `token`, `changeme`, `redacted`, `example`, `your-password` or `your_password`; or only `x` or only `*`; or a
  variable, `$NAME` or `${NAME}`, the name in capitals, digits and `_`; or a name in closed brackets, `<…>`, `{…}`,
  `{{…}}` or `[…]`, with no bracket of the same kind inside; or `%s`. Something that only begins like one of these is
  a password. So `postgres://USER:PASSWORD@HOST`, `https://user:pass@host` and `https://user:${DB_PASSWORD}@host` are
  not secrets, and `postgres://admin:$uperS3cret9@host` is. `mailto:` has no `://` and is not
  judged;
- a mixed run of 44 characters beginning `A` in canonical qb64: an Ed25519 seed in CESR;
- a run of exactly 24 characters, the whole run, that decodes as a salt in CESR: the code `0A` and 16 bytes in
  canonical qb64.

**What may be a secret blocks the item it is in, and never the file** (`looks_like_a_secret`). These are rules of
thumb, and they will sometimes catch text that is not a secret:

- a run of 64 or more hexadecimal characters holding a letter and a digit;
- a run of 40 or more characters holding an upper-case letter, a lower-case letter and three or more separate groups
  of digits, that is not shaped like an identifier.

In a note about the file itself, such text is flagged and the file is read.

**Text shaped like an identifier** holds a run that is:

- 44 characters beginning `E`, `D` or `B` in canonical qb64 (a digest, a key or an identifier in CESR), or 48
  characters beginning `1AAI`;
- 32 to 63 hexadecimal characters holding a letter and a digit.

It blocks the item (`identifier_shaped`), except where an identifier may appear (above), and except in **prose**: a
member its kind declares to hold text a person wrote for a reader, such as instructions or a note. There a commit, a
record number or an identifier is flagged (`identifier_in_text`) and does not block.

Canonical qb64 here means the base64url alphabet with the value's lead bits zero.

## What a reader does

A reader **refuses the file** with the first of these that applies, in this order:

| Reason | When |
|---|---|
| `too_large` | The file is over 4 MiB. |
| `not_json` | The file is not one JSON object that every reader reads the same way: it is not valid UTF-8, begins with a byte order mark, names a member twice in one object, holds half of a surrogate pair, holds a number too large for a 64-bit float, is nested more than 64 deep, or has anything after the object. |
| `not_a_set_up_file` | `format` is absent or is not `identity-agent-set-up/<major>`. |
| `newer_version` | The major version is higher than the reader's. |
| `secret_shaped` | Any string in the file outside `seal`, or any member's name, is in a spelling only a secret has. |
| `null_value` | A null is anywhere in the file outside `seal`. |
| `bad_number` | Any number outside `seal` is not a whole number written plainly. |
| `unknown_field` | The file has a member not in the table above. |
| `bad_field` | `made_at`, `about` or `credentials_needed` is not as the table says. |
| `bad_name`, `name_identifier_shaped`, `duplicate_name` | A needed credential's name is not a name, is shaped like an identifier or a secret, or is named twice. |
| `bad_seal` | `seal` is not written as "The seal" says. A seal that is not written as one refuses the file. |
| `bad_field` | `items` is absent or is not a list. |
| `too_many_items` | There are more than 500 items. |

The three checks of the whole file (a secret, a null, a number) are each made over the whole file before the next, so
the reason given does not depend on the order of the file's members.

**Nothing a reader says repeats text from the file.** A refusal or a finding says where, and never what:

- A place is said in the format's own member names (`items`, `policy`, `origin`, and so on), in the member names a
  kind declared as its own, and otherwise **by position**: `member 3` is the third member of that object, with its
  members sorted by code point. A name the file gave a member is never said, however short and plain: it may be a
  password.
- An item's `name` is kept only when it is a name. An item whose name is not one is listed with no name.
- A kind or an extension an add-on adds says nothing in its own words. It hands back a code and a place, and the
  reader shows the sentence the kind **declared in advance** for that code. A code the kind did not declare, and that
  is not one of the reader's own, is shown as `bad_field`.

What a reader says is logged and shown, and a file is written by somebody else.

A file that is not refused is read item by item. **Every item is listed**, in the file's order, as one of:

- **`ready`**: read in full. It may be chosen.
- **`not_understood`** (`unknown_kind`): its kind is one the reader does not know. It is listed by its kind and its
  name, and skipped. It is never dropped, and it cannot be chosen. Its name is still held to the rules of a name, and
  those findings are listed with it.
- **`blocked`**, with every reason:

| Reason | When |
|---|---|
| `not_an_object` | The item is not an object. |
| `bad_field` | A member is not written as this document says: the kind, a permission, a limit, the grant end, a field of the kind, a utility app a field names, or a member's name. A permission that carries an identifier is one of these. |
| `bad_name`, `name_identifier_shaped` | The name is not a name, or is shaped like an identifier or a secret. |
| `duplicate_name` | An earlier item of the file has this name. |
| `duplicate_item` | An earlier item of the same kind is the same thing by the kind's own measure: a second website of one origin. |
| `unknown_field` | The item has a member its kind does not know, at any depth. |
| `unknown_extension` | The item has an extension the reader does not know. |
| `unknown_permission` | The importing Identity Agent does not know a permission the item asks for. |
| `limit_without_permission` | A limit is on a capability the item does not ask for. |
| `grant_ended` | The grant would already have ended. |
| `unknown_credential` | The item needs a credential that `credentials_needed` does not name. |
| `looks_like_a_secret` | A string may be a secret, by the rules of thumb above. |
| `identifier_shaped` | A string is shaped like an identifier, outside where one may appear and outside prose. |
| `text_too_long`, `hidden_character` | A string is over 64 KiB, or is not shown. |

An item may also carry **flags**, which do not block it and are shown to the person: `needs_access_here`,
`needs_set_up_here` and `identifier_in_text`, each described above. The file itself may carry `looks_like_a_secret`
and `identifier_in_text`, for its notes.

For each item a reader also computes **`rest`**: Blake3-256, as CESR qb64 under the code `E`, of the bytes
`identity-agent-set-up-rest/1`, a line feed, and then the canonical JSON of the item with its `kind`, `name`,
`permissions`, `limits` and `grant_end` removed. An approval signs it (below).

## Versions

`format` is `identity-agent-set-up/` and a major version, a whole number from 1 with no leading zero.

- A reader refuses a file of a higher major version. It does not try to read what it can.
- The major version changes only when a reader of the earlier one would misread a file.
- A new kind and a new extension are not a new version. A reader that does not know a kind lists the item as not
  understood. A reader that does not know an extension, or a field, blocks the item that carries it.
- A new member of the file itself is a new major version, because a reader refuses a member it does not know.

There is no minor version. A reader never has to guess whether what it does not know is safe to ignore: it is not.

## Kinds and extensions

**The format itself defines three kinds, each written as one word:**

| Kind | What it is | Its fields |
|---|---|---|
| `website` | A website people sign in to with their own Identity Agents. | Below. |
| `ai_agent` | An AI agent an Identity Agent holds. | **Reserved.** Published in the change that follows this one. |
| `utility_app` | A utility app that is an asset of an Identity Agent. | **Reserved.** Published in the change that follows this one. |

An AI agent and a utility app are the format's own kinds, defined from the fields the core's own asset model already
holds (ADR-045, ADR-047, ADR-072): what an add-on alone knows about an AI agent rides in an extension. Their fields are not published yet, and **version 1 of the reader as first shipped reads `website` only.**
Until the change that publishes them, a file that holds an `ai_agent` or a `utility_app` item is read like any file
with a kind the reader does not yet understand: the item is listed by its kind and name and skipped in plain sight,
and never dropped. Nobody else may use either word for a kind of their own.

A reader holds a registry of the kinds it reads (`setupfile.Registry`): for each kind, how to parse its own members
strictly, how to check them, and how to describe them to a person.

- **A kind written as one word** is the format's: its fields are published in this document. Two implementations
  never mean different things by one word.
- **Any other kind carries its maker's namespace** before a dot (`example.worker`).
- **A kind may be a utility-app kind**: its items are utility apps, which a permission on a utility app may name.
- **A kind may declare** members that hold an identifier from elsewhere, members that are prose, fields that name a
  utility app, what makes two of its items the same thing, its own member names, and the sentence for each fault it
  may find.
- **`extensions`** is an object with one member to a namespace (`"extensions": {"example.labels": {...}}`), for fields
  an add-on carries on an item of a kind that is not its own. A namespace is written as a kind is, with at least one
  dot.

The reader's rules hold for every kind and extension, whoever wrote it.

### `website`

A website people sign in to with their own Identity Agents. It asks nothing of the Identity Agent, so it holds no
`permissions`, `limits` or `grant_end`: any of them blocks the item. An import gives a website an identity and no
grant.

| Member | Required | What it is |
|---|---|---|
| `origin` | yes | The website's origin, in its one spelling (below). |
| `policy` | yes | Who may sign in. An object: |
| `policy.mode` | yes | `open`, `request` or `invite`. |
| `policy.membership_source` | no | Whose list of members is consulted. Absent, `""` or `asset` is the website's own. Any other value is a short lower-case name (`^[a-z][a-z0-9_-]{0,63}$`) of a list the importing Identity Agent must already keep, and is flagged `needs_set_up_here`. |
| `policy.required_cred_schema` | no | The identifier of the schema of a credential a person must present: a digest in CESR under the code `E`. |
| `policy.required_cred_issuer` | no | Who must have issued that credential: absent for anybody, `self` for the importing organisation, or another identity's identifier. Allowed only with `required_cred_schema`. |

**An origin** is at most 300 bytes and is written exactly one way, because origins are compared as text:

- `http://` or `https://`, in lower case;
- a host: a DNS name in lower case (labels of 1 to 63 letters, digits and hyphens, not beginning or ending with a
  hyphen, joined by dots, 253 bytes at most, no trailing dot); or an IPv4 address as four decimal numbers without a
  leading zero, and a host whose last label is a number or reads as one (`0x7f`) is accepted only in that form; or an
  IPv6 address in brackets in its shortest form, with no zone and not an IPv4-mapped one;
- a port, `:` and 1 to 65535 with no leading zero, **only when it is not the scheme's own** (443 for https, 80 for
  http): `https://portal.example` and `https://portal.example:8443`, never `https://portal.example:443`;
- nothing after it: no path (not even `/`), query, fragment or user.

**Two websites of one origin are one website twice.** The origin is the core's own key for a website, so the later
item is blocked (`duplicate_item`).

These are the members of the core's enrolment policy under the same names. The policy's three gates the core cannot
check (an assurance level, a badge, a score) are never stored by it, so they have no place here and block the item
as fields nobody knows.

## The canonical contents and their digest

The **contents** of a file are the file without its `seal` member, written in the JSON Canonicalization Scheme
([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)): members sorted by UTF-16 code units, no white space, strings with
the shortest escapes. The **digest** of a file is Blake3-256 of those bytes, written as CESR qb64 under the code `E`
(44 characters).

So the digest is over what a file says, not how it is laid out: a file written again with other spacing, or its
members in another order, has the same digest. One character of any name, text or value changed gives another.

## The seal

A file may carry the exporting Identity Agent's seal:

    "seal": {
      "by": "<the exporting Identity Agent's identifier>",
      "kel_sn": <a whole number, 0 or more>,
      "contents": "<the digest of the contents that were sealed>",
      "signature": "<Ed25519, as a CESR indexed signature>"
    }

All four members are required, none is null, and no other is allowed. A seal that is not written this way refuses
the file.

**What is signed** is the envelope of [statement-signature.md](statement-signature.md), used as its section "A
statement made unasked" says. The statement is three lines:

    set-up-seal/1
    contents=<the digest>
    kel-sn=<kel_sn, in decimal>

and the envelope's `asker` line carries the sealing Identity Agent's own identifier, `by`. The signed bytes are:

    statement-signature/1\n
    asker: <by>\n
    \n
    set-up-seal/1\n
    contents=<the digest>\n
    kel-sn=<kel_sn>

The signature is Ed25519 over those bytes, as a CESR indexed signature (code `A`, index 0, so it begins `AA`; 88
characters). `kel_sn` is the sequence number of the establishment event that set the key that signs. It is inside the
signed bytes, so a seal cannot be moved to another key event.

**Who can make a seal.** Only the device that holds the identity's key. An Identity Agent whose key is on another
device exports unsealed, unless that device signs. An identity whose key state holds more than one key does not seal
in version 1, and a seal that names one is left unchecked.

**How a seal is checked.** A verifier:

1. finds, in a key log of `by` that it verified itself, the one key the establishment event at `kel_sn` put in force.
   A key is never taken from the file, and a file carries none. If the log cannot be had, has no such event, or names
   more than one key there, the seal is **unchecked**;
2. rebuilds the signed bytes from the seal's own `by`, `contents` and `kel_sn`, and checks the signature. If it does
   not verify, the seal is **broken**. This comes before the next step on purpose: a seal anybody wrote in somebody
   else's name is broken;
3. computes the digest of the file's contents itself. If it is not `contents`, the file **carries a seal made for
   other contents** (`changed`). That is all it shows. The file may have been edited after it was sealed, or a
   genuine seal may have been copied onto a file its sealer never saw, and nothing tells the two apart. So the sealer
   is **not named**;
4. asks whether the event at `kel_sn` is still the log's latest establishment event. If it is not, the file was
   **sealed by an earlier key**: true once, and whoever holds a key the sealer has left can still make such a seal.

| A seal is found | It means | A review shows |
|---|---|---|
| `unsealed` | The file has no seal. | "Not sealed." |
| `sealed` | The signature verifies under the sealer's key in force, over these contents. | "Sealed by" and the sealer, "and unchanged since." |
| `sealed_by_an_earlier_key` | The signature verifies over these contents, under a key the sealer has since replaced. | "Sealed by" and the sealer "with a key it no longer uses." Never as sealed. |
| `changed` | The signature verifies, over other contents. | "Carries a seal made for other contents." It names nobody. |
| `broken` | The signature does not verify. | "Carries a seal that does not verify." It names nobody. |
| `unchecked` | The sealer's key could not be found. | "Carries a seal that could not be checked." It names nobody. |

Only the two states in which the signature verifies **over these contents** name a sealer.

**What a seal that holds proves:** these contents left that Identity Agent as they are now. It gives nothing in the
file any authority, it does not say the contents are right, and it is not required: a file edited by hand, or never
sealed, is read the same way and reviewed the same way.

## The chosen list: what an approval signs

The owner chooses items of a proposal, and the Identity Agent fixes the choice as a **chosen list**:

    {
      "format": "identity-agent-set-up-approval/1",
      "identity_agent": "<the importing Identity Agent's identifier>",
      "proposal": "<the kept proposal: 16 to 128 base64url characters>",
      "nonce": "<22 to 128 base64url characters>",
      "source": {
        "contents": "<the digest of the file>",
        "seal": "<what the seal was found to be>",
        "sealed_by": "<the sealer, when the seal holds over these contents; otherwise empty>"
      },
      "items": [
        {
          "item": <the item's place in the file, from 0>,
          "operation": "create",
          "kind": "...", "name": "...",
          "permissions": [ ... ], "limits": { ... }, "grant_end": "<a time, or empty>",
          "rest": "<the item's rest digest>",
          "acknowledged": [ <the item's permissions the owner acknowledged one by one> ],
          "utility_apps": [ <the names of the utility apps the item's own fields name> ]
        }
      ],
      "utility_apps": [ {"name": "<a utility app the list names>", "is": "item" | "existing", "identifier": "<...>"} ],
      "credentials": [ {"name": "<a credential a chosen item needs>", "use": "<a stored credential's name, or empty>"} ]
    }

**One choice has one list.** Every member is always written, an empty list as `[]`, an empty object as `{}` and an
absent time or name as `""`, and there is no other member and no null. The list is built in one order, whatever order
things were chosen in:

- **items** in the file's order, each once: `item` rises through the list. There are 1 to 500;
- each item's **acknowledged** permissions in the order of its `permissions`, each once, each one of them;
- each item's **utility_apps**: the utility apps its own fields name, in the order the kind gives them, each a name,
  no two one name;
- the list's **utility_apps**: every utility app the list names, once each, in the order the list first names them
  (item by item: those its permissions are on, then those its fields name), each under the name as first written;
- **credentials**: every credential a chosen item needs, in the order of the file's `credentials_needed`.

Each item's members are held to the rules of a file's item. No two items have one name.

**A choice names each thing once.** A choice that maps one utility app twice, or one credential twice, under two
spellings of one name (`Board` and `BOARD`) gives no list: which was meant would otherwise depend on the order a map
happened to be read in, and one choice would have two lists.

**`source`** is what was found of the file, and is never written by hand. `seal` is one of the six states above.
`sealed_by` is the sealer when `seal` is `sealed` or `sealed_by_an_earlier_key`, and empty otherwise. What was found
of one file is not used for another, even one with the same contents and no seal.

**`utility_apps` binds a name to one utility app when the list is signed**, the way `credentials` binds a credential.
Without it, a permission "on Board" would mean whatever has that name when the list is applied. Every name the list
relies on is bound: those in permissions, and those a kind's own fields name, which is why each item carries its own.

- `"is": "item"`: a utility-app item of this same list, with that name. `identifier` is empty.
- `"is": "existing"`: a utility app the importing Identity Agent already has. `identifier` is its identifier there,
  and no item of the list has that name.

A choice in which a named utility app is neither, or both, gives no list.

**`credentials`**: each name once. `use` is the name of a credential the importing Identity Agent stores (a name, by
the rules of "Names"), or empty for one the owner will enter afterwards. A credential the file does not name cannot
be mapped.

`operation` is `create`, `change` or `remove`. **Version 1 performs creations only**: a list naming a change or a
removal is refused (`not_built`). A list that is not written as above is refused (`bad_approval`). A list in which a
permission the importing Identity Agent requires to be acknowledged is not among the item's `acknowledged` is refused
(`not_acknowledged`). The acknowledgement check is part of making a list: there is no way to the bytes that skips it.

**A renamed item.** Version 1 has no rename inside a chosen list: a chosen item's name is the name in the file. An
owner who wants another name edits the name in the file and hands the file in again. Its digest changes, and a seal
is then found to be for other contents, which is true.

**The bytes an approval signs** are the chosen list in the JSON Canonicalization Scheme, as above. They are the body
of a signed request in the form the Identity Agent already takes (ADR-042), which carries the body's Blake3-256
digest, so the signature covers every byte of the list. There is no new signing format. The Identity Agent builds
these bytes itself from the proposal and the choice it kept, and refuses an approval over any others.

Because the list holds each item's permissions, limits and grant end in full, and the digest of the rest, the bytes
change when anything about a chosen item changes.

**What is applied is what the bytes say.** Whatever applies an approval reads the list back from the approved bytes
and applies that, and nothing it was handed beside them.

**A device that is handed a list to approve** reads it by these same rules, and requires the bytes it was handed to
be exactly the list's canonical bytes, so that what it shows is what it signs. The list carries each item's other
members only as `rest`. Before it shows any of them, the device fetches them and checks each item's against that
item's `rest`; it shows nothing it has not checked.

## What an importer must refuse

- A file its reader refuses, for any reason in "What a reader does".
- To create an item that is blocked or not understood.
- To create anything on the strength of a seal.
- To honour any credential, signature, key log or token from the file's exporter. A file carries none, and every
  identity and grant is made new.
- To overwrite anything whose name is already in use.
- An approval over bytes other than the ones it builds itself, or used before.
- An approval whose list lacks an acknowledgement it requires.
- To bind a name to anything but what the signed list binds it to.
- To show text from a file to an AI agent, or have one summarise it, before the owner has approved.

## Starting values and rules proposed here

ADR-088 decides that there is a file, that it only proposes, what authorises an import, and that the format defines a
website, an AI agent and a utility app. Everything in this list was chosen while writing the reader so that there
would be something exact to test. **None of it has been decided.** Each is a proposal, and changing one before the
format is depended on changes vectors and nothing else.

**Sizes and counts.** 4 MiB a file; 500 items; 64 bytes a name (the one bound taken from the core, which holds an AI
agent's name to it where it lists AI agents to a contact); 64 bytes a kind; 128 bytes a member's name; 2048 bytes a
note; 64 KiB any string; 200 permissions an item; 32 arguments a limit, 256 values an argument, 256 bytes a value; 200
needed credentials; 300 bytes an origin; nesting 64 deep.

**Strictness.**
- An unknown member of the file refuses the whole file, and there is no minor version.
- Null is never a value, and refuses the file.
- A seal that is not written as one refuses the file.
- Whole numbers only.
- Times in UTC to the second, in one spelling.
- A website's origin without its scheme's own port.

**Secrets and identifiers.**
- The list of spellings that refuse a file, and that it is a closed list.
- That text is judged with every character that is not seen taken out, but a tab, a line feed, a carriage return, a
  no-break space and a narrow no-break space; and is a secret also when its Normalization Form KC is one.
- The `sk-` rule; which passwords in an address are placeholders, and that a placeholder is a closed form; what a
  salt is.
- The two rules of thumb that block an item, and their thresholds (64 hexadecimal characters; 40 characters with
  three groups of digits).
- What is shaped like an identifier (CESR codes E, D, B and 1AAI; 32 to 63 hexadecimal characters), that it blocks an
  item, and that it is only flagged in prose and in a limit's value.

**Names and text.**
- A name is in Normalization Form C, and one name is the folded form (Form KC, simple case folding, Form KC again,
  variation selectors, joiners and non-joiners out).
- No `@`, no space at either end, no two spaces together.
- A word does not mix Latin, Greek and Cyrillic letters; a word is a run of letters and marks; a script is the first
  word of a character's name.
- The joiner and non-joiner by rules A1, A2 and B of UAX #31; a variation selector after an emoji; the no-break
  spaces, the soft hyphen and a carriage return before a line feed in text.
- In text and not in names: a joiner between two emoji that are not ASCII, a joiner between a letter and a virama in
  either order, and a non-joiner after an Arabic letter.
- That the bidirectional marks, and the thin, figure and em spaces, are refused in text as in names.
- The Unicode version, 15.0.0, and that later characters are refused until the pin moves.
- The later of two items of one name is blocked; names are compared across all kinds.

**What a reader checks about a name already in use.** This document says what a reader checks inside one file.
ADR-088 decides that an import compares an imported name with the names already held by this same folded form, as
well as by the kind's own rule. Whether a revoked name stays taken is the importer's and is not defined here.

**What a reader says.** Places by position; that no member name from the file is said; that a kind says only what it
declared.

**Shapes.**
- A permission on a utility app as an object of the utility app's name and one word.
- That such a permission, and a field that names a utility app, resolve only to a utility-app item or an existing
  utility app.
- A kind of one word is the format's; any other carries a namespace and a dot.
- `extensions`, by namespace.
- Two websites of one origin are a duplicate.
- The flags, and their three names.

**The seal.**
- Its four members, and that it carries no key.
- The statement signature envelope with the signer on the asker line, and the three-line statement with the key event
  inside it.
- The six states, the order of the check, and that only a seal over these contents names a sealer.
- That an identity with more than one key does not seal in version 1.

**A statement made unasked** ([statement-signature.md](statement-signature.md)). The two refusals it asks of whatever
answers an Ask: a statement whose asker is the signer, and a statement under a reserved header.

**The chosen list.**
- Its members and their bounds (a proposal of 16 to 128 characters, a nonce of 22 to 128).
- That it names the importing Identity Agent, binds utility apps and credentials, and carries the item's place in the
  file.
- The one order it is built in, that a name mapped twice gives no list, and that there is no rename in it.
- The label on the `rest` digest.
