# keri — the Go KERI event layer

## Why this exists

One implementation, for every platform this product runs on.

There were two: a Python sidecar on computers and a Rust library on phones.
Nearly every serious defect found in this subsystem came from those two
disagreeing quietly — events stored in a form the reference implementation
refuses, identities founded unsigned, key commitments silently dropped. None of
them announced itself. Each was found by running the thing.

Go, because the Go core is already compiled into the mobile app. A phone cannot
spawn a helper process, so whatever runs there must be linked in, and this
already is.

## How it is built

Against fixed vectors, not against a reading of the specification.

A KERI identifier IS a digest of its own event. Two implementations agree byte
for byte or they do not interoperate at all — there is no partial credit, and no
amount of review substitutes for comparing the bytes.

`tests/vectors/keri_vectors_v1.json` holds what keripy actually produces, which
the KERI implementations table lists at 100% spec compliance. The file is
generated, never hand-written: an expectation somebody typed is a belief, and
only a captured one is a reference.

```
# regenerate the vectors from the reference implementation
python3 tests/vectors/generate_vectors.py > tests/vectors/keri_vectors_v1.json

# check the vectors still describe what keripy does
python3 tests/vectors/verify_vectors.py tests/vectors/keri_vectors_v1.json

# check THIS implementation against them
go test ./keri/ -run TestConformance -v
```

## Working on it

`Answer` in `answer.go` is the seam. Each event kind is one function; filling one
in moves a group of cases from "not implemented" to either agreement or a
visible disagreement, and nothing in between.

A missing answer returns `ErrNotImplemented` and is reported as a skip. A wrong
answer fails loudly with both byte strings. That distinction is deliberate:
unimplemented is progress not yet made, wrong is a claim that the rest of the
world is mistaken, and a suite that reported them the same way would hide the
second among the first.

The suite is expected to be incomplete while this is written. It is not expected
to be wrong.

## What it found on the first run

The first case implemented disagreed with keripy, because seals were being
carried through a Go map and Go marshals a map alphabetically — so `{"i","s","d"}`
came out as `{"d","i","s"}` and the identifier changed. That is the same defect
that had already made our stored events unreadable, appearing again somewhere
new, and it was caught by the first vector that ran.

That is what this is for.
