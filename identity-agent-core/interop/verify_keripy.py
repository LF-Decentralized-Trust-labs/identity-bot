"""Judge the logs identity-agent-core produces with keripy's own validator.

Cases come from server/key_events_keripy_judges_test.go (see its header): each
is a whole signed key log as one CESR stream, plus any witness receipts. Every
case is given to a fresh Kevery in a single parse, so keripy finds each message
boundary itself, then the escrows are drained (a witnessed event waits there
for its receipts). A case passes only if keripy ends at the log's last event.

    python3 -I interop/verify_keripy.py /tmp/cases.json     # needs keri==1.3.6

Each case is also judged once more with one character of its last signature
changed, and that copy must be refused, so a run shows the judge can say no.

Exit status is non-zero if keripy refuses anything, accepts a broken copy, or
runs a version other than the one this is meant for. Modelled on keri-go's interop/verify_interop.py
(judge_stream), which it does not copy: see interop/README.md.
"""

import base64
import importlib.metadata
import json
import sys
import tempfile

from keri.core import eventing, parsing, serdering
from keri.db import basing

KERIPY = "1.3.6"

# Every shape the test writes. A file missing one, from a filtered or failed
# run, is refused rather than judged on what is left.
EXPECTED = {
    "core/founding",
    "core/rotation",
    "core/interaction",
    "core/recovery-stored-log",
    "core/recovery-superseding",
    "core/move-to-a-new-phrase",
    "core/witnessed-founding",
}


def d(b64):
    return base64.b64decode(b64)


def judge(case):
    # A fresh database per case, so one log cannot lend another its state.
    with tempfile.TemporaryDirectory() as tmp, basing.openDB(name="x3", temp=True, headDirPath=tmp) as db:
        kvy = eventing.Kevery(db=db, lax=True, local=True)
        parsing.Parser(kvy=kvy).parse(ims=bytearray(d(case["message_b64"])))
        for extra in case.get("extra_b64") or []:
            parsing.Parser(kvy=kvy).parse(ims=bytearray(d(extra)))
        kvy.processEscrows()
        last = serdering.SerderKERI(raw=d(case["event_b64"]))
        kever = kvy.kevers.get(last.pre)
        if kever is None:
            return False, "nothing was established"
        if kever.serder.said != last.said:
            return False, f"keripy stopped at sn={kever.sn} {kever.serder.said}, the log ends at {last.said}"
        return True, f"sn={kever.sn}"


def tampered(case):
    """The same case with one character of its last signature changed."""
    stream = bytearray(d(case["message_b64"]))
    i = len(stream) - 5  # inside the last event's last signature
    stream[i] = ord("A") if stream[i] != ord("A") else ord("B")
    return dict(case, message_b64=base64.b64encode(bytes(stream)).decode())


def main(path):
    have = importlib.metadata.version("keri")
    if have != KERIPY:
        print(f"keripy {have} is installed, this judges against {KERIPY}")
        return 2
    with open(path) as f:
        cases = json.load(f)
    labels = {c["label"] for c in cases}
    if labels != EXPECTED or len(cases) != len(EXPECTED):
        print(f"the file does not hold the expected cases: missing {sorted(EXPECTED - labels)}, "
              f"unexpected {sorted(labels - EXPECTED)}, {len(cases)} cases")
        return 1
    refused = 0
    for case in cases:
        try:
            ok, detail = judge(case)
        except Exception as exc:  # noqa: BLE001 - report, never mask
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        print(f"  {'accepted' if ok else 'REFUSED '} {case['label']:34} {detail}")
        refused += not ok
        # A judge that accepts everything proves nothing: the same log with a
        # broken signature must be refused.
        try:
            still, _ = judge(tampered(case))
        except Exception:  # noqa: BLE001 - an exception is a refusal
            still = False
        if still:
            print(f"  ACCEPTED {case['label'] + ' with a broken signature':34} the judge cannot say no")
            refused += 1
    print(f"\nkeripy {have}: {len(cases) - refused} accepted, {refused} refused, out of {len(cases)}")
    return 1 if refused or not cases else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
