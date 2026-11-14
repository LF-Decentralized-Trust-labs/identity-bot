# Does keripy 1.3.6 accept the events this core produces?

keri-go checks its own library calls against keripy. This checks the events
the core produces when an app prepares, signs and commits them.

1. `server/key_events_keripy_judges_test.go` drives `/api/events/prepare` and
   `/api/events/commit` with app-side Ed25519 signatures for: a founding, a
   rotation, interactions, a recovery rotation superseding interactions (the
   stored log, and the replay a verifier that saw the superseded interactions
   would get), a move to a new phrase (two rotations), and a founding with two
   witnesses (receipted by the test playing the witnesses). Each event has the
   app's shape: two next-key digests (the next signing key and a post-quantum
   reserve) with a threshold of one, and the founding anchors a messaging
   keyset. The recovery rotation is committed by `commitRecoveryRotation`, what
   the recovery route calls once its session is found. It lives in `server`
   because the handlers and the test helpers are unexported there.
2. `verify_keripy.py` gives each signed log to keripy as one CESR stream.

```
python3 -m venv kv && kv/bin/pip install keri==1.3.6   # keri needs Python >= 3.12.6
IDENTITY_BOT_INTEROP_OUT=cases.json go test ./server -run 'TestKeripyJudges$'
kv/bin/python -I interop/verify_keripy.py cases.json
```

On Windows the venv's interpreter is `kv\Scripts\python`. The judge refuses a
file that lacks any of the shapes, and requires keripy to refuse a copy of each
log with one signature character changed.

The judge is a small version of keri-go's `interop/verify_interop.py`
(`judge_stream`). What could be shared: that judge, published by keri-go as a
module (`python -m keri_go_interop.judge cases.json`) installed from a pinned
keri-go tag, with the case format (label, message_b64, event_b64, extra_b64)
as its documented input, so both repos use one judge.

## The key state notice and the witness location

`make_key_state_notice_vectors.py` has keripy make a short key log (an
inception with two witnesses, a rotation that cuts one and adds another, an
interaction), state its key state, and have a witness sign the `/ksn/{witness}`
reply carrying it and its own `/loc/scheme` reply. The output is
`witnessproto/testdata/keripy_key_state_notice.json`, and
`witnessproto/key_state_notice_keripy_test.go` checks that witnessproto
believes both replies and makes the same record, notice and location byte for
byte, with the same signatures.

```
kv/bin/python -I interop/make_key_state_notice_vectors.py > witnessproto/testdata/keripy_key_state_notice.json
```
