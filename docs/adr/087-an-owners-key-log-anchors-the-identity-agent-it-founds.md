# ADR-087: An Owner's Key Log Anchors the Identity Agent It Founds

**Status:** Accepted (2026-11-20)
**Date:** 2026-11-19
**Deciders:** Rob Andersen
**Amends:** ADR-032 (an identity can name who owns it, from its first event): what "owned" means to a verifier; ADR-036 (a computer you pair with does not publish who you are): one sentence of "What this costs" and one of decision 4; ADR-038 (who claims a machine is not who owns what it founds): which identity anchors, and that the owner's proof is kept. Each is named in "What this amends".
**Builds on:** ADR-031 (who witnesses what), ADR-032, ADR-034 (an instance is told who may claim it), ADR-036, ADR-038, ADR-061 (every key event is signed before it is added), ADR-062 (an address is believed only when its owner signed it), ADR-070 (witness classes and valid receipts), ADR-075 (a contact is refused on proof of duplicity)

---

## Context

An Identity Agent that runs on a machine founds its own root identity and names a pairwise owner identity in its inception event (ADR-036, ADR-038). The name is an owner seal: an event seal in an establishment event (ADR-032).

That seal points one way. The machine names its owner. Nothing shows the owner agreed.

Anybody can therefore found a look-alike: an Identity Agent of their own whose inception names somebody else's owner identity. The owner identifier is public, because the real machine's inception publishes it. A look-alike's key log verifies, and it names the right owner.

A device that still holds its own record of the machines it founded is not fooled, because it compares against the record. A device that has lost that record has only the logs to go on, and from the logs the real machine and the look-alike are the same.

What a look-alike gains if a device treats the owner seal as proof:

- It can be chosen as the place the owner's backups are sent, or as the default target of the owner's signed requests.
- A grant issued to it carries the owner's genuine signature. A party that checks that grant later, offline, accepts it.

ADR-036 removed KERI delegation from pairing, for good reasons, and recorded the price: "Nobody outside can verify who owns the computer." This record buys that back without bringing delegation back.

**Threat boundary.** The attacker can run any software, found any identity, hold any old copy of any public log, and reach the owner's device over the network. The machine being founded may itself be hostile. The attacker does not hold the owner identity's key. A compromised owner device is out of scope.

**What the proof says, and what it does not.** It says that the holder of an owner identity's key agreed to own one exact Identity Agent, at one exact event. It is a statement at a point in a log. Whether it still holds is a question about the latest state of both logs (decisions 3 and 4). It says nothing about which person holds that key.

## Decision

Below, **M** is the identifier of an Identity Agent on a machine, and **X** is a pairwise owner identity held by the owner's device.

1. **Owned is proved from two logs, never one.** M is owned by X when both of these hold:
   - an establishment event **E** of M's key log carries the owner seal naming X (ADR-032, unchanged);
   - X's own key log carries an **event seal** of E in the `a` field of an **interaction event**: `{"i": M, "s": <E's sequence number, lowercase hex>, "d": <E's SAID>}`.

   For the owner named at founding, E is M's inception, so the seal is `{"i": M, "s": "0", "d": M}`. The owner seal alone means **named, not owned**.

2. **This is KERI's event seal, and it is not delegation.** M stays its own root. X does not approve M's rotations, and M can change hands (decision 9). ADR-036's two ceremonies stand as written.
   - A delegation approval has the same seal shape, so the two are told apart by what is sealed, checked on the whole of M's log and not on one event: M's inception is an `icp`, no event of M names a delegator, and E carries an owner seal naming the identity whose log holds the anchor. A log that begins with a delegated inception can never be owned in this sense.
   - The anchor is written only in an interaction event of X, one anchor to an event. This is a rule of this record, not of KERI: an event seal in an establishment event of an identity is already read as that identity's owner seal (ADR-032), so an anchor there would be read the other way round.

3. **How a verifier checks it.** A verifier needs both logs as signed bytes. It does all of the following, and a seal that merely matches is not enough.
   1. M's log verifies in full as KERI requires: the identifier is the digest of the inception, each event follows the one before by sequence number and prior digest, each is signed to the threshold of the key state in force, and each rotation reveals the keys the previous establishment event committed to (ADR-061 section 2). M's log passes the test of decision 2.
   2. E is the establishment event in which X entered M's owner set, and X is in the owner set in force at **every** establishment event of M from E to the latest. The owner set in force at an event is the one named by the latest establishment event, at or before it, that carries owner seals: a rotation that carries none leaves the set as it was. An owner that left and came back is owned only from the event where it came back, and needs an anchor of that event.
   3. E is an event of the log just verified. Two establishment events of M at one place are duplicity (step 7), and no recovery replaces one.
   4. X's log verifies in full, the same way.
   5. An interaction event that still stands in X's log seals E exactly: identifier, sequence number and digest all equal. A recovery rotation of X that removes that interaction removes the anchor.
   6. That anchor is the first anchor in X's log, or names the same M as the first (decision 8). An anchor, for this count, is an event seal in an interaction event of X whose sealed event is an establishment event that carries an owner seal naming X.
   7. Neither log is proven duplicitous at any place, judged as ADR-075 judges any log.
   8. The anchoring event and E each carry valid witness receipts (ADR-070) to the threshold their own log names.

   Steps 1 to 7 passing is **anchored**. Step 8 passing as well, on logs the verifier took from the witnesses each log names and not only from the party being checked, is **confirmed**. A verifier reports which, and never reports "confirmed" without both.

4. **How fresh the logs must be.** An old copy of a log verifies for ever, so a proof built on old copies shows what was once true.
   - **Confirmed** needs each log's latest state as its own witnesses hold it, asked for by the verifier.
   - A copy of X's log handed over by the machine, or a copy of either log handed over by the party being checked, can prove **anchored** and no more. Only the holder of X's key can sign X's events, so such a copy cannot invent an anchor. It can hide a later event that removed one.
   - An owner identity or a machine that names no witnesses can be anchored and never confirmed. A verifier that kept an earlier copy judges any later copy against it (ADR-075). The owner's device says so when it anchors such a machine.
   - The machine keeps the owner log it verified at founding and serves it beside its own, so the proof can be found again after the owner's device loses its store. That copy is a starting point for the checks above and is not their end.

5. **An address is the machine only when it proves it holds M's key.** Two valid logs can be copied and served by anybody. Before an owner's device treats whatever answers at an address as M, that party signs a fresh challenge under M's key state in force (ADR-062).

6. **Founding is prepare, anchor, commit.** An honest machine never founds an identity that is not yet anchored.
   1. **Prepare.** The machine fixes its witnesses, builds its inception event (keys, witnesses, the owner seal naming X), signs it, and returns the exact bytes, the signature and M. It adds nothing to any log.
   2. **Check.** The owner's device verifies the prepared event in full, as a verifier later will:
      - the digest gives M, the sequence number is 0 and there is no prior event;
      - it is an `icp` and names no delegator;
      - the first key is the one the machine offered (and, on sealed hardware, the one its attestation covers), the next-key digest matches, and the signature is by that key;
      - the owner set is exactly X, with no other owner and no other seal;
      - the witnesses and their threshold are ones the device accepts;
      - X's log anchors nothing yet, or already seals exactly these bytes (a founding being resumed).
   3. **Anchor.** The device appends the interaction event of decision 1 to X's log, signs it, keeps it, and sends it to X's witnesses.
   4. **Commit.** The device presents X's log. The machine founds only if that log verifies and anchors the prepared bytes, and it commits those exact bytes.

   These are the promises of an honest device and an honest machine. A hostile machine holds its own keys and can publish the inception it prepared whenever it likes. What it cannot do is obtain an anchor for any event the device did not check in full (decision 7 covers what a kept anchor is worth).

7. **Both sides keep the founding, a retry changes nothing, and an anchored owner identity is never used for another machine.**
   - Each side writes down what it is about to do before it does it. The machine keeps the prepared bytes, where its founding keys are derived from, and the exchange they belong to. The device keeps the bytes it checked and the anchor it signed. Both survive a restart, and every step carries the exchange's identifier.
   - Prepare returns the same bytes when asked again. Anchor writes nothing when X's log already seals those bytes. Commit, asked again after it succeeded, answers with the founded identity. Only one writer extends X's log at a time.
   - **A lost answer is not a failed founding.** When the device does not hear the result of a commit, it asks the machine what became of the exchange and sends the commit again. It gives up only when the machine answers that the prepared founding expired, or when the person abandons the attempt.
   - A prepared founding that is never committed expires, and an honest machine destroys its keys.
   - **Once X has anchored, X belongs to that M for good**, whether or not the founding completed. If the device gives the attempt up, it records that X was given up and for which M, mints a fresh owner identity for the next attempt, and never again anchors or signs an owner request as X. It may still sign, as X, the claim a machine was told to expect from X. A machine that later publishes the event X anchored is, truthfully, a machine X agreed to own. It gains an owner that signs nothing.
   - Where the machine was already told which identity may claim it (ADR-034), that claim stays as it is, and the fresh identity is supplied as the separate founding owner of ADR-038.

8. **One owner identity owns one Identity Agent.**
   - A device never writes an anchor naming a second Identity Agent in an owner log that already names one. It may anchor later events of the same M (decision 9).
   - A verifier reads X's log in order. The first Identity Agent anchored there is the only one X can own. A later anchor that names a different one is reported as named, not owned.
   - Two different interaction events at one place in X's log are duplicity (decision 10).

9. **A later owner always anchors, and an anchor is made again when a recovery removes it.**
   - An owner that enters M's owner set by a rotation anchors that rotation in its own log, exactly as decision 1 states. A signature given in the ceremony that made the rotation is not a substitute. The ceremony that adds an owner includes this step, so no owner can be added that cannot anchor.
   - An owner carried over from the previous set does not anchor again. Its earlier anchor stands.
   - An owner is no longer an owner when a later establishment event of M leaves it out. Its old anchor stays in its log and means "agreed at that event".
   - Several owners each anchor in their own log.
   - **After a recovery rotation of X** that removes an anchoring interaction, the device anchors again in a new interaction event. Until then the machine is named, not owned, and the device offers the step. M's side needs no such rule: E is an establishment event, and a recovery replaces only interactions (ADR-075).

10. **Two events at one place in an owner's log are settled by KERI's duplicity rules, and nothing new.**
    - Before it appends, the device continues from its own kept copy of X's log, checked against the tip X's witnesses hold when they answer. With no kept copy it continues from the witnesses' copy. It never continues from a copy the machine supplied, and with neither its own copy nor an answer from the witnesses it does not anchor.
    - It reserves the place before it signs, and never signs a second digest at a reserved place (ADR-061 section 4).
    - Two validly signed interaction events at one place are proven duplicity under ADR-075. A verifier shown that proof treats no machine as owned by X.
    - **The way back does not depend on X's log.** The machine obeys the owner key sealed in it at founding. The device mints a fresh owner identity, and a rotation of M, asked for under the old key, puts the fresh identity in M's owner set and leaves X out. The fresh identity anchors that rotation. That request is the only thing the device signs as X once X's log is duplicitous, and X is not used again. The device picks M for it from its own record of M, kept from the founding or rebuilt by the check in "The way out" before the duplicity, and the party at the address proves it holds M's key (decision 5). A device that has lost that record as well founds the Identity Agent again.
    - Where an owner identity can rotate, KERI's recovery rotation followed by a new anchor (decision 9) is a second way back. This record does not rely on it.

11. **Which identity anchors.** The identity named in the owner seal anchors. Where a founding request names a separate founding owner (ADR-038), that identity anchors and the claiming identity does not. The machine checks the founding owner's proof and its anchor before it founds, in every case.

12. **Witness receipts are chased, not hoped for.** An event sent to witnesses that is not receipted is kept in a queue and sent again until it is, across restarts. A founding or an anchor made with no network is anchored at once and becomes confirmed when the queue drains.

13. **The kind of Identity Agent is stored when the owner identity is minted.** What X was minted to own (a person's paired machine, an organisation's Identity Agent, and so on) cannot be read from either log. It is recorded with X and its derivation index at mint time (ADR-036 decision 4), so a record rebuilt later does not have to guess it.

14. **A machine that is named but not anchored is not treated as owned.** An owner's device:
    - does not answer "this is my Identity Agent" for it, to a person or to software;
    - does not sign an owner request for it, except the one rotation request of decision 10;
    - does not choose it as a backup destination or a default target.

    No answer built on the owner seal alone is ever given. There is no allowance for an Identity Agent founded before this rule: it has no anchor and cannot get one, because nothing proves afterwards that the owner founded it. It is founded again (see "Alternatives rejected").

## The way out

A person must never be locked out of a machine they founded under this rule. The rule refuses on the owner's device only, the refusal says why, and each cause has an exit.

**What a refusal is.** When the proof fails or cannot be completed, the device refuses to sign and refuses to answer "owned". It says which of these it found: named but not anchored, duplicity, an anchor removed by a recovery, or a log that could not be checked. A refusal changes nothing on the device or the machine, and deletes nothing.

**The exits:**

- **The device lost its record of a machine, or lost its whole store.** Nothing has to be claimed again, because the proof is in the logs and not in the record. For the machine in front of it, the device reads X from the machine's owner seal and takes X's log from X's witnesses, or from the machine as a starting point. It then finds X among its own: it derives the keys of its owner identities from its seed, index by index up to a bound the implementation states, and looks for the key X's inception names. (The seed gives keys, not identifiers, because an identifier also depends on the witnesses chosen at minting.) With X found, it checks both logs as decisions 3 to 5 require. A machine that X's log anchors is owned, with no ceremony. The kind of Identity Agent, which no log carries (decision 13), is asked of the person.
- **A restored device has also lost the mark that an owner identity was given up** (decision 7). A machine such an identity anchored is one the device checked in full before it anchored, so finding it owned again is accepted.
- **A recovery removed the anchor.** The device anchors again (decision 9).
- **The owner log is duplicitous.** A fresh owner identity replaces X by a rotation of the machine (decision 10).
- **Witnesses cannot be reached.** The device's own kept copy of X's log is enough for the device's own decision, at the device's own risk, and confirmation follows when the queue drains.
- **A founding was interrupted.** It resumes (decision 7).
- **The machine was founded before this rule.** It is named and can never be anchored. It is founded again, and its data is moved first or stays behind (see "What existing deployments must do").

**No "sign anyway" switch exists.** It is the one button a look-alike needs the person to press.

## What ships together

Decisions 1 to 14 and the exits above ship as one release, with **the check a third party can run**: the credential check takes the owner's log, requires decision 3, says whether the result is anchored or confirmed, and reports a credential from a named-but-not-anchored issuer as exactly that.

**Later, and not decided here:** rotation of owner identities, and an owner's signed statement that it no longer claims a machine.

## What this amends

1. **ADR-036**, "What this costs": *"Nobody outside can verify who owns the computer."* A party that knows M can now verify that pairwise X agreed to own it. X still means nothing anywhere else, and the root identifier still appears in nothing a machine publishes.
2. **ADR-032**, "Consequences": *"Ownership is verifiable by anyone, from the log, without trusting the machine the identity runs on."* From the identity's own log a verifier learns who is **named**. Ownership needs the owner's log as well (decision 3).
3. **ADR-038**, decision 3. The owner's proof was a signature checked once and then discarded. It is now also an anchor that is kept. Decision 11 fixes which identity makes it. Its sentence that an owner named at inception "can never be replaced" is read with ADR-032: the owner set changes by a rotation, which decision 10 relies on.
4. **ADR-036**, decision 4, and the same statement in ADR-038, "What this costs": an owner identity whose index was lost "can never be re-derived". Its index can be found again by the search in "The way out", for an owner identity the device is shown.

## What existing deployments must do

- **An Identity Agent founded before this rule is founded again under it,** and its data is moved by its owner before the owner's device is updated. Nothing carries an old founding over.
- **An owner's device and a machine update together** before a machine can be founded: the device to anchor, the machine to prepare. On sealed hardware that is a new image whose measurement must be accepted before it can be used.
- **An implementation whose founding request names a separate founding owner** must have that identity anchor.
- **A verifier** must stop reading an owner seal as ownership.

## Consequences

- **The owner identity's witness learns which machine it owns.** The anchor is a plain event seal, so X's witness, and anybody who resolves X, reads M. Anybody who knows M could already read X. Nothing names the root. Several owners of one machine are joined to each other through M, as its owner set already joins them. This disclosure is accepted.
- An anchor cannot be withdrawn by itself. It stops counting when M leaves X out of its owner set, when a recovery removes it, or when X's log is proven duplicitous. An owner's own signed statement that it no longer claims a machine is later work.
- An owner's device must be able to extend an owner identity's log after a restart: hold the log, find the key from the stored derivation index, and serve one copy of the log, not a snapshot taken at minting.
- Founding gains a step and a durable record on both sides. `POST /api/pairing/complete` founds only on an anchored owner log, and a prepare route is added before it. `POST /api/machines/owner/sign` refuses an Identity Agent the owner identity's log does not anchor.
- The following are fixed by test vectors that an independent KERI implementation reads: the seal and the two-log check, a look-alike, a delegation approval offered as an anchor, an old copy of a log that hides a removal, an owner that left and came back, an anchor removed by a recovery rotation of the owner identity, a second machine anchored in one owner log, a duplicitous owner log, and every point at which a founding can be interrupted.

## Is this the permanent answer?

- **Not a stopgap.** The proof lives in key logs, survives key rotation, and is checked by anybody from signed bytes. Nothing is trusted because a device says so.
- **The protocol already had the parts.** Key logs, the owner seal, witnesses and receipts, and the duplicity proof of ADR-075.
- **Standard mechanisms.** A KERI event seal in an interaction event, witness receipts, first-seen and duplicity, and recovery rotation. No new seal shape and no new arbiter.
- **What it rests on.** "Confirmed" rests on the witnesses each log names, as every confirmed statement in KERI does. Finding a machine again after a device is restored rests on the device's seed, as everything the device signs does.

## Alternatives rejected

- **KERI delegation.** It names the delegator in the machine's own events, gives the owner's device a veto over the machine's rotations, and cannot change hands (ADR-036).
- **A tag or a new seal shape that marks an ownership anchor.** It would not be the KERI event seal, and standard tooling would not read it. What is sealed already tells the two apart (decision 2).
- **A blinded digest in place of the plain seal.** It would hide M from X's witness. It is not the KERI event seal either, and M's inception already publishes X.
- **Found, then anchor.** A device that stops in between leaves a founded, un-anchored machine for good.
- **Using an owner identity again after it anchored a founding that did not complete.** Nobody can prove afterwards that the first machine was never founded.
- **A signature from the ownership ceremony in place of a later owner's anchor.** It is not in the owner's log, so it cannot be found, ordered or checked for duplicity there.
- **Claiming again a machine founded before this rule.** Every way to do it either trusts the one-way owner seal for a while, which is the look-alike's path, or needs evidence a lost record cannot supply (a signed request the machine kept, sealed-hardware evidence, a person at its screen), each weaker than founding. No deployment depends on an old founding, so the rule starts clean.
- **A register of claimed machines kept by a service, or a count of watchers that agree.** KERI settles this by evidence, not by a vote or a third party's list.
