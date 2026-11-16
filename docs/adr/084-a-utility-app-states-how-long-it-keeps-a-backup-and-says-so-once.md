# ADR-084: A Utility App States How Long It Keeps a Backup, and That One Number Is What a Person Is Told

**Status:** Proposed (2026-11-15)
**Date:** 2026-11-15
**Deciders:** to be decided; the manifest field is public contract once this ships
**Amends:** ADR-012 Amendment 5 (the `backup` row of a utility app's manifest)

---

## Context

A utility app that keeps something about a person tells the person it can delete it. A delete removes it from the utility app's store at once, but a backup taken before the delete still holds it until the backup is removed. What the person is told must be true: how long that is has to be a number somebody declared, and the same number the runner that removes backups acts on, not a sentence written next to a different setting.

## Decision

1. The `backup` row gains **`keep_days`**: how many whole days a backup is kept before it is removed, 1 to 3650. It is allowed only when something is backed up (`what` is not empty), as `every_hours` is.
2. **It is optional.** A utility app that backs up and leaves it out states no limit; anything that tells a person how long a backup is kept says so ("not stated") and does not invent a number. Optional keeps every manifest already written valid.
3. **One value is read by both.** What a utility app tells a person about retention is read from `keep_days`, and the runner that prunes reads the same field. A utility app that declares a backup it does not run, or a retention it does not enforce, is a fault in the runner, not a different wording.

## Consequences

- `appmanifest.Backup` gains `KeepDays`; `Validate` refuses 0, more than 3650, and a `keep_days` with nothing backed up; the schema and `contracts/check_app_manifest_vectors.py` say the same; the vector file has one accepted and three refused examples.
