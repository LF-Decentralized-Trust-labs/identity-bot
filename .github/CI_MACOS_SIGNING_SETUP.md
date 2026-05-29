# macOS signing secrets for GitHub Actions (TEMPORARY SETUP DOC)

> **Temporary.** Delete this file once the secrets below are configured in the
> repo. It exists only to walk Rob through obtaining/regenerating the Apple
> credentials the `Desktop — macOS Release` workflow needs. It contains **no
> secret values** — only instructions.

The macOS desktop build signs the `.app` with a **Developer ID Application**
certificate and notarizes it with an **App Store Connect API key**. (This is the
*distribute-outside-the-App-Store* path — it does **not** use App Store
provisioning profiles or fastlane `match`.)

Until these secrets exist, the workflow still runs and produces an **unsigned**
DMG, so Linux/Windows/macOS builds can all go green first.

## The five repo secrets

Add these under **GitHub → repo Settings → Secrets and variables → Actions → New repository secret**:

| Secret name | What it is |
|---|---|
| `CM_CERTIFICATE` | base64 of the Developer ID Application `.p12` (cert + private key) |
| `CM_CERTIFICATE_PASSWORD` | the password protecting that `.p12` |
| `APP_STORE_CONNECT_PRIVATE_KEY` | the **contents** of the App Store Connect API key `.p8` file (used by `notarytool`) |
| `APP_STORE_CONNECT_KEY_IDENTIFIER` | the API key's Key ID (10 chars, e.g. `2X9R4HXF34`) |
| `APP_STORE_CONNECT_ISSUER_ID` | the Issuer ID (a UUID from App Store Connect → Users and Access → Integrations) |

> The names match the Codemagic env-group names on purpose, so the build logic
> is identical across both CI systems.

## Can I reuse the Codemagic ones?

**Short version:** make a **new App Store Connect API key** for Actions; **reuse
the same `.p12`** if you still have the file, otherwise re-export or regenerate.

### `APP_STORE_CONNECT_PRIVATE_KEY` (the `.p8`) — make a NEW one (recommended)

Apple lets you download a `.p8` **only once**, at creation. If it only ever went
into Codemagic, you can't get it back. You **can** have several active keys at
once and they don't interfere, so the clean move is a dedicated key for Actions —
Codemagic's existing key keeps working, and you can revoke either independently.

1. App Store Connect → **Users and Access → Integrations → App Store Connect API**.
2. Create a key with the **Developer** role (sufficient for notarization).
3. **Download the `.p8` now** (only chance) and note the **Key ID** and **Issuer ID**.
4. Set the secrets:
   - `APP_STORE_CONNECT_PRIVATE_KEY` = the entire contents of the `.p8` file
     (including the `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----` lines).
   - `APP_STORE_CONNECT_KEY_IDENTIFIER` = the Key ID.
   - `APP_STORE_CONNECT_ISSUER_ID` = the Issuer ID.

### `CM_CERTIFICATE` (the `.p12`) — reuse if you have it

A Developer ID Application cert is just a cert + private key in a file; the same
`.p12` works in unlimited places at once, so reusing it does **not** break
Codemagic. Three ways to get it:

- **You still have the `.p12`** → use it directly (skip to "Encode" below).
- **Re-export from the Mac that created it:** open **Keychain Access**, find
  *"Developer ID Application: <your name/org> (TEAMID)"*, right-click → **Export**,
  save as `.p12`, set a password (this becomes `CM_CERTIFICATE_PASSWORD`).
- **Mint a fresh one** (if the private key is truly lost): Apple Developer →
  Certificates → **+** → **Developer ID Application** → follow the CSR flow on a
  Mac, then export the resulting cert + key as `.p12` from Keychain Access. (Apple
  allows a small number of these per account.)

**Encode it for the secret** (base64, single line):

```bash
# macOS / Linux
base64 -i developer_id.p12 | tr -d '\n' | pbcopy   # macOS: now in clipboard
base64 -w0 developer_id.p12                          # Linux: prints to stdout
```

Paste the result into `CM_CERTIFICATE`, and put the `.p12` password into
`CM_CERTIFICATE_PASSWORD`.

## After adding the secrets

Re-run the **Desktop — macOS Release** workflow (Actions tab → Run workflow). The
"Detect signing secrets" step will see `CM_CERTIFICATE`, run sign + notarize, and
the DMG will be signed + stapled. Then this doc can be deleted.
