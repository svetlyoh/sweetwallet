# Keylink Logic and Implementation

Status snapshot: August 15, 2026

Keylink is SweetWallet's encrypted secret ownership module. It creates one permanent public identifier and QR code for a secret, encrypts the secret in the browser, and moves the ability to decrypt it between Sugarchain wallet owners. Ownership approval is explicit and is anchored by a Sugarchain transaction containing a `KLT1` record.

The central product rule is:

> The QR stays. Ownership moves.

## Current Feature Set

- Create a secret of up to 300 characters.
- Add an optional local-only label of up to 80 characters.
- Encrypt the secret entirely in the browser.
- Generate a stable 128-bit random Secret ID and permanent `keylink://` URI.
- Display, copy, paste, and scan permanent Keylink identifiers.
- Maintain a wallet-specific X25519 encryption identity in IndexedDB.
- Export and restore a password-encrypted Keylink identity backup.
- Request ownership from the current owner.
- View pending incoming and outgoing ownership requests.
- Approve an ownership request through an in-app confirmation dialog.
- Deny an ownership request through an in-app confirmation dialog.
- Cancel an outgoing ownership request.
- Rewrap the secret's content key for a new owner without re-encrypting or exposing the plaintext secret.
- Sign registrations, requests, decisions, and transfers with the active Sugarchain wallet key.
- Broadcast an on-chain `KLT1` ownership anchor before the relay commits a transfer.
- Display blockchain transfer history with explorer links.
- Retry registrations, requests, and transfer verification after relay or propagation failures.
- Poll relay state every 30 seconds and update the hamburger-menu pending badge.
- Run on the Cloudflare Worker custom domain at `https://sweetwallet.net` and locally through Wrangler.

## System Architecture

| Layer | File | Responsibility |
| --- | --- | --- |
| Keylink UI | [`index.html`](index.html), [`keylink.css`](keylink.css) | Library, creation form, detail sheet, secret viewer, QR, identity tools, and approve/deny dialogs. |
| Client coordinator | [`keylink.js`](keylink.js) | UI state, wallet integration, local records, relay calls, ownership workflow, polling, and retries. |
| Browser cryptography | [`keylink-crypto.js`](keylink-crypto.js) | Secret encryption, X25519 identities, content-key envelopes, identity backups, stable signing input, and `KLT1` encoding. |
| Browser persistence | [`keylink-storage.js`](keylink-storage.js) | Safari-safe IndexedDB schema, migration, identity persistence, and wallet-scoped Keylink records. |
| Wallet bridge | [`sweetwallet.js`](sweetwallet.js) | Active wallet context, secp256k1 record signing, transaction construction, reauthentication, broadcast, explorer links, copy, toast, and QR scanner access. |
| Cloudflare Worker | [`cloudflare-worker.js`](cloudflare-worker.js) | HTTP API, CORS, Durable Object routing, SQLite state, signed-state validation, and on-chain transfer verification. |
| Shared Worker protocol | [`keylink-worker-protocol.mjs`](keylink-worker-protocol.mjs) | Strict record validation, Sugarchain address/public-key checks, signature verification, and server-side `KLT1` reconstruction. |
| Cloudflare configuration | [`wrangler.jsonc`](wrangler.jsonc) | Worker entry point, static assets, `KEYLINK_SECRETS` Durable Object binding, SQLite storage, custom domain, and observability. |
| Tests | [`test/keylink.test.js`](test/keylink.test.js), [`test/keylink-storage.test.js`](test/keylink-storage.test.js), [`test/keylink-worker.test.mjs`](test/keylink-worker.test.mjs) | Cryptography, storage migration, HTTP/CORS, request decisions, and atomic ownership transitions. |

## Core Identifiers and Records

### Secret ID and URI

- A Secret ID is 16 random bytes encoded as 32 lowercase hexadecimal characters.
- Its permanent URI is `keylink://secret/{secret_id}`.
- The QR contains only this public URI. It never contains the plaintext secret, content key, wallet private key, or Keylink private encryption key.
- The same URI remains valid through every ownership transfer.

### Protocol

All Keylink records use the protocol marker `KEYLINK1`.

The implemented signed record types are:

- `secret_registration`
- `ownership_request`
- `ownership_request_denial`
- `ownership_request_cancellation`
- `ownership_transfer`

Each signed record is serialized deterministically by sorting object keys. The wallet signs the SHA-256 digest of that stable JSON with its Sugarchain secp256k1 key. The `signature` and `ownership_txid` fields are excluded from the signing input.

## Cryptographic Design

### Secret encryption

When a secret is created:

1. The browser generates a random 32-byte content key.
2. The browser generates a random 12-byte nonce.
3. The plaintext is encrypted with AES-256-GCM.
4. Authenticated additional data binds the ciphertext to the protocol, record type, Secret ID, and cipher.
5. The plaintext is cleared from the form and is never submitted to the relay.
6. The raw content-key byte array is zeroed after use where the current JavaScript flow retains a mutable copy.

The relay receives the encrypted secret object, including its Secret ID, nonce, cipher name, and ciphertext. It does not receive the plaintext.

### Keylink encryption identity

Each Sugarchain wallet address gets a separate X25519 Keylink identity:

- The X25519 public key can be shared in ownership requests.
- Imported X25519 public keys remain extractable because envelope validation re-exports the public key to recompute its recipient hash.
- The X25519 private key cannot spend SUGAR.
- The private key is stored locally as serialized JWK data for browser compatibility.
- It is not sent to the Cloudflare relay.
- It can be exported in a `KEYLINK-IDENTITY-BACKUP1` file.

Identity backup encryption uses:

- PBKDF2-SHA256
- 600,000 iterations
- A random 16-byte salt
- AES-256-GCM with a random 12-byte nonce
- A minimum backup password length of 10 characters

The restored backup must match the active Sugarchain wallet owner when an owner ID is present.

### Owner envelope

The content key is wrapped separately from the encrypted secret. The owner envelope uses:

- X25519 ephemeral-static key agreement
- HKDF-SHA256
- AES-256-GCM
- A random ephemeral X25519 key pair
- A random 16-byte HKDF salt
- A random 12-byte AES-GCM nonce
- A SHA-256 hash of the recipient's X25519 public key
- Authenticated binding to Secret ID, owner address, state version, cipher, and recipient-key hash

Only the identity matching `recipient_key_hash` can unwrap the content key. A transfer creates a new owner envelope for the new owner's X25519 public key while leaving the encrypted secret ciphertext and permanent Secret ID unchanged.

## Browser Storage

Keylink uses IndexedDB database `sweetwallet_keylink_v1`, currently at version 3.

### Current stores

| Store | Key | Contents |
| --- | --- | --- |
| `identities_v3` | Sugarchain owner address | X25519 public key, private JWK string, and timestamps. |
| `secrets_v3` | `{owner_address}:{secret_id}` | Local label, relationship, encrypted payload/envelope when authorized, requests, transfers, pending retry data, and timestamps. |

Both stores use explicit out-of-line keys. This avoids the Safari/iOS failure where an inline IndexedDB `keyPath` could not be evaluated and produced: “evaluating the object store's key did not yield a value.”

The upgrade path reads older `identities`, `identities_v2`, `secrets`, and `secrets_v2` stores. Existing compatible records are normalized and copied into the version 3 stores. Legacy CryptoKey-based identities are loaded when possible and immediately converted to serialized JWK storage.

The optional human-readable label is local only. It is not included in a registration or sent to the relay.

## Cloudflare Relay and Durable Object

`KEYLINK_SECRETS` is a Cloudflare Durable Object namespace. Each Secret ID maps to one named `KeylinkSecret` instance, providing serialized updates for that secret.

Each Durable Object uses SQLite tables:

- `keylink_secret`: one registration and current ownership state.
- `keylink_requests`: ownership requests and their pending, denied, cancelled, approved, or superseded status.
- `keylink_transfers`: ordered ownership transfers keyed by state version.

The relay's public state contains encrypted content and public metadata. Anyone who knows a Secret ID may be able to resolve that public state; confidentiality depends on client-side encryption, not on the secrecy of the URI or CORS.

### API routes

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/api/keylink/secrets` | Validate, verify, and register a new encrypted Keylink. |
| `GET` | `/api/keylink/secrets/{secret_id}` | Resolve current encrypted state, requests, and transfer history. |
| `POST` | `/api/keylink/batch` | Resolve up to 100 locally known Secret IDs during polling. |
| `POST` | `/api/keylink/secrets/{secret_id}/requests` | Submit a signed ownership request. |
| `POST` | `/api/keylink/secrets/{secret_id}/requests/{request_id}/deny` | Submit a current-owner-signed denial. |
| `POST` | `/api/keylink/secrets/{secret_id}/requests/{request_id}/cancel` | Submit a requester-signed cancellation. |
| `POST` | `/api/keylink/secrets/{secret_id}/transfers` | Verify an on-chain ownership anchor and atomically commit the new owner. |

The HTTP layer limits request-body sizes, validates route IDs against signed body IDs, returns `no-store` responses, and maps validation/conflict/unavailable failures to appropriate public HTTP statuses. CORS is enabled for `https://sweetwallet.net`, `localhost`, and `127.0.0.1` origins.

## End-to-End Workflows

### 1. Create a Keylink

1. The user opens an unlocked Sugarchain wallet and chooses Keylink → Create Secret.
2. `ensureIdentity()` loads, migrates, or creates the wallet's X25519 identity.
3. The browser encrypts the secret with a new AES-256 content key.
4. The content key is wrapped to the creator's X25519 public key at state version 1.
5. The active Sugarchain wallet signs a `secret_registration` record.
6. The client saves the encrypted record locally before contacting the relay.
7. The relay verifies the signature and confirms the public key controls the supplied Sugarchain address.
8. The Durable Object stores the registration idempotently.
9. If the relay is unavailable, the signed registration stays queued locally and is retried later.

### 2. Resolve and request ownership

1. A second user scans or pastes the permanent Keylink URI.
2. The client fetches the public encrypted state from the relay.
3. The requester generates or loads their X25519 identity.
4. The requester signs an `ownership_request` containing their Sugarchain identity and X25519 public key.
5. The request is saved locally and submitted to the relay.
6. The Durable Object verifies the requester signature and current-owner version before accepting it.
7. Duplicate pending requests from the same requester return the existing public state.
8. A Keylink is limited to 100 pending requests.

### 3. View a secret

1. The client resolves the latest state from the relay.
2. It confirms the active Sugarchain address is the current owner.
3. It confirms the stored X25519 identity hash matches the owner envelope.
4. It unwraps the 32-byte content key.
5. It decrypts the secret with AES-256-GCM and shows it in a higher-layer in-app modal.
6. Closing the modal clears the module's plaintext string and displayed text.

The View Secret action shows an immediate `Opening…` state. Errors are displayed above all dialogs so a decryption, identity, or relay error cannot appear to do nothing.

### 4. Approve ownership

1. The owner clicks Approve on a pending request.
2. The client shows `Preparing…` while it validates the current state.
3. The current owner unwraps the existing content key locally.
4. The content key is rewrapped to the requester's X25519 public key for the next state version.
5. The owner signs an `ownership_transfer` record.
6. The client derives the deterministic 76-byte `KLT1` payload.
7. An in-app “Approve Ownership Request?” dialog shows the Secret ID, current owner, requester, estimated fee, and consequences.
8. The final `APPROVE & TRANSFER` action reauthenticates according to wallet security settings.
9. SweetWallet builds and signs a Sugarchain transaction containing the `KLT1` payload in an `OP_RETURN` output and pays the configured transaction fee.
10. After broadcast, the former owner's local record is marked transferred and its encrypted secret/envelope fields are removed.
11. The relay fetches the transaction from the Sugarchain API and independently confirms it contains the expected `KLT1` bytes.
12. The Durable Object atomically changes owner/version/envelope, approves the selected request, stores the txid, and supersedes other pending requests.
13. If the transaction has not propagated yet, the client keeps a pending transfer and retries relay verification.

Approval requires a spendable Sugarchain UTXO sufficient to pay the configured fee and create a positive change output. It never broadcasts automatically; the final confirmation button is required.

### 5. Deny ownership

1. The owner clicks Deny.
2. An in-app “Deny Ownership Request?” dialog identifies the Secret ID and requester.
3. `Keep Request` closes the dialog without changing state.
4. `DENY REQUEST` re-resolves the relay state and confirms the request is still pending and the wallet is still current owner.
5. The wallet signs an `ownership_request_denial` record.
6. The relay verifies the signature and changes the request status to `denied`.

Denial does not require a blockchain transaction or fee. It no longer uses a native browser confirmation dialog.

### 6. Cancel a request

The requester can cancel their own pending request. The wallet signs an `ownership_request_cancellation`, and the relay verifies the request belongs to that requester before marking it cancelled. The current cancellation UI still uses the browser confirmation prompt.

## KLT1 Ownership Anchor

The binary `KLT1` payload is exactly 76 bytes:

| Offset | Length | Value |
| --- | ---: | --- |
| 0 | 4 | ASCII `KLT1` |
| 4 | 16 | Raw Secret ID bytes |
| 20 | 20 | First 20 bytes of SHA-256 of the new owner's Sugarchain address |
| 40 | 4 | New state version, unsigned big-endian |
| 44 | 32 | SHA-256 of the complete signed ownership-transfer record |

The browser and Worker independently construct this payload. The Worker does not trust only the txid supplied by the browser; it retrieves the transaction and searches its decoded structure for the expected payload before committing ownership.

## State Synchronization and Recovery

- Keylink polls every 30 seconds while the panel is active.
- Batch polling supports up to 100 Secret IDs per request.
- The local record is written before a relay mutation so intermittent network failure does not discard work.
- `pending_registration`, `pending_request`, and `pending_transfer` are retried automatically.
- A locally broadcast transfer is protected from being overwritten by an older relay state while transaction propagation is pending.
- When relay state says the current wallet is no longer owner, the client changes the relationship to `transferred` and removes locally stored encrypted secret/envelope fields.
- Closing or locking the wallet clears the in-memory Keylink identity pair, plaintext secret, approval/denial state, polling timer, and sensitive modals.

## Security Properties

- Sugarchain wallet private keys never leave the wallet client.
- The Keylink X25519 private key never goes to the relay.
- Plaintext secrets are encrypted before relay submission.
- Optional labels remain on the local device.
- Every state-changing relay record is signed by the relevant Sugarchain wallet.
- The relay verifies that the signing public key derives the claimed Bech32, nested SegWit, or legacy Sugarchain address.
- AES-GCM authenticated data binds ciphertexts and envelopes to their semantic context.
- Ownership transfers use strictly increasing state versions.
- The Durable Object serializes state changes per Secret ID and rejects stale ownership.
- Registration and transfer commits are idempotent for exact repeats.
- The final approval transaction always requires explicit confirmation and wallet reauthentication when configured.

Important limitations:

- Possession of a Keylink QR is not authorization and should not be treated as proof of ownership.
- Secret IDs and encrypted relay state are public identifiers/data; do not put plaintext secrets in labels or request metadata.
- Losing the current X25519 identity without a backup can make the encrypted secret unrecoverable even when the same Sugarchain wallet key is available.
- The relay currently has duplicate-request and pending-count controls, but no separate CAPTCHA, account system, or per-IP rate limiter for Keylink requests.
- A real ownership approval depends on Sugarchain API availability, transaction broadcast, and transaction propagation.

## UI Behavior

- Keylink is available from the SweetWallet hamburger menu.
- The module uses the green Sugarchain accent on a dedicated dark-mode surface.
- Library filters include All, Owned, Created, Obtained, Pending, and Transferred.
- Sort modes include recent activity, creation time, ownership, pending state, and transfer state.
- The hamburger-menu badge shows pending incoming requests.
- Action dialogs use a higher stacking layer than the detail sheet.
- Toasts use a higher stacking layer than all modals, so action errors remain visible.
- View and Approve buttons show busy text while cryptographic and relay preparation runs.
- Approve and Deny both use consistent in-app confirmation dialogs.
- Buttons and sheets remain touch-friendly for mobile Safari while also supporting desktop Edge.

## Verification Completed So Far

Automated coverage currently verifies:

- Permanent Secret ID and URI format.
- AES secret encryption and X25519 content-key movement between owners.
- Former-owner decryption rejection after envelope rewrap.
- X25519 private identity JSON serialization and restoration.
- Imported X25519 public-key extractability and byte-identical re-export.
- Viewing an existing secret with a reloaded public/private identity pair.
- Preparing content-key rewrapping from a reloaded owner identity to a buyer identity.
- 300-character secret limit.
- Deterministic browser/Worker `KLT1` parity and exact 76-byte encoding.
- Safari-safe IndexedDB v3 migration and explicit keys.
- Rejection of records missing local storage keys.
- Durable Object idempotent registration.
- HTTP registration, resolution, and localhost CORS.
- Signed ownership requests and current-owner denials.
- Atomic transfer commit, approved request state, and repeated-transfer idempotency.
- Rejection of stale ownership transitions.

The latest local browser verification used two isolated browser origins against one local Wrangler Worker/Durable Object. It confirmed:

- Secret creation.
- Cross-user ownership request.
- Owner View Secret while the request was pending.
- Approve confirmation preparation and display without broadcasting.
- Deny confirmation with no native browser dialog.
- Successful signed denial and relay-state refresh.
- No browser console errors during the tested flow.

No real ownership transaction was broadcast during that browser test.

## Development Commands

```sh
npm test
npm run test:worker
npm run test:all
npx wrangler deploy --dry-run
npm run preview
```

Local static development through `npm run dev` serves the wallet at `http://localhost:8080/#/`. In that mode, Keylink relay requests target `https://sweetwallet.net`. `npm run preview` runs the complete Cloudflare Worker locally, including the Durable Object and static assets.

## Current Deployment

- GitHub repository: `svetlyoh/sweetwallet`
- Active development branch: `codex/smooth-wallet-design`
- Cloudflare Worker name: `sweetwallet`
- Custom domain: `https://sweetwallet.net`
- Durable Object binding: `KEYLINK_SECRETS`
- Durable Object class: `KeylinkSecret`
- Durable Object storage: SQLite
