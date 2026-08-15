# SweetWallet

![SweetWallet preview](images/Sweetwallet_Pin.jpg)

SweetWallet is a mobile-first Sugarchain web wallet focused on wallet-only behavior.

## Features

- Create a Sugarchain wallet in the browser
- Open a wallet from a Sugarchain WIF private key
- Show live SUGAR balance from public APIs
- Display receive address and QR code
- Send SUGAR with client-side transaction signing and explicit confirmation
- Broadcast raw transaction hex
- View and copy address, public key, private key WIF, and SegWit redeem script
- Switch Sugarchain API backend
- Open address and transaction history in the Sugarchain explorer
- Create, request, transfer, and reveal encrypted Keylink secrets with Sugarchain-anchored ownership
- Logout without storing private key material
- Optional starter funding for newly created zero-balance wallets when the local server has a funding wallet configured

## Run

```powershell
npm start
```

Open:

`http://localhost:8080/#/`

## Cloudflare Deploy

This repo includes a pinned Wrangler v4 development dependency, `wrangler.jsonc`, and `.assetsignore` so Cloudflare uploads only the browser wallet assets, not `node_modules` or local development files. Use Node.js 22 or newer.

Run the Cloudflare-compatible local preview with:

```powershell
npm run preview
```

The preview stores Wrangler emulator state outside the repository-root asset directory so local state changes do not trigger an asset watch loop. Deploy with `npm run deploy`.

Starter funding on Cloudflare requires a Worker secret:

```powershell
npx wrangler secret put SWEETWALLET_FUNDING_WIF
```

The configured feeder wallet address is `sugar1q39n666w687nxm9x98tx5kgw2uvk780gtmd6yyu`.

## Safety

SweetWallet does not fake balances, does not auto-broadcast user spend transactions, and does not send private keys or WIFs to a server. Back up the WIF shown in the Keys panel before closing a newly created wallet.

## Keylink

Keylink is a full-screen encrypted-secret library with one permanent public identifier per secret:

`keylink://secret/<128-bit-secret-id>`

The QR contains only that identifier. Secret text is limited to 300 characters and encrypted locally with a random AES-256-GCM content key. The content key is wrapped to the current owner's dedicated X25519 identity with ephemeral X25519, HKDF-SHA256, and AES-GCM. Labels stay local and plaintext secrets are not persisted.

Ownership requests are signed by the requester's active Sugarchain key and coordinated off-chain by the Cloudflare relay. Approval rewraps the same content key to the requester, signs an ownership transition, and—only after explicit wallet confirmation—broadcasts an exact 76-byte binary `KLT1` OP_RETURN. The normal SweetWallet UTXO selection, fee, reauthentication, signing, broadcast, and change-return rules apply. No secret text or decryption key is placed on-chain.

The Cloudflare Worker uses one strongly consistent, SQLite-backed Durable Object per Secret ID. It stores only signed public metadata, encrypted secret material, the current owner envelope, requests, and transfer history. Before committing a transfer, the Worker verifies the Sugarchain transaction contains the expected `KLT1` record. The relay coordinates and indexes the signed chain state; it never receives wallet private keys, X25519 private keys, or plaintext secrets.

After Sugarchain accepts a transfer, the prior owner's local envelope and encrypted-secret copy are removed and Keylink no longer offers that identity a View Secret action. This controls future Keylink-mediated access; it cannot make a prior owner forget plaintext they already viewed.

The core rule is: **The QR identifies the secret. Sugarchain identifies the current owner. The current owner's cryptographic identity determines whether Keylink will reveal the secret.**

**The QR stays. Ownership moves.**

## Starter Funding

New wallets can request optional starter funding of `0.025 SUGAR`. To enable it locally, set these in `.env`:

```powershell
SWEETWALLET_FUNDING_ADDRESS=sugar1q39n666w687nxm9x98tx5kgw2uvk780gtmd6yyu
SWEETWALLET_FUNDING_WIF=your-funding-wallet-wif
SWEETWALLET_STARTER_FUNDING_ENABLED=true
```

Only the new wallet address is sent to the local server. The newly generated private key stays in the browser view.
