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
- Relay encrypted file keys to a recipient with a public Sugarchain SGF1 anchor
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

## File Key Relay

File Key Relay lets a sender share an encrypted file without directly sending its plaintext decryption key. The sender selects a file and the recipient's dedicated X25519 public encryption key. SweetWallet then:

1. Creates a fresh random 256-bit file key and encrypts the file locally with AES-256-GCM.
2. Uses ephemeral X25519 ECDH and HKDF-SHA256 to derive a one-time wrapping key.
3. Encrypts the file key into an authenticated capsule for the recipient.
4. With explicit confirmation, publishes a compact `SGF1` OP_RETURN anchor containing truncated public hashes. This spends only the displayed SUGAR network fee and returns change to the active wallet.
5. Generates a public `sugarfilekey://open` QR containing the encrypted key capsule, public cryptographic data, encrypted-file hash, and txid.

The QR code, encrypted file, and blockchain record may all be public. Only the matching recipient File Relay private encryption key can unwrap the file key. The plaintext file key is never placed on-chain, in the QR, in relay history, or on a server. Decrypted files remain local to the browser.

The dedicated File Relay key is separate from the SUGAR spending key and cannot spend SUGAR. Its private part is stored locally in browser IndexedDB. The setup screen can export a password-encrypted JSON backup. Losing the recipient encryption key and all backups means old capsules cannot be decrypted.

Sugarchain proves that an anchored relay record existed at or before its block timestamp and that the anchored manifest cannot be quietly changed. It does not prove the real-world identity of either party, that a file is safe, or that a recipient is the intended legal person. The optional QR-only mode retains the cryptographic key exchange but creates no Sugarchain timestamp proof.

## Starter Funding

New wallets can request optional starter funding of `0.025 SUGAR`. To enable it locally, set these in `.env`:

```powershell
SWEETWALLET_FUNDING_ADDRESS=sugar1q39n666w687nxm9x98tx5kgw2uvk780gtmd6yyu
SWEETWALLET_FUNDING_WIF=your-funding-wallet-wif
SWEETWALLET_STARTER_FUNDING_ENABLED=true
```

Only the new wallet address is sent to the local server. The newly generated private key stays in the browser view.
