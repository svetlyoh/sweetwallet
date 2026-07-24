# SweetWallet Security

SweetWallet is a client-side Sugarchain wallet. Private keys, WIF backups, PINs, and wallet passwords must stay on the user's device.

## Private Keys

- Never commit or log WIFs, private keys, passwords, PINs, local certificates, `.env` files, or production secrets.
- New wallets are session-only until the user explicitly saves the private key encrypted on the device.
- Encrypted wallet storage requires a secure browser context, such as `https://` or `localhost`.
- The local server must never receive a user's wallet private key.

## Starter Funding

Optional starter funding is handled by the local server only when `SWEETWALLET_STARTER_FUNDING_ENABLED=true` and a funding wallet is configured through local environment variables.

Only the new wallet address is sent to the local server. The generated SweetWallet private key stays in the browser.

## User Safety

SweetWallet must not fake balances, auto-send funds, or broadcast transactions without explicit user confirmation. Balances and transaction activity should come from live Sugarchain API or explorer data.
