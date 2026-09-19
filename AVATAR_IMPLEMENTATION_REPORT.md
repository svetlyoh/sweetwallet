# Avatar Implementation Report

## Scope

This report covers the SweetWallet work delivered after `8906343` (`Add browser-local shared avatar picker`) through `80178f3` (`Refine welcome screens and new wallet guidance`). The avatar catalog and interaction model were based on the [KeyLink avatar library](https://github.com/svetlyoh/keylink), then adapted for SweetWallet without making an avatar part of wallet authentication.

## Delivered avatar system

- Added a versioned catalog of 128 named PNG avatars in `avatars/`, with a manifest at `avatars/avatar-manifest.json`.
- Added `noverel-avatar.js`, a small browser-side catalog manager that:
  - validates catalog entries and safe avatar IDs before use;
  - searches by display name, ID, and keywords;
  - supplies six non-repeating suggestions and an optional random pick using `crypto.getRandomValues`;
  - loads images from the local avatar catalog; and
  - falls back to an icon if an image cannot load.
- Stored the selection in the browser's `localStorage` under `noverel_avatar_v1` as harmless metadata only: schema version, avatar ID, display name, catalog version, update time, and source. No wallet address, public key, private key, PIN, password, image binary, or image URL is written to this record.
- Migrates a valid older KeyLink selection from `keylink_security_avatar_v1` into the new profile format after catalog validation.

## User experience

- After a user opens or creates a wallet, an optional prompt offers an avatar if none is selected. It clearly says that the avatar is a local browser picture and never replaces a PIN or password.
- The picker provides search, six suggestions, browse-all, random selection, selected-state feedback, and a detail/change view.
- Entry points are available from the hamburger menu and Settings. When unlocked, the selected avatar is also available in the header as a quick detail control.
- The selected avatar appears on both the returning-user login screen and the locked-wallet unlock screen. It is intentionally hidden from the header on those screens, so the login/lock area remains the recognition surface.
- Landscape artwork is displayed with `object-fit: contain` in a taller rounded preview. This preserves the full image rather than cropping animal artwork.
- Both login and locked-unlock headings now use the restored `WELCOME BACK` size, with the taller avatar preview taking the recovered space.

## Browser-sharing scope

The system is browser-local and intentionally has no Noverel service, account, identity record, analytics, or KYC connection. It can be reused by apps that serve the same avatar catalog and can read the same browser storage origin.

Browser `localStorage` is origin-scoped. Therefore, apps on different domains or subdomains cannot read the same stored selection solely through this implementation. They can present the same 128-avatar catalog, but true cross-origin device-wide sharing would require a separately approved mechanism, such as a browser extension, user-controlled export/import, or a privacy-reviewed relay. No such mechanism was added.

## Login-flow repair

- Removed the second locked-wallet authentication card and its independent PIN/password event flow. SweetWallet now uses `#loginScreen` as the sole access surface for cold start, saved-wallet unlock, auto-lock return, and Lock Wallet Now.
- Added `sweetwallet-access.js` as the shared, testable access-state controller. `closed` and `locked` show the access screen; `session`, `saved`, and `watch` show the wallet dashboard.
- A locked wallet retains only public wallet details for balance refresh. It no longer presents the normal dashboard until the encrypted signing key is unlocked.
- Startup now chooses a usable credential mode: PIN for a saved vault with a PIN, password for a saved vault without one, and private key when no vault exists. Choosing an unavailable PIN or password shows a concise explanation instead of a fake credential prompt.
- The access avatar is shown only while the canonical login screen is presented. The header avatar is shown only for an unlocked session or saved wallet, never for closed, locked, or watch-only state.
- New-wallet safety guidance was moved into the authenticated wallet flow so it remains visible after the login screen correctly disappears.

## Related wallet refinements delivered in the same period

- Replaced login/lock wording with `WELCOME BACK`; removed the older login-screen avatar credit wording from those recognition screens.
- Added the shared footer: “Made with ♥ by Noverel,” linked to `https://noverel.net/`.
- Reworked the mobile PIN cells to match the compact KeyLink-style square-cell proportions and typing feedback.
- Changed the header balance to six decimal places and limited the header avatar to authenticated, unlocked wallet sessions.
- Fixed locked-wallet balance refreshes to use the saved public address and added API fallback paths:
  1. `/balance/{address}`
  2. `/esplora/address/{address}` computed chain and mempool totals
  3. `/unspent/{address}?amount=0` summed spendable outputs

  Balance values continue to come only from live backend data; no UI balance is synthesized.
- Replaced the large visible “New” control with a small, accessible plus icon in the login-card corner.
- Updated the new-wallet reminder to: “This new wallet is only available for now. To keep it on this device, save it with a password in the Security menu.” It is hidden for returning and locked users and is only revealed after a new wallet is created.

## Verification

- Added automated coverage for the 128-entry catalog, image-file existence, selection metadata, KeyLink legacy migration, catalog search, secure suggestion behavior, avatar UI entry points, contained artwork, the accessible new-wallet button, login reminder visibility, header visibility rules, locked balance refresh, and API fallback behavior.
- Latest verification completed successfully: 34 Node tests and 11 worker tests passed (45 total).

## Change history

| Commit | Summary |
| --- | --- |
| `8906343` | Added the browser-local avatar picker, catalog, and initial integration. |
| `43fd705` | Added shared footer, API fallback handling, and PIN UI refinements. |
| `d060309` | Updated post-unlock wording and suppressed raw automatic-load errors. |
| `580decb` | Refined header balance precision and avatar visibility. |
| `2fabf88` | Improved mobile login/lock layout and locked-state balance refresh. |
| `4fe6d82` | Contained avatar artwork and converted New to an icon control. |
| `80178f3` | Restored heading size, increased avatar preview height, and made new-wallet guidance conditional. |
