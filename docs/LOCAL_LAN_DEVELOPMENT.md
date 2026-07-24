# Local LAN Development

Run SweetWallet on the Windows PC so an iPhone or another computer on the same home WiFi can reach it.

## HTTP

```powershell
npm start
```

Open from the PC:

```text
http://localhost:8080/#/
```

Open from another device on the same LAN, replacing the IP if needed:

```text
http://192.168.1.16:8080/#/
```

## HTTPS For iOS Wallet Storage

iOS Safari requires a secure context for encrypted private-key storage. Use the HTTPS helper when testing save/unlock features from a LAN address.

```powershell
npm run cert:local
npm run dev:https
```

Then open:

```text
https://192.168.1.16:3443/#/
```

If iOS warns about the certificate, install and trust the local development certificate described in `docs/LOCAL_HTTPS.md`.

## Firewall

The Windows network profile should be Private, and Windows Firewall must allow inbound TCP `8080` for HTTP testing and `3443` for HTTPS testing from your home LAN.
