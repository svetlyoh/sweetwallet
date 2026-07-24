# Local HTTPS For SweetWallet

SweetWallet can run locally over HTTPS for iPhone, Android, and LAN testing.
This is required for browser features such as Web Crypto encrypted private-key storage and WebAuthn security-key approval.

The fixed HTTPS development port is:

```text
3443
```

Use:

```text
https://localhost:3443/#/
https://127.0.0.1:3443/#/
https://<PC-LAN-IP>:3443/#/
```

Do not use these certificates for production.

## 1. Install mkcert On Windows

Using Chocolatey:

```powershell
choco install mkcert
```

Or using Scoop:

```powershell
scoop bucket add extras
scoop install mkcert
```

Install the local certificate authority:

```powershell
mkcert -install
```

This is an explicit trust step. SweetWallet scripts do not install a root certificate authority automatically.

## 2. Find The PC LAN IP

Run:

```powershell
ipconfig
```

Find the active adapter's IPv4 address, for example:

```text
192.168.1.50
```

You can also let the launch script detect it, but the certificate must include the LAN IP as a Subject Alternative Name.

## 3. Create `.env.local`

Copy:

```powershell
Copy-Item .env.local.example .env.local
```

Edit `.env.local`:

```dotenv
HTTPS_PORT=3443
LOCAL_LAN_IP=192.168.1.50
HTTPS_CERT_PATH=certs/local-cert.pem
HTTPS_KEY_PATH=certs/local-key.pem
```

Replace `192.168.1.50` with your PC's actual LAN IP.

`.env.local` is ignored by Git.

## 4. Generate The Project Certificate

Create the certificate folder:

```powershell
mkdir certs
```

Generate a certificate for localhost and the LAN IP:

```powershell
mkcert `
  -cert-file certs/local-cert.pem `
  -key-file certs/local-key.pem `
  localhost 127.0.0.1 ::1 192.168.1.50
```

Replace `192.168.1.50` with the current PC LAN IP.

If the PC LAN IP changes, regenerate the certificate with the new IP. A certificate created only for `localhost` will not validate on an iPhone opened through `https://<PC-LAN-IP>:3443`.

## 5. Launch HTTPS

Recommended:

```powershell
.\scripts\start-https.ps1
```

Or:

```powershell
npm run dev:https
```

The server binds to:

```text
0.0.0.0
```

That allows other devices on the same LAN to connect.

Expected URLs:

```text
https://localhost:3443/#/
https://<PC-LAN-IP>:3443/#/
```

If the certificate files are missing, the server fails clearly and does not fall back to HTTP.

## 6. Windows Firewall

Windows Firewall may block incoming LAN connections.

In an administrator PowerShell terminal, allow the local HTTPS port on Private networks:

```powershell
New-NetFirewallRule `
  -DisplayName "Local Project HTTPS 3443" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 3443 `
  -Action Allow `
  -Profile Private
```

Remove the rule:

```powershell
Remove-NetFirewallRule -DisplayName "Local Project HTTPS 3443"
```

Do not expose this development server to the public internet.

## 7. Trust The Certificate On A Phone

Phones must trust the mkcert local root CA before `https://<PC-LAN-IP>:3443` opens without warnings.

Find the mkcert CA folder:

```powershell
mkcert -CAROOT
```

Only transfer the public root certificate to the phone. It is usually named:

```text
rootCA.pem
```

Never transfer:

```text
rootCA-key.pem
```

That file is the private key for your local certificate authority.

On iPhone, install the public root certificate profile, then enable full trust in iOS certificate trust settings. After trust is configured, open:

```text
https://<PC-LAN-IP>:3443/#/
```

## 8. Optional Stable LAN Hostname

For WebAuthn and YubiKey testing, a stable hostname is better than a changing IP because credentials are scoped to the relying-party identity.

Example hostname:

```text
mobilewallet.test
```

Generate a certificate that includes it:

```powershell
mkcert `
  -cert-file certs/local-cert.pem `
  -key-file certs/local-key.pem `
  localhost 127.0.0.1 ::1 mobilewallet.test 192.168.1.50
```

Add local DNS or hosts entries so devices resolve:

```text
192.168.1.50 mobilewallet.test
```

Then open:

```text
https://mobilewallet.test:3443/#/
```

## 9. Troubleshooting

If the iPhone still shows a certificate warning:

- Confirm the certificate includes the LAN IP you are using.
- Confirm the public mkcert root CA is installed and trusted on the phone.
- Regenerate the certificate after your PC LAN IP changes.
- Confirm the phone and PC are on the same Private LAN.
- Confirm Windows Firewall allows TCP port `3443` on the Private profile.

If SweetWallet says Web Crypto is unavailable:

- Confirm the page URL starts with `https://`.
- Do not use `http://192.168.x.x:8080` for encrypted private-key storage.
- Use `https://<PC-LAN-IP>:3443/#/`.

If the server fails to start:

- Check `HTTPS_CERT_PATH` and `HTTPS_KEY_PATH` in `.env.local`.
- Confirm both files exist.
- Run `npm run cert:local` to print the mkcert commands.

Never set `NODE_TLS_REJECT_UNAUTHORIZED=0`, disable browser security, or use these local certificates in production.
