const os = require('os');
const fs = require('fs');
const path = require('path');

function loadEnvLocal() {
	const envPath = path.resolve(__dirname, '..', '.env.local');
	if (!fs.existsSync(envPath)) {
		return;
	}
	const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith('#')) {
			continue;
		}
		const separator = trimmed.indexOf('=');
		if (separator <= 0) {
			continue;
		}
		const key = trimmed.slice(0, separator).trim();
		let value = trimmed.slice(separator + 1).trim();
		if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
			value = value.slice(1, -1);
		}
		if (key && process.env[key] === undefined) {
			process.env[key] = value;
		}
	}
}

function activeLanIp() {
	const interfaces = os.networkInterfaces();
	for (const addresses of Object.values(interfaces)) {
		for (const address of addresses || []) {
			if (address.family === 'IPv4' && !address.internal) {
				return address.address;
			}
		}
	}
	return '192.168.1.50';
}

loadEnvLocal();
const lanIp = process.env.LOCAL_LAN_IP || activeLanIp();

console.log('');
console.log('SweetWallet local HTTPS certificate setup');
console.log('');
console.log('1. Install mkcert, if needed:');
console.log('   choco install mkcert');
console.log('   # or');
console.log('   scoop bucket add extras');
console.log('   scoop install mkcert');
console.log('');
console.log('2. Install the local mkcert certificate authority:');
console.log('   mkcert -install');
console.log('');
console.log('3. Generate this project certificate:');
console.log('   mkdir certs');
console.log(`   mkcert -cert-file certs/local-cert.pem -key-file certs/local-key.pem localhost 127.0.0.1 ::1 ${lanIp}`);
console.log('');
console.log('4. Start HTTPS:');
console.log('   npm run dev:https');
console.log('');
console.log('Open locally:');
console.log('   https://localhost:3443/#/');
console.log('');
console.log('Open from LAN:');
console.log(`   https://${lanIp}:3443/#/`);
console.log('');
console.log('Only transfer the public mkcert rootCA.pem to phones. Never transfer rootCA-key.pem.');
