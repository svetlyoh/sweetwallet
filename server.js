const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');

const rootDir = __dirname;
loadLocalEnv('.env');
loadLocalEnv('.env.local');
const port = Number(process.env.PORT || 8080);
const httpsPort = Number(process.env.HTTPS_PORT || 3443);
const httpsEnabled = process.argv.includes('--https') || String(process.env.SWEETWALLET_HTTPS || '').toLowerCase() === 'true';
const host = httpsEnabled ? '0.0.0.0' : (process.env.HOST || '0.0.0.0');
const httpsCertPath = path.resolve(rootDir, process.env.HTTPS_CERT_PATH || 'certs/local-cert.pem');
const httpsKeyPath = path.resolve(rootDir, process.env.HTTPS_KEY_PATH || 'certs/local-key.pem');
const sugarDecimals = 8;
const faucetAmountSatoshis = 2500000;
const faucetMinimumBalanceSatoshis = 1000000;
const faucetFeeSatoshis = 1000;
const faucetExpectedAddress = process.env.SWEETWALLET_FUNDING_ADDRESS || 'sugar1q39n666w687nxm9x98tx5kgw2uvk780gtmd6yyu';
const sugarApiBase = (process.env.SUGAR_API_URL || 'https://api.sugar.wtf').replace(/\/+$/, '');
const faucetEnabled = String(process.env.SWEETWALLET_STARTER_FUNDING_ENABLED || 'true').toLowerCase() !== 'false';
const faucetAttempts = new Map();
let bundledBitcoin = null;

const sugarNetwork = {
	messagePrefix: '\x19Sugarchain Signed Message:\n',
	bip32: {
		public: 0x0488b21e,
		private: 0x0488ade4
	},
	bech32: 'sugar',
	pubKeyHash: 0x3F,
	scriptHash: 0x7D,
	wif: 0x80
};

const mimeTypes = {
	'.html': 'text/html; charset=utf-8',
	'.js': 'application/javascript; charset=utf-8',
	'.css': 'text/css; charset=utf-8',
	'.json': 'application/json; charset=utf-8',
	'.png': 'image/png',
	'.svg': 'image/svg+xml',
	'.ico': 'image/x-icon',
	'.webmanifest': 'application/manifest+json; charset=utf-8',
	'.txt': 'text/plain; charset=utf-8'
};

function loadLocalEnv(filename) {
	const envPath = path.join(rootDir, filename);
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

function sendJson(res, statusCode, payload) {
	res.writeHead(statusCode, {
		'content-type': 'application/json; charset=utf-8',
		'cache-control': 'no-store'
	});
	res.end(JSON.stringify(payload));
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		let body = '';
		req.on('data', chunk => {
			body += chunk;
			if (body.length > 1024 * 32) {
				req.destroy();
				reject(new Error('Request body is too large.'));
			}
		});
		req.on('end', () => resolve(body));
		req.on('error', reject);
	});
}

function loadBundledBitcoin() {
	if (bundledBitcoin) {
		return bundledBitcoin;
	}
	const bitcoinScript = fs.readFileSync(path.join(rootDir, 'lib', 'bitcoinjs-4.0.3-browser.js'), 'utf8');
	const cryptoShim = {
		getRandomValues(target) {
			nodeCrypto.randomFillSync(target);
			return target;
		}
	};
	const context = {
		module: { exports: {} },
		exports: {},
		crypto: cryptoShim,
		msCrypto: cryptoShim,
		window: { crypto: cryptoShim, msCrypto: cryptoShim },
		self: { crypto: cryptoShim, msCrypto: cryptoShim },
		global: { crypto: cryptoShim, msCrypto: cryptoShim }
	};
	vm.runInNewContext(bitcoinScript, context, { timeout: 5000 });
	bundledBitcoin = context.module.exports || context.window.bitcoin || context.global.bitcoin;
	if (!bundledBitcoin) {
		throw new Error('Bundled BitcoinJS failed to load.');
	}
	return bundledBitcoin;
}

function sugarAmount(satoshis) {
	return Number(satoshis || 0) / Math.pow(10, sugarDecimals);
}

function normalizeAddress(value) {
	return String(value || '').trim();
}

function validateSugarAddress(bitcoin, address) {
	try {
		const base58 = bitcoin.address.fromBase58Check(address);
		return base58.version === sugarNetwork.pubKeyHash || base58.version === sugarNetwork.scriptHash;
	} catch (error) {
		try {
			const bech32 = bitcoin.address.fromBech32(address);
			return bech32.prefix === sugarNetwork.bech32;
		} catch (innerError) {
			return false;
		}
	}
}

function getP2WPKHScript(bitcoin, pubkey) {
	return bitcoin.payments.p2wpkh({
		pubkey,
		network: sugarNetwork
	});
}

function getP2SHScript(bitcoin, redeem) {
	return bitcoin.payments.p2sh({
		redeem,
		network: sugarNetwork
	});
}

function getAddressFromKeys(bitcoin, keys) {
	return getP2WPKHScript(bitcoin, keys.publicKey).address;
}

function getScriptType(bitcoin, script) {
	if (script[0] === bitcoin.opcodes.OP_0 && script[1] === 20) {
		return 'bech32';
	}
	if (script[0] === bitcoin.opcodes.OP_HASH160 && script[1] === 20) {
		return 'segwit';
	}
	if (script[0] === bitcoin.opcodes.OP_DUP &&
		script[1] === bitcoin.opcodes.OP_HASH160 &&
		script[2] === 20) {
		return 'legacy';
	}
	return '';
}

async function sugarApiGet(pathname) {
	const response = await fetch(sugarApiBase + pathname);
	const data = await response.json().catch(() => null);
	if (!response.ok || !data) {
		throw new Error('Sugarchain API request failed.');
	}
	return data;
}

async function sugarApiPost(pathname, body) {
	const response = await fetch(sugarApiBase + pathname, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded'
		},
		body: new URLSearchParams(body)
	});
	const data = await response.json().catch(() => null);
	if (!response.ok || !data) {
		throw new Error('Sugarchain API request failed.');
	}
	return data;
}

async function getAddressBalanceSatoshis(address) {
	const data = await sugarApiGet('/balance/' + encodeURIComponent(address));
	return Number(data && data.result && data.result.balance || 0);
}

async function getAddressUtxos(address, amountSatoshis) {
	const data = await sugarApiGet('/unspent/' + encodeURIComponent(address) + '?amount=' + encodeURIComponent(amountSatoshis));
	if (data.error) {
		throw new Error(data.error.message || 'Unable to load funding UTXOs.');
	}
	return Array.isArray(data.result) ? data.result : [];
}

function chooseFaucetUtxos(utxos, requiredSatoshis) {
	const chosen = [];
	let total = 0;
	for (const utxo of utxos) {
		chosen.push(utxo);
		total += Number(utxo.value || 0);
		if (total > requiredSatoshis) {
			break;
		}
	}
	return { chosen, total };
}

function buildFaucetTransaction(bitcoin, keys, recipientAddress, utxos, amountSatoshis, feeSatoshis) {
	const faucetAddress = getAddressFromKeys(bitcoin, keys);
	const txb = new bitcoin.TransactionBuilder(sugarNetwork);
	const scripts = [];
	let totalValue = 0;

	txb.setVersion(2);
	for (const utxo of utxos) {
		const txid = utxo.txid;
		const index = utxo.index !== undefined ? utxo.index : utxo.vout;
		const scriptHex = String(utxo.script || utxo.scriptPubKey || (utxo.scriptPubKey && utxo.scriptPubKey.hex) || '');
		const script = bitcoin.Buffer.from(scriptHex, 'hex');
		const type = getScriptType(bitcoin, script);
		totalValue += Number(utxo.value || 0);
		if (type === 'bech32') {
			const p2wpkh = getP2WPKHScript(bitcoin, keys.publicKey);
			txb.addInput(txid, index, null, p2wpkh.output);
		} else {
			txb.addInput(txid, index);
		}
		scripts.push({
			type,
			value: Number(utxo.value || 0)
		});
	}

	if (totalValue <= amountSatoshis + feeSatoshis) {
		throw new Error('Funding wallet has insufficient spendable balance.');
	}

	txb.addOutput(recipientAddress, amountSatoshis);
	const change = totalValue - amountSatoshis - feeSatoshis;
	if (change > 0) {
		txb.addOutput(faucetAddress, change);
	}

	for (let index = 0; index < scripts.length; index++) {
		switch (scripts[index].type) {
			case 'bech32':
				txb.sign(index, keys, null, null, scripts[index].value, null);
				break;
			case 'segwit': {
				const redeem = getP2WPKHScript(bitcoin, keys.publicKey);
				const p2sh = getP2SHScript(bitcoin, redeem);
				txb.sign(index, keys, p2sh.redeem.output, null, scripts[index].value, null);
				break;
			}
			case 'legacy':
				txb.sign(index, keys);
				break;
			default:
				throw new Error('Unsupported funding UTXO script type.');
		}
	}

	return txb.build().toHex();
}

async function handleFaucetFund(req, res) {
	if (req.method !== 'POST') {
		sendJson(res, 405, { funded: false, error: 'Method not allowed.' });
		return;
	}

	try {
		const rawBody = await readBody(req);
		const body = req.headers['content-type'] && req.headers['content-type'].includes('application/json')
			? JSON.parse(rawBody || '{}')
			: Object.fromEntries(new URLSearchParams(rawBody || ''));
		const address = normalizeAddress(body.address);
		const bitcoin = loadBundledBitcoin();
		if (!validateSugarAddress(bitcoin, address)) {
			throw new Error('Invalid Sugarchain address.');
		}

		const balance = await getAddressBalanceSatoshis(address);
		if (balance >= faucetMinimumBalanceSatoshis) {
			sendJson(res, 200, {
				funded: false,
				reason: 'balance_ok',
				balance,
				minimum_balance: faucetMinimumBalanceSatoshis
			});
			return;
		}

		if (!faucetEnabled) {
			sendJson(res, 503, { funded: false, error: 'Starter funding is disabled on this server.' });
			return;
		}

		const faucetWif = String(process.env.SWEETWALLET_FUNDING_WIF || '').trim();
		if (!faucetWif) {
			sendJson(res, 503, { funded: false, error: 'Starter funding is not configured on this server.' });
			return;
		}

		const previousAttempt = faucetAttempts.get(address);
		if (previousAttempt && Date.now() - previousAttempt < 10 * 60 * 1000) {
			sendJson(res, 200, { funded: false, reason: 'recent_attempt' });
			return;
		}

		const keys = bitcoin.ECPair.fromWIF(faucetWif, sugarNetwork);
		const faucetAddress = getAddressFromKeys(bitcoin, keys);
		if (faucetExpectedAddress && faucetAddress !== faucetExpectedAddress) {
			throw new Error('Starter funding key does not match the configured funding address.');
		}
		const required = faucetAmountSatoshis + faucetFeeSatoshis;
		const utxos = await getAddressUtxos(faucetAddress, required);
		const selection = chooseFaucetUtxos(utxos, required);
		const raw = buildFaucetTransaction(bitcoin, keys, address, selection.chosen, faucetAmountSatoshis, faucetFeeSatoshis);
		const broadcast = await sugarApiPost('/broadcast', { raw });
		if (broadcast.error) {
			throw new Error(broadcast.error.message || 'Starter funding broadcast failed.');
		}

		faucetAttempts.set(address, Date.now());
		sendJson(res, 200, {
			funded: true,
			txid: broadcast.result,
			amount: sugarAmount(faucetAmountSatoshis),
			amount_satoshis: faucetAmountSatoshis
		});
	} catch (error) {
		sendJson(res, 400, { funded: false, error: error.message || 'Starter funding failed.' });
	}
}

function serveStatic(req, res) {
	const requestUrl = new URL(req.url, 'http://localhost');
	let pathname = decodeURIComponent(requestUrl.pathname);
	if (pathname === '/') {
		pathname = '/index.html';
	}

	const filePath = path.resolve(rootDir, '.' + pathname);
	const relativePath = path.relative(rootDir, filePath);
	if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
		res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
		res.end('Forbidden');
		return;
	}

	fs.readFile(filePath, (error, data) => {
		if (error) {
			res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
			res.end('Not found');
			return;
		}

		res.writeHead(200, {
			'content-type': mimeTypes[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
			'cache-control': 'no-store'
		});
		res.end(data);
	});
}

function createRequestHandler() {
	return (req, res) => {
		if (req.url && req.url.startsWith('/api/faucet/fund')) {
			handleFaucetFund(req, res);
			return;
		}
		if (!['GET', 'HEAD'].includes(req.method)) {
			res.writeHead(405, { 'allow': 'GET, HEAD' });
			res.end();
			return;
		}
		serveStatic(req, res);
	};
}

function readHttpsCredentials() {
	if (!fs.existsSync(httpsCertPath)) {
		throw new Error(`Missing HTTPS certificate: ${httpsCertPath}. Generate it with mkcert before running npm run dev:https.`);
	}
	if (!fs.existsSync(httpsKeyPath)) {
		throw new Error(`Missing HTTPS private key: ${httpsKeyPath}. Generate it with mkcert before running npm run dev:https.`);
	}
	return {
		cert: fs.readFileSync(httpsCertPath),
		key: fs.readFileSync(httpsKeyPath)
	};
}

function localLanUrl(portNumber) {
	const lanIp = String(process.env.LOCAL_LAN_IP || '').trim();
	return lanIp ? `https://${lanIp}:${portNumber}/#/` : `https://<PC-LAN-IP>:${portNumber}/#/`;
}

if (httpsEnabled) {
	const server = https.createServer(readHttpsCredentials(), createRequestHandler());
	server.listen(httpsPort, host, () => {
		console.log(`SweetWallet HTTPS running at https://localhost:${httpsPort}/#/`);
		console.log(`SweetWallet HTTPS LAN access: ${localLanUrl(httpsPort)}`);
		console.log(`Listening on ${host}:${httpsPort}`);
	});
} else {
	const server = http.createServer(createRequestHandler());
	server.listen(port, host, () => {
		console.log(`SweetWallet running at http://localhost:${port}/#/`);
		console.log(`SweetWallet LAN access: http://<PC-LAN-IP>:${port}/#/`);
	});
}
