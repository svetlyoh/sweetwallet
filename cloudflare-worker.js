import bitcoin from 'bitcoinjs-lib';
import { Buffer } from 'node:buffer';

const sugarDecimals = 8;
const faucetAmountSatoshis = 2500000;
const faucetMinimumBalanceSatoshis = 1000000;
const faucetFeeSatoshis = 1000;
const defaultFundingAddress = 'sugar1q39n666w687nxm9x98tx5kgw2uvk780gtmd6yyu';

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

function jsonResponse(payload, status = 200) {
	return new Response(JSON.stringify(payload), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store'
		}
	});
}

function normalizeAddress(value) {
	return String(value || '').trim();
}

function validateSugarAddress(address) {
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

function sugarAmount(satoshis) {
	return Number(satoshis || 0) / Math.pow(10, sugarDecimals);
}

function sugarApiBase(env) {
	return String(env.SUGAR_API_URL || 'https://api.sugar.wtf').replace(/\/+$/, '');
}

async function sugarApiGet(env, pathname) {
	const response = await fetch(sugarApiBase(env) + pathname);
	const data = await response.json().catch(() => null);
	if (!response.ok || !data) {
		throw new Error('Sugarchain API request failed.');
	}
	return data;
}

async function sugarApiPost(env, pathname, body) {
	const response = await fetch(sugarApiBase(env) + pathname, {
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

async function getAddressBalanceSatoshis(env, address) {
	const data = await sugarApiGet(env, '/balance/' + encodeURIComponent(address));
	return Number(data && data.result && data.result.balance || 0);
}

async function getAddressUtxos(env, address, amountSatoshis) {
	const data = await sugarApiGet(env, '/unspent/' + encodeURIComponent(address) + '?amount=' + encodeURIComponent(amountSatoshis));
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

function getP2WPKHScript(pubkey) {
	return bitcoin.payments.p2wpkh({
		pubkey,
		network: sugarNetwork
	});
}

function getP2SHScript(redeem) {
	return bitcoin.payments.p2sh({
		redeem,
		network: sugarNetwork
	});
}

function getAddressFromKeys(keys) {
	return getP2WPKHScript(keys.publicKey).address;
}

function getScriptType(script) {
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

function buildFaucetTransaction(keys, recipientAddress, utxos, amountSatoshis, feeSatoshis) {
	const faucetAddress = getAddressFromKeys(keys);
	const txb = new bitcoin.TransactionBuilder(sugarNetwork);
	const scripts = [];
	let totalValue = 0;

	txb.setVersion(2);
	for (const utxo of utxos) {
		const txid = utxo.txid;
		const index = utxo.index !== undefined ? utxo.index : utxo.vout;
		const scriptHex = String(utxo.script || utxo.scriptPubKey || (utxo.scriptPubKey && utxo.scriptPubKey.hex) || '');
		const script = Buffer.from(scriptHex, 'hex');
		const type = getScriptType(script);
		totalValue += Number(utxo.value || 0);
		if (type === 'bech32') {
			const p2wpkh = getP2WPKHScript(keys.publicKey);
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
				const redeem = getP2WPKHScript(keys.publicKey);
				const p2sh = getP2SHScript(redeem);
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

async function handleFaucetFund(request, env) {
	if (request.method !== 'POST') {
		return jsonResponse({ funded: false, error: 'Method not allowed.' }, 405);
	}

	try {
		const body = await request.json().catch(() => ({}));
		const address = normalizeAddress(body.address);
		if (!validateSugarAddress(address)) {
			throw new Error('Invalid Sugarchain address.');
		}

		const balance = await getAddressBalanceSatoshis(env, address);
		if (balance >= faucetMinimumBalanceSatoshis) {
			return jsonResponse({
				funded: false,
				reason: 'balance_ok',
				balance,
				minimum_balance: faucetMinimumBalanceSatoshis
			});
		}

		const enabled = String(env.SWEETWALLET_STARTER_FUNDING_ENABLED || 'true').toLowerCase() !== 'false';
		if (!enabled) {
			return jsonResponse({ funded: false, error: 'Starter funding is disabled on this server.' }, 503);
		}

		const faucetWif = String(env.SWEETWALLET_FUNDING_WIF || '').trim();
		if (!faucetWif) {
			return jsonResponse({ funded: false, error: 'Starter funding is not configured on this server.' }, 503);
		}

		const keys = bitcoin.ECPair.fromWIF(faucetWif, sugarNetwork);
		const faucetAddress = getAddressFromKeys(keys);
		const expectedAddress = String(env.SWEETWALLET_FUNDING_ADDRESS || defaultFundingAddress).trim();
		if (expectedAddress && faucetAddress !== expectedAddress) {
			throw new Error('Starter funding key does not match the configured funding address.');
		}

		const required = faucetAmountSatoshis + faucetFeeSatoshis;
		const utxos = await getAddressUtxos(env, faucetAddress, required);
		const selection = chooseFaucetUtxos(utxos, required);
		const raw = buildFaucetTransaction(keys, address, selection.chosen, faucetAmountSatoshis, faucetFeeSatoshis);
		const broadcast = await sugarApiPost(env, '/broadcast', { raw });
		if (broadcast.error) {
			throw new Error(broadcast.error.message || 'Starter funding broadcast failed.');
		}

		return jsonResponse({
			funded: true,
			txid: broadcast.result,
			amount: sugarAmount(faucetAmountSatoshis),
			amount_satoshis: faucetAmountSatoshis
		});
	} catch (error) {
		return jsonResponse({ funded: false, error: error.message || 'Starter funding failed.' }, 400);
	}
}

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		if (url.pathname === '/api/faucet/fund') {
			return handleFaucetFund(request, env);
		}
		return env.ASSETS.fetch(request);
	}
};
