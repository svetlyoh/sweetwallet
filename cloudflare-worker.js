import bitcoin from 'bitcoinjs-lib';
import { Buffer } from 'node:buffer';
import { DurableObject } from 'cloudflare:workers';
import {
	TXID_PATTERN,
	createKlt1Hex,
	transactionContainsKlt1,
	validateOwnershipRequest,
	validateRegistration,
	validateRequestDecision,
	validateSecretId,
	validateTransfer,
	verifySignedRecord
} from './keylink-worker-protocol.mjs';

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

function publicErrorStatus(message) {
	if (/not found|not registered/i.test(message)) {
		return 404;
	}
	if (/already|changed|conflict|stale|does not match|no longer|superseded/i.test(message)) {
		return 409;
	}
	if (/temporarily|unavailable|verify the Sugarchain/i.test(message)) {
		return 503;
	}
	return 400;
}

function allowedCorsOrigin(request) {
	const origin = request.headers.get('origin') || '';
	if (origin === 'https://sweetwallet.net' ||
		/^https?:\/\/localhost(?::\d+)?$/.test(origin) ||
		/^https?:\/\/127\.0\.0\.1(?::\d+)?$/.test(origin)) {
		return origin;
	}
	return '';
}

function withKeylinkCors(response, request) {
	const headers = new Headers(response.headers);
	const origin = allowedCorsOrigin(request);
	if (origin) {
		headers.set('access-control-allow-origin', origin);
		headers.set('vary', 'Origin');
	}
	headers.set('access-control-allow-methods', 'GET, POST, OPTIONS');
	headers.set('access-control-allow-headers', 'Content-Type');
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers
	});
}

async function readBoundedJson(request, maximumBytes = 32768) {
	const declaredLength = Number(request.headers.get('content-length') || 0);
	if (declaredLength > maximumBytes) {
		throw new Error('Keylink request body is too large.');
	}
	const text = await request.text();
	if (new TextEncoder().encode(text).length > maximumBytes) {
		throw new Error('Keylink request body is too large.');
	}
	try {
		return JSON.parse(text);
	} catch (error) {
		throw new Error('Keylink request body is not valid JSON.');
	}
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

export class KeylinkSecret extends DurableObject {
	constructor(ctx, env) {
		super(ctx, env);
		ctx.blockConcurrencyWhile(async () => {
			this.ctx.storage.sql.exec(`
				CREATE TABLE IF NOT EXISTS keylink_secret (
					singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
					secret_id TEXT NOT NULL UNIQUE,
					created_by TEXT NOT NULL,
					current_owner TEXT NOT NULL,
					state_version INTEGER NOT NULL,
					registration_json TEXT NOT NULL,
					encrypted_secret_json TEXT NOT NULL,
					owner_envelope_json TEXT NOT NULL,
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL,
					latest_transfer_txid TEXT
				);
				CREATE TABLE IF NOT EXISTS keylink_requests (
					request_id TEXT PRIMARY KEY,
					requester_id TEXT NOT NULL,
					request_json TEXT NOT NULL,
					status TEXT NOT NULL,
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL,
					decision_json TEXT,
					transfer_txid TEXT
				);
				CREATE INDEX IF NOT EXISTS idx_keylink_requests_status ON keylink_requests(status, updated_at DESC);
				CREATE INDEX IF NOT EXISTS idx_keylink_requests_requester ON keylink_requests(requester_id, updated_at DESC);
				CREATE TABLE IF NOT EXISTS keylink_transfers (
					state_version INTEGER PRIMARY KEY,
					transfer_json TEXT NOT NULL,
					txid TEXT NOT NULL UNIQUE,
					created_at TEXT NOT NULL
				);
			`);
		});
	}

	secretRow() {
		const rows = this.ctx.storage.sql.exec('SELECT * FROM keylink_secret WHERE singleton = 1').toArray();
		return rows[0] || null;
	}

	publicState() {
		const secret = this.secretRow();
		if (!secret) {
			throw new Error('Keylink secret is not registered.');
		}
		const requests = this.ctx.storage.sql.exec(
			'SELECT request_json, status, updated_at, decision_json, transfer_txid FROM keylink_requests ORDER BY updated_at DESC LIMIT 200'
		).toArray().map((row) => {
			const request = JSON.parse(row.request_json);
			return {
				...request,
				status: row.status,
				updated_at: row.updated_at,
				decision: row.decision_json ? JSON.parse(row.decision_json) : null,
				transfer_txid: row.transfer_txid || null
			};
		});
		const transfers = this.ctx.storage.sql.exec(
			'SELECT transfer_json, txid FROM keylink_transfers ORDER BY state_version ASC'
		).toArray().map((row) => ({
			...JSON.parse(row.transfer_json),
			ownership_txid: row.txid
		}));
		return {
			protocol: 'KEYLINK1',
			secret_id: secret.secret_id,
			created_by: secret.created_by,
			current_owner: secret.current_owner,
			state_version: Number(secret.state_version),
			registration: JSON.parse(secret.registration_json),
			encrypted_secret: JSON.parse(secret.encrypted_secret_json),
			owner_envelope: JSON.parse(secret.owner_envelope_json),
			latest_transfer_txid: secret.latest_transfer_txid || null,
			created_at: secret.created_at,
			updated_at: secret.updated_at,
			requests,
			transfers
		};
	}

	async register(registrationInput) {
		const registration = validateRegistration(registrationInput);
		await verifySignedRecord(registration, registration.current_owner, registration.owner_public_key);
		const existing = this.secretRow();
		if (existing) {
			if (existing.secret_id === registration.secret_id && existing.registration_json === JSON.stringify(registration)) {
				return this.publicState();
			}
			throw new Error('This Keylink Secret ID is already registered.');
		}
		this.ctx.storage.sql.exec(
			`INSERT INTO keylink_secret (
				singleton, secret_id, created_by, current_owner, state_version,
				registration_json, encrypted_secret_json, owner_envelope_json,
				created_at, updated_at, latest_transfer_txid
			) VALUES (1, ?, ?, ?, 1, ?, ?, ?, ?, ?, NULL)`,
			registration.secret_id,
			registration.created_by,
			registration.current_owner,
			JSON.stringify(registration),
			JSON.stringify(registration.encrypted_secret),
			JSON.stringify(registration.owner_envelope),
			registration.created_at,
			registration.created_at
		);
		return this.publicState();
	}

	async createRequest(requestInput) {
		const ownershipRequest = validateOwnershipRequest(requestInput);
		await verifySignedRecord(ownershipRequest, ownershipRequest.requester_id, ownershipRequest.requester_public_key);
		const secret = this.secretRow();
		if (!secret) {
			throw new Error('Keylink secret is not registered.');
		}
		if (secret.secret_id !== ownershipRequest.secret_id || secret.current_owner !== ownershipRequest.current_owner_id) {
			throw new Error('Keylink ownership changed before this request was accepted.');
		}
		const duplicate = this.ctx.storage.sql.exec(
			"SELECT request_id FROM keylink_requests WHERE requester_id = ? AND status = 'pending' LIMIT 1",
			ownershipRequest.requester_id
		).toArray()[0];
		if (duplicate) {
			return this.publicState();
		}
		const pendingCount = this.ctx.storage.sql.exec(
			"SELECT COUNT(*) AS count FROM keylink_requests WHERE status = 'pending'"
		).one().count;
		if (Number(pendingCount) >= 100) {
			throw new Error('This Keylink already has too many pending requests.');
		}
		this.ctx.storage.sql.exec(
			`INSERT INTO keylink_requests (
				request_id, requester_id, request_json, status, created_at, updated_at
			) VALUES (?, ?, ?, 'pending', ?, ?)`,
			ownershipRequest.request_id,
			ownershipRequest.requester_id,
			JSON.stringify(ownershipRequest),
			ownershipRequest.created_at,
			ownershipRequest.created_at
		);
		return this.publicState();
	}

	async denyRequest(decisionInput) {
		const decision = validateRequestDecision(decisionInput, 'denied');
		await verifySignedRecord(decision, decision.owner_id, decision.owner_public_key);
		const secret = this.secretRow();
		if (!secret || secret.secret_id !== decision.secret_id) {
			throw new Error('Keylink secret is not registered.');
		}
		if (secret.current_owner !== decision.owner_id) {
			throw new Error('Only the current Keylink owner can deny this request.');
		}
		const row = this.ctx.storage.sql.exec(
			'SELECT status FROM keylink_requests WHERE request_id = ?', decision.request_id
		).toArray()[0];
		if (!row) {
			throw new Error('Keylink ownership request was not found.');
		}
		if (row.status === 'denied') {
			return this.publicState();
		}
		if (row.status !== 'pending') {
			throw new Error('Keylink ownership request is no longer pending.');
		}
		this.ctx.storage.sql.exec(
			"UPDATE keylink_requests SET status = 'denied', updated_at = ?, decision_json = ? WHERE request_id = ? AND status = 'pending'",
			decision.created_at,
			JSON.stringify(decision),
			decision.request_id
		);
		return this.publicState();
	}

	async cancelRequest(decisionInput) {
		const decision = validateRequestDecision(decisionInput, 'cancelled');
		await verifySignedRecord(decision, decision.requester_id, decision.requester_public_key);
		const secret = this.secretRow();
		if (!secret || secret.secret_id !== decision.secret_id) {
			throw new Error('Keylink secret is not registered.');
		}
		const row = this.ctx.storage.sql.exec(
			'SELECT requester_id, status FROM keylink_requests WHERE request_id = ?', decision.request_id
		).toArray()[0];
		if (!row || row.requester_id !== decision.requester_id) {
			throw new Error('Keylink ownership request was not found.');
		}
		if (row.status === 'cancelled') {
			return this.publicState();
		}
		if (row.status !== 'pending') {
			throw new Error('Keylink ownership request is no longer pending.');
		}
		this.ctx.storage.sql.exec(
			"UPDATE keylink_requests SET status = 'cancelled', updated_at = ?, decision_json = ? WHERE request_id = ? AND status = 'pending'",
			decision.created_at,
			JSON.stringify(decision),
			decision.request_id
		);
		return this.publicState();
	}

	async commitTransfer(transferInput, ownershipTxid) {
		const transfer = validateTransfer(transferInput);
		const txid = String(ownershipTxid || '').trim().toLowerCase();
		if (!TXID_PATTERN.test(txid)) {
			throw new Error('Sugarchain ownership transaction ID is invalid.');
		}
		await verifySignedRecord(transfer, transfer.from, transfer.owner_public_key);
		const existingTransfer = this.ctx.storage.sql.exec(
			'SELECT txid FROM keylink_transfers WHERE state_version = ?', transfer.new_state_version
		).toArray()[0];
		if (existingTransfer && existingTransfer.txid === txid) {
			return this.publicState();
		}
		const secret = this.secretRow();
		if (!secret || secret.secret_id !== transfer.secret_id) {
			throw new Error('Keylink secret is not registered.');
		}
		if (secret.current_owner !== transfer.from || Number(secret.state_version) !== transfer.previous_state_version) {
			throw new Error('Keylink ownership changed before this transfer was committed.');
		}
		const request = this.ctx.storage.sql.exec(
			'SELECT requester_id, status FROM keylink_requests WHERE request_id = ?', transfer.request_id
		).toArray()[0];
		if (!request || request.requester_id !== transfer.to || request.status !== 'pending') {
			throw new Error('The approved Keylink request is missing or no longer pending.');
		}
		this.ctx.storage.sql.exec(
			`INSERT INTO keylink_transfers (state_version, transfer_json, txid, created_at)
			 VALUES (?, ?, ?, ?)`,
			transfer.new_state_version,
			JSON.stringify(transfer),
			txid,
			transfer.timestamp
		);
		this.ctx.storage.sql.exec(
			`UPDATE keylink_secret
			 SET current_owner = ?, state_version = ?, owner_envelope_json = ?,
			     updated_at = ?, latest_transfer_txid = ?
			 WHERE singleton = 1 AND current_owner = ? AND state_version = ?`,
			transfer.to,
			transfer.new_state_version,
			JSON.stringify(transfer.new_owner_envelope),
			transfer.timestamp,
			txid,
			transfer.from,
			transfer.previous_state_version
		);
		this.ctx.storage.sql.exec(
			"UPDATE keylink_requests SET status = 'approved', updated_at = ?, decision_json = ?, transfer_txid = ? WHERE request_id = ? AND status = 'pending'",
			transfer.timestamp,
			JSON.stringify(transfer),
			txid,
			transfer.request_id
		);
		this.ctx.storage.sql.exec(
			"UPDATE keylink_requests SET status = 'superseded', updated_at = ? WHERE request_id <> ? AND status = 'pending'",
			transfer.timestamp,
			transfer.request_id
		);
		return this.publicState();
	}
}

function keylinkStub(env, secretId) {
	return env.KEYLINK_SECRETS.getByName(validateSecretId(secretId));
}

async function verifyKlt1Transaction(env, transfer, txid) {
	const expectedHex = await createKlt1Hex(transfer);
	let transaction;
	try {
		transaction = await sugarApiGet(env, '/transaction/' + encodeURIComponent(txid));
	} catch (error) {
		throw new Error('Unable to verify the Sugarchain ownership transaction yet. Retry after propagation.');
	}
	if (transaction && transaction.error) {
		throw new Error('Unable to verify the Sugarchain ownership transaction yet. Retry after propagation.');
	}
	if (!transactionContainsKlt1(transaction, expectedHex)) {
		throw new Error('Sugarchain transaction does not contain the expected KLT1 ownership record.');
	}
}

async function handleKeylinkRequest(request, env) {
	if (request.method === 'OPTIONS') {
		return new Response(null, { status: 204 });
	}
	const url = new URL(request.url);
	const path = url.pathname;
	if (path === '/api/keylink/secrets' && request.method === 'POST') {
		const body = await readBoundedJson(request);
		const registration = validateRegistration(body);
		return jsonResponse({ state: await keylinkStub(env, registration.secret_id).register(registration) }, 201);
	}
	if (path === '/api/keylink/batch' && request.method === 'POST') {
		const body = await readBoundedJson(request, 16384);
		const values = Array.isArray(body.secret_ids) ? body.secret_ids : [];
		const secretIds = Array.from(new Set(values.map(validateSecretId)));
		if (!secretIds.length || secretIds.length > 100) {
			throw new Error('Keylink batch must contain between 1 and 100 Secret IDs.');
		}
		const states = await Promise.all(secretIds.map(async (secretId) => {
			try {
				return await keylinkStub(env, secretId).publicState();
			} catch (error) {
				return { secret_id: secretId, error: 'not_found' };
			}
		}));
		return jsonResponse({ states });
	}
	const match = path.match(/^\/api\/keylink\/secrets\/([0-9a-f]{32})(?:\/(.*))?$/i);
	if (!match) {
		return jsonResponse({ error: 'Keylink API route was not found.' }, 404);
	}
	const secretId = validateSecretId(match[1]);
	const action = match[2] || '';
	const stub = keylinkStub(env, secretId);
	if (!action && request.method === 'GET') {
		return jsonResponse({ state: await stub.publicState() });
	}
	if (action === 'requests' && request.method === 'POST') {
		const body = await readBoundedJson(request);
		if (validateSecretId(body.secret_id) !== secretId) {
			throw new Error('Keylink request path does not match its Secret ID.');
		}
		return jsonResponse({ state: await stub.createRequest(body) }, 201);
	}
	const requestMatch = action.match(/^requests\/([0-9a-f]{32})\/(deny|cancel)$/i);
	if (requestMatch && request.method === 'POST') {
		const body = await readBoundedJson(request);
		if (String(body.request_id || '').toLowerCase() !== requestMatch[1].toLowerCase() || validateSecretId(body.secret_id) !== secretId) {
			throw new Error('Keylink request decision path does not match its signed record.');
		}
		const state = requestMatch[2].toLowerCase() === 'deny' ?
			await stub.denyRequest(body) : await stub.cancelRequest(body);
		return jsonResponse({ state });
	}
	if (action === 'transfers' && request.method === 'POST') {
		const body = await readBoundedJson(request);
		const transfer = validateTransfer(body.transfer);
		const txid = String(body.ownership_txid || '').trim().toLowerCase();
		if (transfer.secret_id !== secretId || !TXID_PATTERN.test(txid)) {
			throw new Error('Keylink transfer path or transaction ID is invalid.');
		}
		await verifySignedRecord(transfer, transfer.from, transfer.owner_public_key);
		await verifyKlt1Transaction(env, transfer, txid);
		return jsonResponse({ state: await stub.commitTransfer(transfer, txid) });
	}
	return jsonResponse({ error: 'Method not allowed.' }, 405);
}

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		if (url.pathname === '/api/faucet/fund') {
			return handleFaucetFund(request, env);
		}
		if (url.pathname.startsWith('/api/keylink/')) {
			const requestId = crypto.randomUUID();
			try {
				return withKeylinkCors(await handleKeylinkRequest(request, env), request);
			} catch (error) {
				const message = error instanceof Error ? error.message : 'Keylink relay request failed.';
				console.error(JSON.stringify({
					level: 'error',
					message: 'Keylink relay request failed',
					requestId,
					method: request.method,
					path: url.pathname,
					error: message
				}));
				return withKeylinkCors(jsonResponse({ error: message, request_id: requestId }, publicErrorStatus(message)), request);
			}
		}
		return env.ASSETS.fetch(request);
	}
};
