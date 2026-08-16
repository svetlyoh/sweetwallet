import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base58check, bech32 } from '@scure/base';
import { Buffer } from 'node:buffer';

export const KEYLINK_PROTOCOL = 'KEYLINK1';
export const KLT1_PREFIX = 'KLT1';
export const SECRET_ID_PATTERN = /^[0-9a-f]{32}$/;
export const TXID_PATTERN = /^[0-9a-f]{64}$/;
export const PUBLIC_KEY_PATTERN = /^(02|03)[0-9a-f]{64}$/;
export const SIGNATURE_PATTERN = /^[0-9a-f]{128}$/;
export const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
export const PIN_PATTERN = /^\d{6}$/;

export const sugarNetwork = {
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

const sugarBase58 = base58check(sha256);

function isPlainObject(value) {
	return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function stableStringify(value) {
	if (value === null || typeof value !== 'object') {
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		return '[' + value.map(stableStringify).join(',') + ']';
	}
	return '{' + Object.keys(value).sort().map((key) => {
		return JSON.stringify(key) + ':' + stableStringify(value[key]);
	}).join(',') + '}';
}

export async function sha256Bytes(value) {
	const bytes = value instanceof Uint8Array ? value : new TextEncoder().encode(String(value));
	return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function sha256Hex(value) {
	return Buffer.from(await sha256Bytes(value)).toString('hex');
}

export function unsignedRecord(value) {
	if (!isPlainObject(value)) {
		throw new Error('Signed Keylink record must be an object.');
	}
	const record = {};
	for (const key of Object.keys(value)) {
		if (key !== 'signature' && key !== 'ownership_txid') {
			record[key] = value[key];
		}
	}
	return record;
}

export function validateSecretId(value) {
	const secretId = String(value || '').trim().toLowerCase();
	if (!SECRET_ID_PATTERN.test(secretId)) {
		throw new Error('Keylink Secret ID is invalid.');
	}
	return secretId;
}

export function validateTimestamp(value, label = 'Timestamp') {
	const text = String(value || '');
	const timestamp = Date.parse(text);
	if (!Number.isFinite(timestamp)) {
		throw new Error(label + ' is invalid.');
	}
	if (Math.abs(Date.now() - timestamp) > 24 * 60 * 60 * 1000) {
		throw new Error(label + ' is outside the accepted 24-hour window.');
	}
	return new Date(timestamp).toISOString();
}

export function validateAddress(address) {
	const value = String(address || '').trim();
	try {
		const decoded = sugarBase58.decode(value);
		if (decoded.length === 21 && (decoded[0] === sugarNetwork.pubKeyHash || decoded[0] === sugarNetwork.scriptHash)) {
			return value;
		}
	} catch (error) {
		// Continue with Bech32 validation.
	}
	try {
		const decoded = bech32.decode(value);
		if (decoded.prefix === sugarNetwork.bech32 && decoded.words[0] === 0 && bech32.fromWords(decoded.words.slice(1)).length === 20) {
			return value;
		}
	} catch (error) {
		// Fall through to the shared validation error.
	}
	throw new Error('Sugarchain identity is invalid.');
}

export function addressesForPublicKey(publicKeyHex) {
	const value = String(publicKeyHex || '').trim().toLowerCase();
	if (!PUBLIC_KEY_PATTERN.test(value)) {
		throw new Error('Sugarchain public key is invalid.');
	}
	const pubkey = Uint8Array.from(Buffer.from(value, 'hex'));
	const publicKeyHash = ripemd160(sha256(pubkey));
	const witnessAddress = bech32.encode(sugarNetwork.bech32, [0].concat(bech32.toWords(publicKeyHash)));
	const redeemScript = new Uint8Array(2 + publicKeyHash.length);
	redemptionScriptSet(redeemScript, publicKeyHash);
	const nestedHash = ripemd160(sha256(redeemScript));
	const nestedAddress = sugarBase58.encode(Uint8Array.from([sugarNetwork.scriptHash].concat(Array.from(nestedHash))));
	const legacyAddress = sugarBase58.encode(Uint8Array.from([sugarNetwork.pubKeyHash].concat(Array.from(publicKeyHash))));
	return [witnessAddress, nestedAddress, legacyAddress];
}

function redemptionScriptSet(script, publicKeyHash) {
	script[0] = 0;
	script[1] = 20;
	script.set(publicKeyHash, 2);
}

export async function verifySignedRecord(record, address, publicKeyHex) {
	const signatureHex = String(record && record.signature || '').trim().toLowerCase();
	const publicKey = String(publicKeyHex || '').trim().toLowerCase();
	const identity = validateAddress(address);
	if (!SIGNATURE_PATTERN.test(signatureHex)) {
		throw new Error('Keylink signature is invalid.');
	}
	if (!addressesForPublicKey(publicKey).includes(identity)) {
		throw new Error('Keylink public key does not control the supplied Sugarchain identity.');
	}
	const digest = await sha256Bytes(stableStringify(unsignedRecord(record)));
	if (!secp256k1.verify(Buffer.from(signatureHex, 'hex'), digest, Buffer.from(publicKey, 'hex'), {
		prehash: false,
		lowS: true,
		format: 'compact'
	})) {
		throw new Error('Keylink signature verification failed.');
	}
	return true;
}

function assertBase64UrlBytes(label, value, expectedLength, maximumLength = expectedLength) {
	const text = String(value || '');
	if (!text || !BASE64URL_PATTERN.test(text)) {
		throw new Error(label + ' is invalid.');
	}
	let bytes;
	try {
		bytes = Buffer.from(text.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
	} catch (error) {
		throw new Error(label + ' is invalid.');
	}
	if (bytes.length < expectedLength || bytes.length > maximumLength) {
		throw new Error(label + ' has an invalid length.');
	}
	return text;
}

export function validateEncryptedSecret(value) {
	if (!isPlainObject(value) || value.protocol !== KEYLINK_PROTOCOL || value.type !== 'encrypted_secret' || value.cipher !== 'AES-256-GCM') {
		throw new Error('Encrypted Keylink secret is invalid.');
	}
	const secretId = validateSecretId(value.secret_id);
	assertBase64UrlBytes('Secret nonce', value.nonce, 12);
	assertBase64UrlBytes('Secret ciphertext', value.ciphertext, 17, 4096);
	return {
		protocol: KEYLINK_PROTOCOL,
		type: 'encrypted_secret',
		secret_id: secretId,
		cipher: 'AES-256-GCM',
		nonce: String(value.nonce),
		ciphertext: String(value.ciphertext)
	};
}

export function validateOwnerEnvelope(value, expectedSecretId, expectedOwner, expectedVersion) {
	if (!isPlainObject(value) || value.protocol !== KEYLINK_PROTOCOL || value.type !== 'owner_envelope' || value.cipher !== 'X25519-HKDF-SHA256+A256GCM') {
		throw new Error('Keylink owner envelope is invalid.');
	}
	const secretId = validateSecretId(value.secret_id);
	const owner = validateAddress(value.owner_id);
	const version = Number(value.state_version);
	if (secretId !== expectedSecretId || owner !== expectedOwner || version !== expectedVersion) {
		throw new Error('Keylink owner envelope does not match the ownership state.');
	}
	assertBase64UrlBytes('Owner encryption-key hash', value.recipient_key_hash, 32);
	assertBase64UrlBytes('Owner envelope ephemeral key', value.ephemeral_public, 32);
	assertBase64UrlBytes('Owner envelope salt', value.salt, 16);
	assertBase64UrlBytes('Owner envelope nonce', value.nonce, 12);
	assertBase64UrlBytes('Owner envelope ciphertext', value.ciphertext, 48);
	return {
		protocol: KEYLINK_PROTOCOL,
		type: 'owner_envelope',
		secret_id: secretId,
		owner_id: owner,
		state_version: version,
		cipher: 'X25519-HKDF-SHA256+A256GCM',
		recipient_key_hash: String(value.recipient_key_hash),
		ephemeral_public: String(value.ephemeral_public),
		salt: String(value.salt),
		nonce: String(value.nonce),
		ciphertext: String(value.ciphertext)
	};
}

export function validateRegistration(input) {
	if (!isPlainObject(input) || input.protocol !== KEYLINK_PROTOCOL || input.type !== 'secret_registration') {
		throw new Error('Keylink registration is invalid.');
	}
	const secretId = validateSecretId(input.secret_id);
	const creator = validateAddress(input.created_by);
	const owner = validateAddress(input.current_owner);
	const stateVersion = Number(input.state_version);
	if (creator !== owner || stateVersion !== 1) {
		throw new Error('New Keylinks must begin with the creator as owner at state version 1.');
	}
	const encryptedSecret = validateEncryptedSecret(input.encrypted_secret);
	if (encryptedSecret.secret_id !== secretId) {
		throw new Error('Encrypted secret does not match the Keylink Secret ID.');
	}
	const envelope = validateOwnerEnvelope(input.owner_envelope, secretId, owner, 1);
	assertBase64UrlBytes('Owner encryption public key', input.owner_encryption_key, 32);
	if (!PUBLIC_KEY_PATTERN.test(String(input.owner_public_key || '').toLowerCase())) {
		throw new Error('Owner public key is invalid.');
	}
	if (!/^[0-9a-f]{32}$/.test(String(input.nonce || '').toLowerCase())) {
		throw new Error('Registration nonce is invalid.');
	}
	validateTimestamp(input.created_at, 'Registration timestamp');
	const registration = {
		protocol: KEYLINK_PROTOCOL,
		type: 'secret_registration',
		secret_id: secretId,
		created_by: creator,
		current_owner: owner,
		owner_public_key: String(input.owner_public_key).toLowerCase(),
		owner_encryption_key: String(input.owner_encryption_key),
		encrypted_secret: encryptedSecret,
		owner_envelope: envelope,
		state_version: 1,
		nonce: String(input.nonce).toLowerCase(),
		created_at: new Date(Date.parse(input.created_at)).toISOString(),
		signature: String(input.signature || '').toLowerCase()
	};
	if (Object.prototype.hasOwnProperty.call(input, 'pin_required')) {
		registration.pin_required = input.pin_required === true;
	}
	if (Object.prototype.hasOwnProperty.call(input, 'autoapprove_enabled')) {
		registration.autoapprove_enabled = registration.pin_required === true && input.autoapprove_enabled === true;
	}
	return registration;
}

export function validateOwnershipRequest(input) {
	if (!isPlainObject(input) || input.protocol !== KEYLINK_PROTOCOL || input.type !== 'ownership_request') {
		throw new Error('Keylink ownership request is invalid.');
	}
	const secretId = validateSecretId(input.secret_id);
	const currentOwner = validateAddress(input.current_owner_id);
	const requester = validateAddress(input.requester_id);
	if (requester === currentOwner) {
		throw new Error('The current owner cannot request their own Keylink.');
	}
	if (!/^[0-9a-f]{32}$/.test(String(input.request_id || '').toLowerCase()) ||
		!/^[0-9a-f]{32}$/.test(String(input.nonce || '').toLowerCase())) {
		throw new Error('Keylink request identifier is invalid.');
	}
	if (!PUBLIC_KEY_PATTERN.test(String(input.requester_public_key || '').toLowerCase())) {
		throw new Error('Requester public key is invalid.');
	}
	assertBase64UrlBytes('Requester encryption public key', input.requester_encryption_key, 32);
	validateTimestamp(input.created_at, 'Request timestamp');
	const ownershipRequest = {
		protocol: KEYLINK_PROTOCOL,
		type: 'ownership_request',
		request_id: String(input.request_id).toLowerCase(),
		secret_id: secretId,
		current_owner_id: currentOwner,
		requester_id: requester,
		requester_public_key: String(input.requester_public_key).toLowerCase(),
		requester_encryption_key: String(input.requester_encryption_key),
		nonce: String(input.nonce).toLowerCase(),
		created_at: new Date(Date.parse(input.created_at)).toISOString(),
		signature: String(input.signature || '').toLowerCase()
	};
	if (Object.prototype.hasOwnProperty.call(input, 'state_version')) {
		const stateVersion = Number(input.state_version);
		if (!Number.isInteger(stateVersion) || stateVersion < 1) {
			throw new Error('Keylink request state version is invalid.');
		}
		ownershipRequest.state_version = stateVersion;
	}
	return ownershipRequest;
}

export function validatePinPolicyUpdate(input) {
	if (!isPlainObject(input) || input.protocol !== KEYLINK_PROTOCOL || input.type !== 'pin_policy_update') {
		throw new Error('Keylink PIN policy update is invalid.');
	}
	const stateVersion = Number(input.state_version);
	if (!Number.isInteger(stateVersion) || stateVersion < 1 || !PUBLIC_KEY_PATTERN.test(String(input.owner_public_key || '').toLowerCase()) ||
		!/^[0-9a-f]{32}$/.test(String(input.nonce || '').toLowerCase())) {
		throw new Error('Keylink PIN policy authorization is invalid.');
	}
	validateTimestamp(input.created_at, 'PIN policy timestamp');
	const pinRequired = input.pin_required === true;
	return {
		protocol: KEYLINK_PROTOCOL,
		type: 'pin_policy_update',
		secret_id: validateSecretId(input.secret_id),
		owner_id: validateAddress(input.owner_id),
		owner_public_key: String(input.owner_public_key).toLowerCase(),
		state_version: stateVersion,
		pin_required: pinRequired,
		autoapprove_enabled: pinRequired && input.autoapprove_enabled === true,
		replace_pin: pinRequired && input.replace_pin === true,
		replace_reserved: input.replace_reserved === true,
		nonce: String(input.nonce).toLowerCase(),
		created_at: new Date(Date.parse(input.created_at)).toISOString(),
		signature: String(input.signature || '').toLowerCase()
	};
}

export function validateRequestDecision(input, type) {
	const expectedType = type === 'cancelled' ? 'ownership_request_cancellation' : 'ownership_request_denial';
	if (!isPlainObject(input) || input.protocol !== KEYLINK_PROTOCOL || input.type !== expectedType) {
		throw new Error('Keylink request decision is invalid.');
	}
	const actorField = type === 'cancelled' ? 'requester_id' : 'owner_id';
	const publicKeyField = type === 'cancelled' ? 'requester_public_key' : 'owner_public_key';
	const actor = validateAddress(input[actorField]);
	if (!/^[0-9a-f]{32}$/.test(String(input.request_id || '').toLowerCase()) ||
		!/^[0-9a-f]{32}$/.test(String(input.nonce || '').toLowerCase())) {
		throw new Error('Keylink request decision identifier is invalid.');
	}
	if (!PUBLIC_KEY_PATTERN.test(String(input[publicKeyField] || '').toLowerCase())) {
		throw new Error('Keylink request decision public key is invalid.');
	}
	validateTimestamp(input.created_at, 'Decision timestamp');
	return {
		protocol: KEYLINK_PROTOCOL,
		type: expectedType,
		request_id: String(input.request_id).toLowerCase(),
		secret_id: validateSecretId(input.secret_id),
		[actorField]: actor,
		[publicKeyField]: String(input[publicKeyField]).toLowerCase(),
		nonce: String(input.nonce).toLowerCase(),
		created_at: new Date(Date.parse(input.created_at)).toISOString(),
		signature: String(input.signature || '').toLowerCase()
	};
}

export function validateTransfer(input) {
	if (!isPlainObject(input) || input.protocol !== KEYLINK_PROTOCOL || input.type !== 'ownership_transfer') {
		throw new Error('Keylink ownership transfer is invalid.');
	}
	const secretId = validateSecretId(input.secret_id);
	const from = validateAddress(input.from);
	const to = validateAddress(input.to);
	const previousVersion = Number(input.previous_state_version);
	const newVersion = Number(input.new_state_version);
	if (from === to || !Number.isInteger(previousVersion) || previousVersion < 1 || newVersion !== previousVersion + 1) {
		throw new Error('Keylink ownership transition is invalid.');
	}
	if (!/^[0-9a-f]{32}$/.test(String(input.request_id || '').toLowerCase()) ||
		!/^[0-9a-f]{32}$/.test(String(input.nonce || '').toLowerCase())) {
		throw new Error('Keylink transfer identifier is invalid.');
	}
	if (!PUBLIC_KEY_PATTERN.test(String(input.owner_public_key || '').toLowerCase())) {
		throw new Error('Transfer owner public key is invalid.');
	}
	const manualApproval = isPlainObject(input.authorization) && input.authorization.policy === 'CURRENT_OWNER_MANUAL_APPROVAL' &&
		input.authorization.provider === 'ManualOwnerApprovalProvider' && input.authorization.decision === 'approved';
	const pinAutoapproval = isPlainObject(input.authorization) && input.authorization.policy === 'PIN_AUTOAPPROVE_ADVANCE_AUTHORIZATION' &&
		input.authorization.provider === 'LocalWalletPinAutoapproveProvider' && input.authorization.decision === 'approved';
	if (!manualApproval && !pinAutoapproval) {
		throw new Error('Keylink transfer authorization is invalid.');
	}
	validateTimestamp(input.timestamp, 'Transfer timestamp');
	const envelope = validateOwnerEnvelope(input.new_owner_envelope, secretId, to, newVersion);
	return {
		protocol: KEYLINK_PROTOCOL,
		type: 'ownership_transfer',
		secret_id: secretId,
		from,
		to,
		request_id: String(input.request_id).toLowerCase(),
		previous_state_version: previousVersion,
		new_state_version: newVersion,
		timestamp: new Date(Date.parse(input.timestamp)).toISOString(),
		nonce: String(input.nonce).toLowerCase(),
		authorization: {
			policy: input.authorization.policy,
			provider: input.authorization.provider,
			decision: 'approved'
		},
		owner_public_key: String(input.owner_public_key).toLowerCase(),
		new_owner_envelope: envelope,
		signature: String(input.signature || '').toLowerCase()
	};
}

export async function createKlt1Payload(transferInput) {
	const transfer = validateTransfer(transferInput);
	if (!SIGNATURE_PATTERN.test(transfer.signature)) {
		throw new Error('Keylink transfer signature is invalid.');
	}
	const secretBytes = Buffer.from(transfer.secret_id, 'hex');
	const ownerHash = Buffer.from(await sha256Bytes(transfer.to)).subarray(0, 20);
	const version = Buffer.alloc(4);
	version.writeUInt32BE(transfer.new_state_version, 0);
	const transferHash = Buffer.from(await sha256Bytes(stableStringify(transfer)));
	const payload = Buffer.concat([
		Buffer.from(KLT1_PREFIX, 'ascii'),
		secretBytes,
		ownerHash,
		version,
		transferHash
	]);
	if (payload.length !== 76) {
		throw new Error('KLT1 payload must be exactly 76 bytes.');
	}
	return new Uint8Array(payload);
}

export async function createKlt1Hex(transfer) {
	return Buffer.from(await createKlt1Payload(transfer)).toString('hex');
}

export function transactionContainsKlt1(value, expectedHex) {
	const needle = String(expectedHex || '').toLowerCase();
	if (!/^[0-9a-f]{152}$/.test(needle) || !needle.startsWith(Buffer.from(KLT1_PREFIX, 'ascii').toString('hex'))) {
		return false;
	}
	let found = false;
	function walk(item) {
		if (found || item === null || item === undefined) {
			return;
		}
		if (typeof item === 'string') {
			const text = item.trim().toLowerCase();
			if (/^[0-9a-f]+$/.test(text) && text.includes(needle)) {
				found = true;
			}
			return;
		}
		if (Array.isArray(item)) {
			for (const child of item) {
				walk(child);
			}
			return;
		}
		if (typeof item === 'object') {
			for (const child of Object.values(item)) {
				walk(child);
			}
		}
	}
	walk(value);
	return found;
}
