(function (root, factory) {
	'use strict';
	var api = factory(root);
	if (typeof module === 'object' && module.exports) {
		module.exports = api;
	} else {
		root.SweetWalletKeylinkCrypto = api;
	}
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
	'use strict';

	var PROTOCOL = 'KEYLINK1';
	var URI_PREFIX = 'keylink://secret/';
	var KLT1_PREFIX = 'KLT1';
	var SECRET_CIPHER = 'AES-256-GCM';
	var ENVELOPE_CIPHER = 'X25519-HKDF-SHA256+A256GCM';
	var IDENTITY_BACKUP_PROTOCOL = 'KEYLINK-IDENTITY-BACKUP1';
	var HKDF_LABEL = 'SWEETWALLET_KEYLINK_CONTENT_KEY_V1';
	var MAX_SECRET_LENGTH = 300;
	var BACKUP_ITERATIONS = 600000;

	function getCrypto() {
		var cryptoObject = root && root.crypto;
		if (!cryptoObject || !cryptoObject.getRandomValues || !cryptoObject.subtle) {
			throw new Error('Keylink requires Web Crypto on HTTPS or localhost.');
		}
		return cryptoObject;
	}

	function encoder() {
		return new TextEncoder();
	}

	function decoder() {
		return new TextDecoder();
	}

	function toBytes(value) {
		if (value instanceof Uint8Array) {
			return value;
		}
		if (value instanceof ArrayBuffer) {
			return new Uint8Array(value);
		}
		if (ArrayBuffer.isView(value)) {
			return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
		}
		throw new Error('Expected binary data.');
	}

	function randomBytes(length) {
		var bytes = new Uint8Array(length);
		getCrypto().getRandomValues(bytes);
		return bytes;
	}

	function bytesToHex(value) {
		return Array.prototype.map.call(toBytes(value), function (byte) {
			return byte.toString(16).padStart(2, '0');
		}).join('');
	}

	function hexToBytes(value) {
		var text = String(value || '').trim().toLowerCase();
		if (!text || text.length % 2 || !/^[0-9a-f]+$/.test(text)) {
			throw new Error('Invalid hexadecimal value.');
		}
		var bytes = new Uint8Array(text.length / 2);
		for (var index = 0; index < bytes.length; index += 1) {
			bytes[index] = parseInt(text.slice(index * 2, index * 2 + 2), 16);
		}
		return bytes;
	}

	function bytesToBase64(value) {
		var bytes = toBytes(value);
		if (typeof Buffer !== 'undefined') {
			return Buffer.from(bytes).toString('base64');
		}
		var binary = '';
		for (var index = 0; index < bytes.length; index += 1) {
			binary += String.fromCharCode(bytes[index]);
		}
		return btoa(binary);
	}

	function base64ToBytes(value) {
		var text = String(value || '');
		var binary = typeof Buffer !== 'undefined' ? Buffer.from(text, 'base64') : atob(text);
		return typeof binary === 'string' ? Uint8Array.from(binary, function (character) {
			return character.charCodeAt(0);
		}) : new Uint8Array(binary);
	}

	function bytesToBase64Url(value) {
		return bytesToBase64(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
	}

	function base64UrlToBytes(value) {
		var text = String(value || '').trim();
		if (!text || !/^[A-Za-z0-9_-]+$/.test(text)) {
			throw new Error('Invalid base64url value.');
		}
		var normalized = text.replace(/-/g, '+').replace(/_/g, '/');
		while (normalized.length % 4) {
			normalized += '=';
		}
		return base64ToBytes(normalized);
	}

	function stableStringify(value) {
		if (value === null || typeof value !== 'object') {
			return JSON.stringify(value);
		}
		if (Array.isArray(value)) {
			return '[' + value.map(stableStringify).join(',') + ']';
		}
		return '{' + Object.keys(value).sort().map(function (key) {
			return JSON.stringify(key) + ':' + stableStringify(value[key]);
		}).join(',') + '}';
	}

	function unsignedRecord(value) {
		var record = {};
		Object.keys(value || {}).forEach(function (key) {
			if (key !== 'signature' && key !== 'ownership_txid') {
				record[key] = value[key];
			}
		});
		return record;
	}

	function sha256Bytes(value) {
		var bytes = typeof value === 'string' ? encoder().encode(value) : toBytes(value);
		return getCrypto().subtle.digest('SHA-256', bytes).then(function (digest) {
			return new Uint8Array(digest);
		});
	}

	function sha256Hex(value) {
		return sha256Bytes(value).then(bytesToHex);
	}

	function assertLength(label, bytes, expected) {
		if (toBytes(bytes).length !== expected) {
			throw new Error(label + ' must be ' + expected + ' bytes.');
		}
		return toBytes(bytes);
	}

	function normalizeSecretId(value) {
		var secretId = String(value || '').trim().toLowerCase();
		if (!/^[0-9a-f]{32}$/.test(secretId)) {
			throw new Error('Keylink Secret ID is invalid.');
		}
		return secretId;
	}

	function createSecretId() {
		return bytesToHex(randomBytes(16));
	}

	function createSecretUri(secretId) {
		return URI_PREFIX + normalizeSecretId(secretId);
	}

	function parseSecretUri(value) {
		var text = String(value || '').trim();
		if (/^[0-9a-f]{32}$/i.test(text)) {
			return normalizeSecretId(text);
		}
		var uri;
		try {
			uri = new URL(text);
		} catch (error) {
			throw new Error('This is not a valid Keylink QR.');
		}
		if (uri.protocol.toLowerCase() !== 'keylink:' || uri.hostname.toLowerCase() !== 'secret') {
			throw new Error('This is not a supported Keylink QR.');
		}
		return normalizeSecretId(uri.pathname.replace(/^\/+/, '').split('/')[0]);
	}

	function generateIdentity() {
		return getCrypto().subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
	}

	function exportPublicKey(publicKey) {
		return getCrypto().subtle.exportKey('raw', publicKey).then(function (raw) {
			return bytesToBase64Url(assertLength('X25519 public key', new Uint8Array(raw), 32));
		});
	}

	function importPublicKey(value) {
		var raw = assertLength('X25519 public key', base64UrlToBytes(value), 32);
		return getCrypto().subtle.importKey('raw', raw, { name: 'X25519' }, false, []);
	}

	function envelopeAad(secretId, ownerId, version, recipientHash) {
		return encoder().encode(stableStringify({
			protocol: PROTOCOL,
			type: 'owner_envelope',
			secret_id: normalizeSecretId(secretId),
			owner_id: String(ownerId || '').trim(),
			state_version: Number(version),
			cipher: ENVELOPE_CIPHER,
			recipient_key_hash: recipientHash
		}));
	}

	function deriveEnvelopeKey(privateKey, publicKey, salt, secretId, ownerId, version) {
		var shared;
		return getCrypto().subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256).then(function (bits) {
			shared = new Uint8Array(bits);
			return getCrypto().subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
		}).then(function (key) {
			return getCrypto().subtle.deriveKey({
				name: 'HKDF',
				hash: 'SHA-256',
				salt: salt,
				info: encoder().encode(HKDF_LABEL + '|' + normalizeSecretId(secretId) + '|' + String(ownerId || '').trim() + '|' + Number(version))
			}, key, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
		}).finally(function () {
			if (shared) {
				shared.fill(0);
			}
		});
	}

	async function wrapContentKey(contentKey, recipientPublicKeyValue, secretId, ownerId, version) {
		var keyBytes = assertLength('Keylink content key', contentKey, 32);
		var recipientBytes = assertLength('X25519 public key', base64UrlToBytes(recipientPublicKeyValue), 32);
		var recipientHash = bytesToBase64Url(await sha256Bytes(recipientBytes));
		var recipientPublicKey = await importPublicKey(recipientPublicKeyValue);
		var ephemeral = await generateIdentity();
		var salt = randomBytes(16);
		var nonce = randomBytes(12);
		var wrapKey = await deriveEnvelopeKey(ephemeral.privateKey, recipientPublicKey, salt, secretId, ownerId, version);
		var ciphertext = await getCrypto().subtle.encrypt({
			name: 'AES-GCM',
			iv: nonce,
			additionalData: envelopeAad(secretId, ownerId, version, recipientHash),
			tagLength: 128
		}, wrapKey, keyBytes);
		return {
			protocol: PROTOCOL,
			type: 'owner_envelope',
			secret_id: normalizeSecretId(secretId),
			owner_id: String(ownerId || '').trim(),
			state_version: Number(version),
			cipher: ENVELOPE_CIPHER,
			recipient_key_hash: recipientHash,
			ephemeral_public: await exportPublicKey(ephemeral.publicKey),
			salt: bytesToBase64Url(salt),
			nonce: bytesToBase64Url(nonce),
			ciphertext: bytesToBase64Url(new Uint8Array(ciphertext))
		};
	}

	async function unwrapContentKey(envelope, identity) {
		if (!envelope || envelope.protocol !== PROTOCOL || envelope.type !== 'owner_envelope' || envelope.cipher !== ENVELOPE_CIPHER) {
			throw new Error('Keylink owner envelope is invalid.');
		}
		var ownPublic = await exportPublicKey(identity.publicKey);
		var ownHash = bytesToBase64Url(await sha256Bytes(base64UrlToBytes(ownPublic)));
		if (ownHash !== envelope.recipient_key_hash) {
			throw new Error('This Keylink encryption identity is not authorized for the current owner envelope.');
		}
		var publicKey = await importPublicKey(envelope.ephemeral_public);
		var salt = assertLength('Envelope salt', base64UrlToBytes(envelope.salt), 16);
		var key = await deriveEnvelopeKey(identity.privateKey, publicKey, salt, envelope.secret_id, envelope.owner_id, envelope.state_version);
		try {
			var plaintext = await getCrypto().subtle.decrypt({
				name: 'AES-GCM',
				iv: assertLength('Envelope nonce', base64UrlToBytes(envelope.nonce), 12),
				additionalData: envelopeAad(envelope.secret_id, envelope.owner_id, envelope.state_version, envelope.recipient_key_hash),
				tagLength: 128
			}, key, base64UrlToBytes(envelope.ciphertext));
			return assertLength('Keylink content key', new Uint8Array(plaintext), 32);
		} catch (error) {
			throw new Error('Unable to open this Keylink with the current encryption identity.');
		}
	}

	function secretAad(secretId) {
		return encoder().encode(stableStringify({
			protocol: PROTOCOL,
			type: 'encrypted_secret',
			secret_id: normalizeSecretId(secretId),
			cipher: SECRET_CIPHER
		}));
	}

	async function encryptSecret(secret, secretIdValue) {
		var text = String(secret || '');
		if (!text.trim()) {
			throw new Error('Enter a secret.');
		}
		if (Array.from(text).length > MAX_SECRET_LENGTH) {
			throw new Error('Keylink secrets may contain at most 300 characters.');
		}
		var secretId = secretIdValue ? normalizeSecretId(secretIdValue) : createSecretId();
		var contentKey = randomBytes(32);
		var nonce = randomBytes(12);
		var cryptoKey = await getCrypto().subtle.importKey('raw', contentKey, { name: 'AES-GCM' }, false, ['encrypt']);
		var ciphertext = await getCrypto().subtle.encrypt({
			name: 'AES-GCM',
			iv: nonce,
			additionalData: secretAad(secretId),
			tagLength: 128
		}, cryptoKey, encoder().encode(text));
		return {
			contentKey: contentKey,
			encryptedSecret: {
				protocol: PROTOCOL,
				type: 'encrypted_secret',
				secret_id: secretId,
				cipher: SECRET_CIPHER,
				nonce: bytesToBase64Url(nonce),
				ciphertext: bytesToBase64Url(new Uint8Array(ciphertext))
			}
		};
	}

	async function decryptSecret(encryptedSecret, contentKey) {
		if (!encryptedSecret || encryptedSecret.protocol !== PROTOCOL || encryptedSecret.type !== 'encrypted_secret' || encryptedSecret.cipher !== SECRET_CIPHER) {
			throw new Error('Encrypted Keylink secret is invalid.');
		}
		var key = await getCrypto().subtle.importKey('raw', assertLength('Keylink content key', contentKey, 32), { name: 'AES-GCM' }, false, ['decrypt']);
		try {
			var plaintext = await getCrypto().subtle.decrypt({
				name: 'AES-GCM',
				iv: assertLength('Secret nonce', base64UrlToBytes(encryptedSecret.nonce), 12),
				additionalData: secretAad(encryptedSecret.secret_id),
				tagLength: 128
			}, key, base64UrlToBytes(encryptedSecret.ciphertext));
			return decoder().decode(plaintext);
		} catch (error) {
			throw new Error('Unable to decrypt this Keylink secret.');
		}
	}

	async function rewrapOwnerEnvelope(envelope, currentIdentity, newOwnerPublicKey, newOwnerId, newVersion) {
		var key = await unwrapContentKey(envelope, currentIdentity);
		try {
			return await wrapContentKey(key, newOwnerPublicKey, envelope.secret_id, newOwnerId, newVersion);
		} finally {
			key.fill(0);
		}
	}

	async function createKlt1Payload(transfer) {
		var secretId = normalizeSecretId(transfer && transfer.secret_id);
		var version = Number(transfer && transfer.new_state_version);
		if (!Number.isInteger(version) || version < 2 || !transfer.signature) {
			throw new Error('Signed Keylink transfer is invalid.');
		}
		var ownerHash = (await sha256Bytes(String(transfer.to || '').trim())).slice(0, 20);
		var transferHash = await sha256Bytes(stableStringify(transfer));
		var payload = new Uint8Array(76);
		payload.set(encoder().encode(KLT1_PREFIX), 0);
		payload.set(hexToBytes(secretId), 4);
		payload.set(ownerHash, 20);
		new DataView(payload.buffer).setUint32(40, version, false);
		payload.set(transferHash, 44);
		return payload;
	}

	async function createKlt1Hex(transfer) {
		return bytesToHex(await createKlt1Payload(transfer));
	}

	async function exportIdentityBackup(identity, password, ownerId) {
		if (String(password || '').length < 10) {
			throw new Error('Use a backup password of at least 10 characters.');
		}
		var privateJwk = await getCrypto().subtle.exportKey('jwk', identity.privateKey);
		var publicJwk = await getCrypto().subtle.exportKey('jwk', identity.publicKey);
		var salt = randomBytes(16);
		var nonce = randomBytes(12);
		var material = await getCrypto().subtle.importKey('raw', encoder().encode(password), 'PBKDF2', false, ['deriveKey']);
		var key = await getCrypto().subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: BACKUP_ITERATIONS }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
		var payload = stableStringify({ private_key: privateJwk, public_key: publicJwk, owner_id: String(ownerId || ''), created_at: new Date().toISOString() });
		var ciphertext = await getCrypto().subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, encoder().encode(payload));
		return JSON.stringify({ protocol: IDENTITY_BACKUP_PROTOCOL, kdf: 'PBKDF2-SHA256', iterations: BACKUP_ITERATIONS, salt: bytesToBase64Url(salt), cipher: 'AES-256-GCM', nonce: bytesToBase64Url(nonce), ciphertext: bytesToBase64Url(new Uint8Array(ciphertext)) });
	}

	async function importIdentityBackup(value, password) {
		var backup;
		try {
			backup = typeof value === 'string' ? JSON.parse(value) : value;
		} catch (error) {
			throw new Error('Keylink identity backup is not valid JSON.');
		}
		if (!backup || backup.protocol !== IDENTITY_BACKUP_PROTOCOL || backup.iterations !== BACKUP_ITERATIONS) {
			throw new Error('This is not a supported Keylink identity backup.');
		}
		var material = await getCrypto().subtle.importKey('raw', encoder().encode(String(password || '')), 'PBKDF2', false, ['deriveKey']);
		var key = await getCrypto().subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: base64UrlToBytes(backup.salt), iterations: BACKUP_ITERATIONS }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
		var payload;
		try {
			var plaintext = await getCrypto().subtle.decrypt({ name: 'AES-GCM', iv: base64UrlToBytes(backup.nonce), tagLength: 128 }, key, base64UrlToBytes(backup.ciphertext));
			payload = JSON.parse(decoder().decode(plaintext));
		} catch (error) {
			throw new Error('Unable to open the Keylink identity backup. Check the password.');
		}
		return {
			ownerId: String(payload.owner_id || ''),
			privateKey: await getCrypto().subtle.importKey('jwk', payload.private_key, { name: 'X25519' }, true, ['deriveBits']),
			publicKey: await getCrypto().subtle.importKey('jwk', payload.public_key, { name: 'X25519' }, true, [])
		};
	}

	return {
		PROTOCOL: PROTOCOL,
		KLT1_PREFIX: KLT1_PREFIX,
		MAX_SECRET_LENGTH: MAX_SECRET_LENGTH,
		IDENTITY_BACKUP_PROTOCOL: IDENTITY_BACKUP_PROTOCOL,
		bytesToBase64Url: bytesToBase64Url,
		base64UrlToBytes: base64UrlToBytes,
		bytesToHex: bytesToHex,
		hexToBytes: hexToBytes,
		stableStringify: stableStringify,
		unsignedRecord: unsignedRecord,
		sha256Bytes: sha256Bytes,
		sha256Hex: sha256Hex,
		createSecretId: createSecretId,
		createSecretUri: createSecretUri,
		parseSecretUri: parseSecretUri,
		generateIdentity: generateIdentity,
		exportPublicKey: exportPublicKey,
		importPublicKey: importPublicKey,
		encryptSecret: encryptSecret,
		decryptSecret: decryptSecret,
		wrapContentKey: wrapContentKey,
		unwrapContentKey: unwrapContentKey,
		rewrapOwnerEnvelope: rewrapOwnerEnvelope,
		createKlt1Payload: createKlt1Payload,
		createKlt1Hex: createKlt1Hex,
		exportIdentityBackup: exportIdentityBackup,
		importIdentityBackup: importIdentityBackup
	};
}));
