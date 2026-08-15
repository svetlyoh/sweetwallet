(function (root, factory) {
	'use strict';
	var api = factory(root);
	if (typeof module === 'object' && module.exports) {
		module.exports = api;
	} else {
		root.SweetWalletFileRelayCrypto = api;
	}
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
	'use strict';

	var PROTOCOL = 'SGF1';
	var RECIPIENT_PROTOCOL = 'SGK1';
	var FILE_CIPHER = 'AES-256-GCM';
	var KEY_TYPE = 'X25519';
	var HKDF_INFO = 'SUGARCHAIN_FILE_KEY_RELAY_V1';
	var BACKUP_PROTOCOL = 'SGK-BACKUP1';
	var BACKUP_ITERATIONS = 600000;

	function getCrypto() {
		var cryptoObject = root && root.crypto;
		if (!cryptoObject || !cryptoObject.getRandomValues || !cryptoObject.subtle) {
			throw new Error('File Key Relay requires Web Crypto on HTTPS or localhost.');
		}
		return cryptoObject;
	}

	function textEncoder() {
		return new TextEncoder();
	}

	function textDecoder() {
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

	function bytesToBase64(bytes) {
		var binary = '';
		toBytes(bytes).forEach(function (byte) {
			binary += String.fromCharCode(byte);
		});
		if (typeof btoa === 'function') {
			return btoa(binary);
		}
		return Buffer.from(binary, 'binary').toString('base64');
	}

	function base64ToBytes(value) {
		var binary;
		if (typeof atob === 'function') {
			binary = atob(value);
		} else {
			binary = Buffer.from(value, 'base64').toString('binary');
		}
		var bytes = new Uint8Array(binary.length);
		for (var index = 0; index < binary.length; index += 1) {
			bytes[index] = binary.charCodeAt(index);
		}
		return bytes;
	}

	function bytesToBase64Url(bytes) {
		return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
	}

	function base64UrlToBytes(value) {
		var clean = String(value || '').trim();
		if (!clean || !/^[A-Za-z0-9_-]+$/.test(clean)) {
			throw new Error('Invalid base64url value.');
		}
		var normalized = clean.replace(/-/g, '+').replace(/_/g, '/');
		while (normalized.length % 4) {
			normalized += '=';
		}
		try {
			return base64ToBytes(normalized);
		} catch (error) {
			throw new Error('Invalid base64url value.');
		}
	}

	function bytesToHex(bytes) {
		return Array.prototype.map.call(toBytes(bytes), function (byte) {
			return byte.toString(16).padStart(2, '0');
		}).join('');
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

	function sha256Bytes(value) {
		var bytes = typeof value === 'string' ? textEncoder().encode(value) : toBytes(value);
		return getCrypto().subtle.digest('SHA-256', bytes).then(function (digest) {
			return new Uint8Array(digest);
		});
	}

	function sha256Hex(value) {
		return sha256Bytes(value).then(bytesToHex);
	}

	function constantTimeEqual(left, right) {
		var a = toBytes(left);
		var b = toBytes(right);
		if (a.length !== b.length) {
			return false;
		}
		var difference = 0;
		for (var index = 0; index < a.length; index += 1) {
			difference |= a[index] ^ b[index];
		}
		return difference === 0;
	}

	function assertByteLength(label, value, length) {
		var bytes = base64UrlToBytes(value);
		if (bytes.length !== length) {
			throw new Error(label + ' must be ' + length + ' bytes.');
		}
		return bytes;
	}

	function normalizedText(value, maxLength) {
		return String(value || '').trim().slice(0, maxLength);
	}

	function createRecipientUri(publicKey, label) {
		assertByteLength('Recipient public encryption key', publicKey, 32);
		var params = new URLSearchParams();
		params.set('v', '1');
		params.set('enc_pubkey', publicKey);
		if (normalizedText(label, 80)) {
			params.set('label', normalizedText(label, 80));
		}
		return 'sugarfilekey://recipient?' + params.toString();
	}

	function parseRecipientPublicKey(value) {
		var raw = String(value || '').trim();
		var label = '';
		var publicKey = raw;
		if (/^sugarfilekey:\/\//i.test(raw)) {
			var uri;
			try {
				uri = new URL(raw);
			} catch (error) {
				throw new Error('Recipient QR URI is malformed.');
			}
			if (uri.protocol !== 'sugarfilekey:' || uri.hostname !== 'recipient' || uri.searchParams.get('v') !== '1') {
				throw new Error('This is not a supported recipient key QR.');
			}
			publicKey = uri.searchParams.get('enc_pubkey') || '';
			label = normalizedText(uri.searchParams.get('label'), 80);
		}
		assertByteLength('Recipient public encryption key', publicKey, 32);
		return {
			publicKey: publicKey,
			label: label
		};
	}

	function generateKeyPair() {
		return getCrypto().subtle.generateKey({ name: KEY_TYPE }, true, ['deriveBits']);
	}

	function exportPublicKey(publicKey) {
		return getCrypto().subtle.exportKey('raw', publicKey).then(function (raw) {
			var bytes = new Uint8Array(raw);
			if (bytes.length !== 32) {
				throw new Error('The browser returned an invalid X25519 public key.');
			}
			return bytesToBase64Url(bytes);
		});
	}

	function importPublicKey(value) {
		var raw = assertByteLength('X25519 public key', value, 32);
		return getCrypto().subtle.importKey('raw', raw, { name: KEY_TYPE }, false, []);
	}

	function deriveWrapKey(privateKey, publicKey, salt) {
		var sharedBytes;
		return getCrypto().subtle.deriveBits({
			name: KEY_TYPE,
			public: publicKey
		}, privateKey, 256).then(function (bits) {
			sharedBytes = new Uint8Array(bits);
			return getCrypto().subtle.importKey('raw', sharedBytes, 'HKDF', false, ['deriveKey']);
		}).then(function (hkdfKey) {
			return getCrypto().subtle.deriveKey({
				name: 'HKDF',
				hash: 'SHA-256',
				salt: toBytes(salt),
				info: textEncoder().encode(HKDF_INFO)
			}, hkdfKey, {
				name: 'AES-GCM',
				length: 256
			}, false, ['encrypt', 'decrypt']);
		}).finally(function () {
			if (sharedBytes) {
				sharedBytes.fill(0);
			}
		});
	}

	function importFileKey(fileKey, usages) {
		if (toBytes(fileKey).length !== 32) {
			return Promise.reject(new Error('File encryption key must be 32 bytes.'));
		}
		return getCrypto().subtle.importKey('raw', fileKey, {
			name: 'AES-GCM',
			length: 256
		}, false, usages);
	}

	function aadFields(payload) {
		return {
			protocol: PROTOCOL,
			type: 'file_key_capsule',
			relay_mode: payload.relay_mode === 'offchain' ? 'offchain' : 'sugarchain',
			capsule_id: normalizedText(payload.capsule_id, 32),
			recipient_key_hash: normalizedText(payload.recipient_key_hash, 64),
			sender_ephemeral_public: normalizedText(payload.sender_ephemeral_public, 64),
			file_cipher: FILE_CIPHER,
			file_nonce: normalizedText(payload.file_nonce, 32),
			encrypted_file_hash: normalizedText(payload.encrypted_file_hash, 64),
			encrypted_file_url: payload.encrypted_file_url || null,
			file_name: normalizedText(payload.file_name, 160),
			file_type: normalizedText(payload.file_type, 100),
			recipient_label: normalizedText(payload.recipient_label, 80),
			note: normalizedText(payload.note, 160),
			created_at: normalizedText(payload.created_at, 40)
		};
	}

	function manifestFields(payload) {
		var manifest = aadFields(payload);
		manifest.capsule_nonce = normalizedText(payload.capsule_nonce, 32);
		manifest.key_capsule_ciphertext = normalizedText(payload.key_capsule_ciphertext, 128);
		return manifest;
	}

	function manifestHash(payload) {
		return sha256Hex(stableStringify(manifestFields(payload)));
	}

	function encodeRelayUri(payload) {
		var encoded = bytesToBase64Url(textEncoder().encode(stableStringify(payload)));
		return 'sugarfilekey://open?v=1&payload=' + encoded;
	}

	function decodeRelayPayload(value) {
		var raw = String(value || '').trim();
		if (!raw || raw.length > 20000) {
			throw new Error('Relay payload is empty or too large.');
		}
		if (/^sugarfilekey:\/\//i.test(raw)) {
			var uri;
			try {
				uri = new URL(raw);
			} catch (error) {
				throw new Error('Relay QR URI is malformed.');
			}
			if (uri.protocol !== 'sugarfilekey:' || uri.hostname !== 'open' || uri.searchParams.get('v') !== '1') {
				throw new Error('This is not a supported File Key Relay QR.');
			}
			raw = textDecoder().decode(base64UrlToBytes(uri.searchParams.get('payload') || ''));
		} else if (raw.charAt(0) !== '{') {
			raw = textDecoder().decode(base64UrlToBytes(raw));
		}
		try {
			return JSON.parse(raw);
		} catch (error) {
			throw new Error('Relay payload JSON is malformed.');
		}
	}

	function normalizeRelayPayload(payload) {
		if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
			throw new Error('Relay payload must be a JSON object.');
		}
		var normalized = {
			protocol: String(payload.protocol || ''),
			type: String(payload.type || ''),
			capsule_id: normalizedText(payload.capsule_id, 32),
			txid: payload.txid ? normalizedText(payload.txid, 64).toLowerCase() : null,
			recipient_key_hash: normalizedText(payload.recipient_key_hash, 64).toLowerCase(),
			sender_ephemeral_public: normalizedText(payload.sender_ephemeral_public, 64),
			capsule_nonce: normalizedText(payload.capsule_nonce, 32),
			key_capsule_ciphertext: normalizedText(payload.key_capsule_ciphertext, 128),
			file_cipher: String(payload.file_cipher || ''),
			file_nonce: normalizedText(payload.file_nonce, 32),
			encrypted_file_hash: normalizedText(payload.encrypted_file_hash, 64).toLowerCase(),
			encrypted_file_url: payload.encrypted_file_url ? normalizedText(payload.encrypted_file_url, 2048) : null,
			manifest_hash: normalizedText(payload.manifest_hash, 64).toLowerCase(),
			created_at: normalizedText(payload.created_at, 40),
			file_name: normalizedText(payload.file_name, 160) || 'decrypted-file',
			file_type: normalizedText(payload.file_type, 100) || 'application/octet-stream',
			recipient_label: normalizedText(payload.recipient_label, 80),
			note: normalizedText(payload.note, 160),
			relay_mode: payload.relay_mode === 'offchain' ? 'offchain' : 'sugarchain'
		};
		if (normalized.protocol !== PROTOCOL || normalized.type !== 'file_key_capsule') {
			throw new Error('Unsupported relay protocol or capsule type.');
		}
		if (!/^[0-9a-f]{16,32}$/i.test(normalized.capsule_id)) {
			throw new Error('Relay capsule ID is invalid.');
		}
		if (normalized.txid && !/^[0-9a-f]{64}$/.test(normalized.txid)) {
			throw new Error('Sugarchain transaction ID is invalid.');
		}
		if (!/^[0-9a-f]{64}$/.test(normalized.recipient_key_hash) ||
			!/^[0-9a-f]{64}$/.test(normalized.encrypted_file_hash) ||
			!/^[0-9a-f]{64}$/.test(normalized.manifest_hash)) {
			throw new Error('Relay hash field is invalid.');
		}
		assertByteLength('Sender ephemeral public key', normalized.sender_ephemeral_public, 32);
		assertByteLength('Capsule nonce', normalized.capsule_nonce, 12);
		assertByteLength('File nonce', normalized.file_nonce, 12);
		var capsuleBytes = base64UrlToBytes(normalized.key_capsule_ciphertext);
		if (capsuleBytes.length !== 48) {
			throw new Error('Encrypted file-key capsule has an invalid length.');
		}
		if (normalized.file_cipher !== FILE_CIPHER) {
			throw new Error('This wallet does not support the capsule file cipher.');
		}
		if (!normalized.created_at || !Number.isFinite(Date.parse(normalized.created_at))) {
			throw new Error('Relay creation time is invalid.');
		}
		if (normalized.relay_mode === 'sugarchain' && !normalized.txid) {
			throw new Error('Sugarchain relay payload is missing its transaction ID.');
		}
		return normalized;
	}

	function validateRelayPayload(payload) {
		var normalized = normalizeRelayPayload(payload);
		return manifestHash(normalized).then(function (computedHash) {
			if (computedHash !== normalized.manifest_hash) {
				throw new Error('Relay manifest hash does not match the capsule.');
			}
			return normalized;
		});
	}

	function encryptRelay(input) {
		var fileBytes = toBytes(input.fileBytes);
		var recipient = parseRecipientPublicKey(input.recipientPublicKey);
		var fileKey = randomBytes(32);
		var fileNonce = randomBytes(12);
		var capsuleNonce = randomBytes(12);
		var payload = {
			protocol: PROTOCOL,
			type: 'file_key_capsule',
			capsule_id: bytesToHex(randomBytes(8)),
			txid: null,
			recipient_key_hash: '',
			sender_ephemeral_public: '',
			capsule_nonce: bytesToBase64Url(capsuleNonce),
			key_capsule_ciphertext: '',
			file_cipher: FILE_CIPHER,
			file_nonce: bytesToBase64Url(fileNonce),
			encrypted_file_hash: '',
			encrypted_file_url: input.encryptedFileUrl || null,
			manifest_hash: '',
			created_at: input.createdAt || new Date().toISOString(),
			file_name: normalizedText(input.fileName, 160) || 'encrypted-file',
			file_type: normalizedText(input.fileType, 100) || 'application/octet-stream',
			recipient_label: normalizedText(input.recipientLabel || recipient.label, 80),
			note: normalizedText(input.note, 160),
			relay_mode: input.relayMode === 'offchain' ? 'offchain' : 'sugarchain'
		};
		var ephemeralPair;
		var encryptedFile;
		var recipientPublic;

		return Promise.all([
			sha256Hex(base64UrlToBytes(recipient.publicKey)),
			importPublicKey(recipient.publicKey),
			generateKeyPair(),
			importFileKey(fileKey, ['encrypt'])
		]).then(function (results) {
			payload.recipient_key_hash = results[0];
			recipientPublic = results[1];
			ephemeralPair = results[2];
			return Promise.all([
				exportPublicKey(ephemeralPair.publicKey),
				getCrypto().subtle.encrypt({
					name: 'AES-GCM',
					iv: fileNonce,
					tagLength: 128
				}, results[3], fileBytes)
			]);
		}).then(function (results) {
			payload.sender_ephemeral_public = results[0];
			encryptedFile = new Uint8Array(results[1]);
			return sha256Hex(encryptedFile);
		}).then(function (hash) {
			payload.encrypted_file_hash = hash;
			return deriveWrapKey(ephemeralPair.privateKey, recipientPublic, capsuleNonce);
		}).then(function (wrapKey) {
			return getCrypto().subtle.encrypt({
				name: 'AES-GCM',
				iv: capsuleNonce,
				additionalData: textEncoder().encode(stableStringify(aadFields(payload))),
				tagLength: 128
			}, wrapKey, fileKey);
		}).then(function (ciphertext) {
			payload.key_capsule_ciphertext = bytesToBase64Url(ciphertext);
			return manifestHash(payload);
		}).then(function (hash) {
			payload.manifest_hash = hash;
			return {
				payload: payload,
				relayUri: encodeRelayUri(payload),
				encryptedFile: encryptedFile,
				opReturnHeader: createAnchorHeader(payload)
			};
		}).finally(function () {
			fileKey.fill(0);
			ephemeralPair = null;
			recipientPublic = null;
		});
	}

	function createAnchorHeader(payload) {
		var normalized = normalizeRelayPayload(Object.assign({}, payload, {
			txid: payload.txid || ('0'.repeat(64)),
			relay_mode: 'sugarchain'
		}));
		var header = PROTOCOL + '|' + normalized.capsule_id.slice(0, 16) + '|' +
			normalized.manifest_hash.slice(0, 32) + '|' + normalized.recipient_key_hash.slice(0, 16);
		if (textEncoder().encode(header).length > 80) {
			throw new Error('SGF1 OP_RETURN header exceeds 80 bytes.');
		}
		return header;
	}

	function withTransaction(payload, txid) {
		var next = Object.assign({}, payload, {
			txid: String(txid || '').toLowerCase(),
			relay_mode: 'sugarchain'
		});
		normalizeRelayPayload(next);
		return next;
	}

	function unwrapFileKey(payload, recipientPrivateKey, recipientPublicKey) {
		var normalized;
		var capsuleNonce;
		var expectedRecipientHash;
		return validateRelayPayload(payload).then(function (validated) {
			normalized = validated;
			capsuleNonce = base64UrlToBytes(normalized.capsule_nonce);
			return sha256Hex(base64UrlToBytes(recipientPublicKey));
		}).then(function (hash) {
			expectedRecipientHash = hash;
			if (hash !== normalized.recipient_key_hash) {
				throw new Error('This file key capsule was not encrypted for this wallet.');
			}
			return importPublicKey(normalized.sender_ephemeral_public);
		}).then(function (ephemeralPublic) {
			return deriveWrapKey(recipientPrivateKey, ephemeralPublic, capsuleNonce);
		}).then(function (wrapKey) {
			return getCrypto().subtle.decrypt({
				name: 'AES-GCM',
				iv: capsuleNonce,
				additionalData: textEncoder().encode(stableStringify(aadFields(normalized))),
				tagLength: 128
			}, wrapKey, base64UrlToBytes(normalized.key_capsule_ciphertext));
		}).then(function (fileKey) {
			var bytes = new Uint8Array(fileKey);
			if (bytes.length !== 32) {
				throw new Error('Decrypted file key has an invalid length.');
			}
			return bytes;
		}).catch(function (error) {
			if (error && /not encrypted for this wallet|manifest hash/i.test(error.message || '')) {
				throw error;
			}
			throw new Error('File key decryption failed. Ask the sender to generate a new relay.');
		});
	}

	function decryptFile(payload, fileKey, encryptedBytes) {
		var normalized;
		var bytes = toBytes(encryptedBytes);
		return validateRelayPayload(payload).then(function (validated) {
			normalized = validated;
			return sha256Hex(bytes);
		}).then(function (hash) {
			if (hash !== normalized.encrypted_file_hash) {
				throw new Error('Encrypted file hash mismatch. Select the file supplied for this relay.');
			}
			return importFileKey(fileKey, ['decrypt']);
		}).then(function (key) {
			return getCrypto().subtle.decrypt({
				name: 'AES-GCM',
				iv: base64UrlToBytes(normalized.file_nonce),
				tagLength: 128
			}, key, bytes);
		}).then(function (plaintext) {
			return new Uint8Array(plaintext);
		}).catch(function (error) {
			if (error && /hash mismatch/i.test(error.message || '')) {
				throw error;
			}
			throw new Error('File decryption failed. Rescan the QR or ask the sender for a new relay.');
		});
	}

	function deriveBackupKey(passphrase, salt, iterations) {
		if (String(passphrase || '').length < 10) {
			return Promise.reject(new Error('Use at least 10 characters for the relay backup password.'));
		}
		return getCrypto().subtle.importKey('raw', textEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']).then(function (baseKey) {
			return getCrypto().subtle.deriveKey({
				name: 'PBKDF2',
				hash: 'SHA-256',
				salt: salt,
				iterations: iterations
			}, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
		});
	}

	function backupAad(record) {
		return textEncoder().encode(stableStringify({
			protocol: BACKUP_PROTOCOL,
			key_type: KEY_TYPE,
			public_key: record.public_key,
			owner_address_hash: record.owner_address_hash,
			created_at: record.created_at
		}));
	}

	function exportEncryptedKeyBackup(privateKey, publicKey, ownerAddressHash, passphrase) {
		var salt = randomBytes(16);
		var nonce = randomBytes(12);
		var pkcs8Bytes;
		var record = {
			protocol: BACKUP_PROTOCOL,
			key_type: KEY_TYPE,
			kdf: 'PBKDF2-SHA256',
			iterations: BACKUP_ITERATIONS,
			salt: bytesToBase64Url(salt),
			nonce: bytesToBase64Url(nonce),
			public_key: publicKey,
			owner_address_hash: ownerAddressHash,
			created_at: new Date().toISOString(),
			ciphertext: ''
		};
		assertByteLength('Relay public key', publicKey, 32);
		return getCrypto().subtle.exportKey('pkcs8', privateKey).then(function (pkcs8) {
			pkcs8Bytes = new Uint8Array(pkcs8);
			return deriveBackupKey(passphrase, salt, BACKUP_ITERATIONS);
		}).then(function (key) {
			return getCrypto().subtle.encrypt({
				name: 'AES-GCM',
				iv: nonce,
				additionalData: backupAad(record),
				tagLength: 128
			}, key, pkcs8Bytes);
		}).then(function (ciphertext) {
			record.ciphertext = bytesToBase64Url(ciphertext);
			return record;
		}).finally(function () {
			if (pkcs8Bytes) {
				pkcs8Bytes.fill(0);
			}
		});
	}

	function verifyKeyPair(privateKey, publicKey) {
		var ephemeral;
		var expected;
		return generateKeyPair().then(function (pair) {
			ephemeral = pair;
			return Promise.all([
				getCrypto().subtle.deriveBits({ name: KEY_TYPE, public: publicKey }, pair.privateKey, 256),
				getCrypto().subtle.deriveBits({ name: KEY_TYPE, public: pair.publicKey }, privateKey, 256)
			]);
		}).then(function (secrets) {
			expected = new Uint8Array(secrets[0]);
			var actual = new Uint8Array(secrets[1]);
			var matches = constantTimeEqual(expected, actual);
			actual.fill(0);
			if (!matches) {
				throw new Error('Relay backup public and private keys do not match.');
			}
			return true;
		}).finally(function () {
			if (expected) {
				expected.fill(0);
			}
			ephemeral = null;
		});
	}

	function importEncryptedKeyBackup(record, passphrase) {
		if (!record || record.protocol !== BACKUP_PROTOCOL || record.key_type !== KEY_TYPE || record.kdf !== 'PBKDF2-SHA256') {
			return Promise.reject(new Error('This is not a supported File Relay key backup.'));
		}
		var iterations = Number(record.iterations);
		if (!Number.isInteger(iterations) || iterations < 300000 || iterations > 2000000) {
			return Promise.reject(new Error('Relay backup KDF settings are invalid.'));
		}
		var salt;
		var nonce;
		var ciphertext;
		var publicKey;
		try {
			salt = assertByteLength('Backup salt', record.salt, 16);
			nonce = assertByteLength('Backup nonce', record.nonce, 12);
			ciphertext = base64UrlToBytes(record.ciphertext);
			assertByteLength('Relay public key', record.public_key, 32);
		} catch (error) {
			return Promise.reject(error);
		}
		if (ciphertext.length < 32 || ciphertext.length > 512) {
			return Promise.reject(new Error('Relay backup ciphertext is invalid.'));
		}
		return deriveBackupKey(passphrase, salt, iterations).then(function (key) {
			return getCrypto().subtle.decrypt({
				name: 'AES-GCM',
				iv: nonce,
				additionalData: backupAad(record),
				tagLength: 128
			}, key, ciphertext);
		}).then(function (pkcs8) {
			return getCrypto().subtle.importKey('pkcs8', pkcs8, { name: KEY_TYPE }, true, ['deriveBits']);
		}).then(function (privateKey) {
			return importPublicKey(record.public_key).then(function (importedPublic) {
				publicKey = importedPublic;
				return verifyKeyPair(privateKey, publicKey).then(function () {
					return {
						privateKey: privateKey,
						publicKey: record.public_key,
						ownerAddressHash: record.owner_address_hash || '',
						createdAt: record.created_at || new Date().toISOString()
					};
				});
			});
		}).catch(function (error) {
			if (error && /public and private|supported|invalid/i.test(error.message || '')) {
				throw error;
			}
			throw new Error('Relay key backup password was not accepted or the file is damaged.');
		});
	}

	function transactionContainsAnchor(value, expectedHeader) {
		var expected = String(expectedHeader || '');
		var expectedHex = bytesToHex(textEncoder().encode(expected)).toLowerCase();
		var found = false;
		function walk(item) {
			if (found || item === null || item === undefined) {
				return;
			}
			if (typeof item === 'string') {
				var text = item.trim();
				if (text.indexOf(expected) >= 0) {
					found = true;
					return;
				}
				if (/^[0-9a-fA-F]+$/.test(text) && text.toLowerCase().indexOf(expectedHex) >= 0) {
					found = true;
				}
				return;
			}
			if (Array.isArray(item)) {
				item.forEach(walk);
				return;
			}
			if (typeof item === 'object') {
				Object.keys(item).forEach(function (key) {
					walk(item[key]);
				});
			}
		}
		walk(value);
		return found;
	}

	return {
		PROTOCOL: PROTOCOL,
		RECIPIENT_PROTOCOL: RECIPIENT_PROTOCOL,
		FILE_CIPHER: FILE_CIPHER,
		KEY_TYPE: KEY_TYPE,
		BACKUP_PROTOCOL: BACKUP_PROTOCOL,
		randomBytes: randomBytes,
		bytesToBase64Url: bytesToBase64Url,
		base64UrlToBytes: base64UrlToBytes,
		bytesToHex: bytesToHex,
		stableStringify: stableStringify,
		sha256Hex: sha256Hex,
		createRecipientUri: createRecipientUri,
		parseRecipientPublicKey: parseRecipientPublicKey,
		generateKeyPair: generateKeyPair,
		exportPublicKey: exportPublicKey,
		importPublicKey: importPublicKey,
		encryptRelay: encryptRelay,
		encodeRelayUri: encodeRelayUri,
		decodeRelayPayload: decodeRelayPayload,
		validateRelayPayload: validateRelayPayload,
		manifestHash: manifestHash,
		createAnchorHeader: createAnchorHeader,
		withTransaction: withTransaction,
		unwrapFileKey: unwrapFileKey,
		decryptFile: decryptFile,
		exportEncryptedKeyBackup: exportEncryptedKeyBackup,
		importEncryptedKeyBackup: importEncryptedKeyBackup,
		transactionContainsAnchor: transactionContainsAnchor
	};
}));
