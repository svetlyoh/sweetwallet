(function (root, factory) {
	if (typeof module === 'object' && module.exports) {
		module.exports = factory();
	} else {
		root.SweetWalletVault = factory();
	}
}(typeof self !== 'undefined' ? self : this, function () {
	'use strict';

	var SCHEMA_VERSION = 1;
	var DEFAULT_ITERATIONS = 900000;
	var PIN_ITERATIONS = 240000;
	var NETWORK = 'sugarchain-mainnet';
	var COMMON_PASSWORDS = [
		'password', 'password1', 'password123', '1234567890', '123456789',
		'qwerty12345', 'letmein123', '1111111111', 'sugarchain', 'sweetwallet'
	];

	function availabilityError() {
		var cryptoObj = (typeof globalThis !== 'undefined' && globalThis.crypto) || null;
		if (typeof globalThis !== 'undefined' &&
			typeof globalThis.isSecureContext === 'boolean' &&
			!globalThis.isSecureContext) {
			return 'Encrypted private-key storage requires HTTPS or localhost. iOS Safari blocks Web Crypto on ordinary http:// LAN addresses like 192.168.x.x.';
		}
		if (!cryptoObj || !cryptoObj.getRandomValues) {
			return 'Secure random generation is unavailable in this browser.';
		}
		if (!cryptoObj.subtle) {
			return 'Web Crypto encryption is unavailable. Open SweetWallet from HTTPS or localhost before saving a private key.';
		}
		return '';
	}

	function isAvailable() {
		return !availabilityError();
	}

	function getCrypto() {
		var error = availabilityError();
		if (error) {
			throw new Error(error);
		}
		var cryptoObj = (typeof globalThis !== 'undefined' && globalThis.crypto) || null;
		return cryptoObj;
	}

	function textEncoder() {
		return new TextEncoder();
	}

	function textDecoder() {
		return new TextDecoder();
	}

	function randomBytes(length) {
		var bytes = new Uint8Array(length);
		getCrypto().getRandomValues(bytes);
		return bytes;
	}

	function bytesToBase64(bytes) {
		var binary = '';
		var view = new Uint8Array(bytes);
		for (var index = 0; index < view.length; index += 1) {
			binary += String.fromCharCode(view[index]);
		}
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
		var normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
		while (normalized.length % 4) {
			normalized += '=';
		}
		return base64ToBytes(normalized);
	}

	function bytesToHex(bytes) {
		return Array.prototype.map.call(new Uint8Array(bytes), function (byte) {
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

	function aadBytes(metadata, purpose) {
		return textEncoder().encode(stableStringify({
			purpose: purpose,
			schemaVersion: metadata.schemaVersion || SCHEMA_VERSION,
			walletId: metadata.walletId,
			network: metadata.network || NETWORK,
			address: metadata.address,
			keyType: metadata.keyType || 'wif',
			createdAt: metadata.createdAt
		}));
	}

	function publicMetadata(record) {
		return {
			schemaVersion: record.schemaVersion,
			walletId: record.walletId,
			network: record.network,
			address: record.address,
			publicKey: record.publicKey || '',
			keyType: record.keyType,
			createdAt: record.createdAt
		};
	}

	function validatePassword(password) {
		var value = String(password || '');
		var lower = value.toLowerCase();
		if (value.length < 10) {
			return {
				ok: false,
				message: 'Use at least 10 characters for the wallet password.'
			};
		}
		if (COMMON_PASSWORDS.indexOf(lower) >= 0) {
			return {
				ok: false,
				message: 'Use a less common wallet password.'
			};
		}
		return {
			ok: true,
			message: ''
		};
	}

	function validatePin(pin) {
		var value = String(pin || '');
		if (!/^\d{6,}$/.test(value)) {
			return {
				ok: false,
				message: 'Use a numeric PIN with at least 6 digits.'
			};
		}
		return {
			ok: true,
			message: ''
		};
	}

	function importAesKey(raw, usages) {
		return getCrypto().subtle.importKey('raw', raw, {
			name: 'AES-GCM',
			length: 256
		}, false, usages || ['encrypt', 'decrypt']);
	}

	function deriveAesKey(secret, salt, iterations) {
		return getCrypto().subtle.importKey('raw', textEncoder().encode(secret), 'PBKDF2', false, ['deriveKey']).then(function (baseKey) {
			return getCrypto().subtle.deriveKey({
				name: 'PBKDF2',
				hash: 'SHA-256',
				salt: salt,
				iterations: iterations
			}, baseKey, {
				name: 'AES-GCM',
				length: 256
			}, false, ['encrypt', 'decrypt']);
		});
	}

	function aesEncrypt(key, plaintextBytes, aad) {
		var nonce = randomBytes(12);
		return getCrypto().subtle.encrypt({
			name: 'AES-GCM',
			iv: nonce,
			additionalData: aad,
			tagLength: 128
		}, key, plaintextBytes).then(function (ciphertext) {
			return {
				nonce: bytesToBase64(nonce),
				ciphertext: bytesToBase64(ciphertext)
			};
		});
	}

	function aesDecrypt(key, cipher, aad) {
		return getCrypto().subtle.decrypt({
			name: 'AES-GCM',
			iv: base64ToBytes(cipher.nonce),
			additionalData: aad,
			tagLength: 128
		}, key, base64ToBytes(cipher.ciphertext));
	}

	function makeWalletId() {
		var cryptoObj = getCrypto();
		if (typeof cryptoObj.randomUUID === 'function') {
			return cryptoObj.randomUUID();
		}
		var hex = bytesToHex(randomBytes(16));
		return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
	}

	function createVault(input, password, options) {
		return Promise.resolve().then(function () {
			options = options || {};
			var validation = validatePassword(password);
			if (!validation.ok) {
				throw new Error(validation.message);
			}
			var createdAt = input.createdAt || new Date().toISOString();
			var metadata = {
				schemaVersion: SCHEMA_VERSION,
				walletId: input.walletId || makeWalletId(),
				network: input.network || NETWORK,
				address: input.address,
				publicKey: input.publicKey || '',
				keyType: 'wif',
				createdAt: createdAt
			};
			var vaultKeyBytes = randomBytes(32);
			var iterations = options.iterations || DEFAULT_ITERATIONS;
			var salt = randomBytes(16);
			var updatedAt = new Date().toISOString();
			var vaultKey;
			var passwordKey;

			return importAesKey(vaultKeyBytes).then(function (key) {
				vaultKey = key;
				return deriveAesKey(password, salt, iterations);
			}).then(function (key) {
				passwordKey = key;
				return aesEncrypt(vaultKey, textEncoder().encode(input.privateKeyWif), aadBytes(metadata, 'private-key'));
			}).then(function (privateCipher) {
				return aesEncrypt(passwordKey, vaultKeyBytes, aadBytes(metadata, 'wrapped-vault-key')).then(function (wrappedCipher) {
					return {
						schemaVersion: metadata.schemaVersion,
						walletId: metadata.walletId,
						network: metadata.network,
						address: metadata.address,
						publicKey: metadata.publicKey,
						keyType: metadata.keyType,
						cipher: {
							name: 'AES-GCM',
							nonce: privateCipher.nonce,
							ciphertext: privateCipher.ciphertext,
							authTagIncluded: true
						},
						wrappedVaultKey: {
							kdf: 'PBKDF2-SHA256',
							iterations: iterations,
							salt: bytesToBase64(salt),
							nonce: wrappedCipher.nonce,
							ciphertext: wrappedCipher.ciphertext
						},
						quickUnlock: {
							enabled: false,
							version: 1
						},
						createdAt: createdAt,
						updatedAt: updatedAt
					};
				});
			});
		});
	}

	function getVaultKeyBytes(record, password) {
		var metadata = publicMetadata(record);
		var wrapped = record.wrappedVaultKey || {};
		return deriveAesKey(password, base64ToBytes(wrapped.salt), wrapped.iterations || DEFAULT_ITERATIONS).then(function (passwordKey) {
			return aesDecrypt(passwordKey, wrapped, aadBytes(metadata, 'wrapped-vault-key'));
		}).then(function (raw) {
			return new Uint8Array(raw);
		}).catch(function () {
			throw new Error('Wallet could not be unlocked.');
		});
	}

	function decryptWithVaultKey(record, vaultKeyBytes) {
		var metadata = publicMetadata(record);
		return importAesKey(vaultKeyBytes).then(function (vaultKey) {
			return aesDecrypt(vaultKey, record.cipher, aadBytes(metadata, 'private-key'));
		}).then(function (plaintext) {
			return textDecoder().decode(plaintext);
		}).catch(function () {
			throw new Error('Wallet could not be unlocked.');
		});
	}

	function decryptVault(record, password) {
		return getVaultKeyBytes(record, password).then(function (vaultKeyBytes) {
			return decryptWithVaultKey(record, vaultKeyBytes);
		});
	}

	function changePassword(record, oldPassword, newPassword, options) {
		options = options || {};
		var validation = validatePassword(newPassword);
		if (!validation.ok) {
			return Promise.reject(new Error(validation.message));
		}
		return getVaultKeyBytes(record, oldPassword).then(function (vaultKeyBytes) {
			var salt = randomBytes(16);
			var iterations = options.iterations || DEFAULT_ITERATIONS;
			return deriveAesKey(newPassword, salt, iterations).then(function (passwordKey) {
				return aesEncrypt(passwordKey, vaultKeyBytes, aadBytes(publicMetadata(record), 'wrapped-vault-key')).then(function (wrappedCipher) {
					var updated = JSON.parse(JSON.stringify(record));
					updated.wrappedVaultKey = {
						kdf: 'PBKDF2-SHA256',
						iterations: iterations,
						salt: bytesToBase64(salt),
						nonce: wrappedCipher.nonce,
						ciphertext: wrappedCipher.ciphertext
					};
					updated.updatedAt = new Date().toISOString();
					return updated;
				});
			});
		});
	}

	function wrapVaultKeyForPin(vaultKeyBytes, pin, deviceKey, metadata) {
		var validation = validatePin(pin);
		if (!validation.ok) {
			return Promise.reject(new Error(validation.message));
		}
		var pinSalt = randomBytes(16);
		return deriveAesKey(pin, pinSalt, PIN_ITERATIONS).then(function (pinKey) {
			return aesEncrypt(pinKey, vaultKeyBytes, aadBytes(metadata, 'quick-pin')).then(function (pinCipher) {
				return aesEncrypt(deviceKey, textEncoder().encode(JSON.stringify(pinCipher)), aadBytes(metadata, 'device-pin-wrap')).then(function (deviceCipher) {
					return {
						enabled: true,
						version: 1,
						kdf: 'PBKDF2-SHA256',
						iterations: PIN_ITERATIONS,
						salt: bytesToBase64(pinSalt),
						nonce: deviceCipher.nonce,
						ciphertext: deviceCipher.ciphertext,
						failures: 0,
						lockedUntil: 0,
						updatedAt: new Date().toISOString()
					};
				});
			});
		});
	}

	function unwrapVaultKeyWithPin(record, pin, deviceKey) {
		var quick = record.quickUnlock || {};
		if (!quick.enabled) {
			return Promise.reject(new Error('PIN unlock is not enabled.'));
		}
		var metadata = publicMetadata(record);
		return aesDecrypt(deviceKey, quick, aadBytes(metadata, 'device-pin-wrap')).then(function (pinCipherBytes) {
			var pinCipher = JSON.parse(textDecoder().decode(pinCipherBytes));
			return deriveAesKey(pin, base64ToBytes(quick.salt), quick.iterations || PIN_ITERATIONS).then(function (pinKey) {
				return aesDecrypt(pinKey, pinCipher, aadBytes(metadata, 'quick-pin'));
			});
		}).then(function (vaultKeyBytes) {
			return new Uint8Array(vaultKeyBytes);
		}).catch(function () {
			throw new Error('The password or PIN was not accepted.');
		});
	}

	function sha256Base64Url(value) {
		var bytes = typeof value === 'string' ? textEncoder().encode(value) : value;
		return getCrypto().subtle.digest('SHA-256', bytes).then(function (digest) {
			return bytesToBase64Url(digest);
		});
	}

	function sha256Hex(value) {
		var bytes = typeof value === 'string' ? textEncoder().encode(value) : value;
		return getCrypto().subtle.digest('SHA-256', bytes).then(function (digest) {
			return bytesToHex(digest);
		});
	}

	return {
		SCHEMA_VERSION: SCHEMA_VERSION,
		DEFAULT_ITERATIONS: DEFAULT_ITERATIONS,
		PIN_ITERATIONS: PIN_ITERATIONS,
		NETWORK: NETWORK,
		availabilityError: availabilityError,
		isAvailable: isAvailable,
		createVault: createVault,
		decryptVault: decryptVault,
		changePassword: changePassword,
		getVaultKeyBytes: getVaultKeyBytes,
		decryptWithVaultKey: decryptWithVaultKey,
		wrapVaultKeyForPin: wrapVaultKeyForPin,
		unwrapVaultKeyWithPin: unwrapVaultKeyWithPin,
		validatePassword: validatePassword,
		validatePin: validatePin,
		randomBytes: randomBytes,
		bytesToBase64: bytesToBase64,
		base64ToBytes: base64ToBytes,
		bytesToBase64Url: bytesToBase64Url,
		base64UrlToBytes: base64UrlToBytes,
		bytesToHex: bytesToHex,
		stableStringify: stableStringify,
		sha256Base64Url: sha256Base64Url,
		sha256Hex: sha256Hex
	};
}));
