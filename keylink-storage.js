(function (root, factory) {
	'use strict';
	var api = factory();
	if (typeof module === 'object' && module.exports) {
		module.exports = api;
	}
	if (root && root.indexedDB) {
		root.SweetWalletKeylinkStorage = api.createStorage(root.indexedDB);
	}
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
	'use strict';

	var DB_NAME = 'sweetwallet_keylink_v1';
	var DB_VERSION = 3;
	var IDENTITY_STORE = 'identities_v3';
	var SECRET_STORE = 'secrets_v3';
	var LEGACY_IDENTITY_STORES = ['identities_v2', 'identities'];
	var LEGACY_SECRET_STORES = ['secrets_v2', 'secrets'];

	function text(value) {
		return String(value === undefined || value === null ? '' : value).trim();
	}

	function normalizeIdentity(record, primaryKey) {
		var source = record && typeof record === 'object' ? record : {};
		var ownerId = text(source.owner_id || source.ownerId || primaryKey);
		if (!ownerId) { return null; }
		return Object.assign({}, source, {
			owner_id: ownerId,
			public_key: source.public_key || source.publicKey || '',
			private_key: source.private_key || source.privateKey || null,
			private_key_jwk: source.private_key_jwk || source.privateKeyJwk || '',
			created_at: source.created_at || source.createdAt || new Date().toISOString(),
			updated_at: source.updated_at || source.updatedAt || new Date().toISOString()
		});
	}

	function serializedIdentity(record, primaryKey) {
		var normalized = normalizeIdentity(record, primaryKey);
		if (!normalized || !normalized.public_key || !normalized.private_key_jwk) { return null; }
		var persisted = Object.assign({}, normalized, {
			private_key_jwk: typeof normalized.private_key_jwk === 'string' ?
				normalized.private_key_jwk : JSON.stringify(normalized.private_key_jwk)
		});
		delete persisted.private_key;
		delete persisted.privateKey;
		delete persisted.publicKey;
		delete persisted.privateKeyJwk;
		return persisted;
	}

	function normalizeSecret(record, primaryKey, ownerId) {
		var source = record && typeof record === 'object' ? record : {};
		var normalizedOwner = text(source.owner_id || source.ownerId || ownerId);
		var secretId = text(source.secret_id || source.secretId).toLowerCase();
		var localId = text(source.local_id || source.localId || primaryKey);
		if (!localId && normalizedOwner && secretId) { localId = normalizedOwner + ':' + secretId; }
		if (!localId || !normalizedOwner || !secretId) { return null; }
		return Object.assign({}, source, {
			local_id: localId,
			owner_id: normalizedOwner,
			secret_id: secretId,
			created_at: source.created_at || source.createdAt || new Date().toISOString(),
			updated_at: source.updated_at || source.updatedAt || source.created_at || source.createdAt || new Date().toISOString()
		});
	}

	function migrateStore(transaction, sourceName, targetStore, normalize, keyForRecord) {
		if (!transaction.db.objectStoreNames.contains(sourceName)) { return; }
		var cursorRequest = transaction.objectStore(sourceName).openCursor();
		cursorRequest.onsuccess = function () {
			var cursor = cursorRequest.result;
			if (!cursor) { return; }
			var normalized = normalize(cursor.value, cursor.primaryKey);
			var key = normalized && keyForRecord(normalized);
			if (normalized && key) { targetStore.put(normalized, key); }
			cursor.continue();
		};
	}

	function createStorage(indexedDb) {
		if (!indexedDb || typeof indexedDb.open !== 'function') {
			throw new Error('This browser cannot store the local Keylink identity.');
		}

		function openDatabase() {
			return new Promise(function (resolve, reject) {
				var request = indexedDb.open(DB_NAME, DB_VERSION);
				request.onupgradeneeded = function () {
					var database = request.result;
					var transaction = request.transaction;
					var identityStore = database.objectStoreNames.contains(IDENTITY_STORE) ?
						transaction.objectStore(IDENTITY_STORE) :
						database.createObjectStore(IDENTITY_STORE);
					var secretStore = database.objectStoreNames.contains(SECRET_STORE) ?
						transaction.objectStore(SECRET_STORE) :
						database.createObjectStore(SECRET_STORE);
					LEGACY_IDENTITY_STORES.forEach(function (storeName) {
						migrateStore(transaction, storeName, identityStore, serializedIdentity, function (record) { return record.owner_id; });
					});
					LEGACY_SECRET_STORES.forEach(function (storeName) {
						migrateStore(transaction, storeName, secretStore, function (record, primaryKey) {
							return normalizeSecret(record, primaryKey);
						}, function (record) { return record.local_id; });
					});
				};
				request.onsuccess = function () { resolve(request.result); };
				request.onerror = function () { reject(request.error || new Error('Keylink storage could not open.')); };
				request.onblocked = function () { reject(new Error('Close other SweetWallet tabs, then reopen Keylink to finish its storage upgrade.')); };
			});
		}

		function dbRequest(storeName, mode, operation) {
			return openDatabase().then(function (database) {
				return new Promise(function (resolve, reject) {
					var settled = false;
					var result;
					var transaction;
					var request;
					try {
						transaction = database.transaction(storeName, mode);
						request = operation(transaction.objectStore(storeName));
					} catch (error) {
						database.close();
						reject(error);
						return;
					}
					request.onsuccess = function () { result = request.result; };
					request.onerror = function () {
						if (!settled) { settled = true; reject(request.error || new Error('Keylink storage operation failed.')); }
					};
					transaction.oncomplete = function () {
						database.close();
						if (!settled) { settled = true; resolve(result); }
					};
					transaction.onabort = transaction.onerror = function () {
						database.close();
						if (!settled) { settled = true; reject(transaction.error || new Error('Keylink storage transaction failed.')); }
					};
				});
			});
		}

		function optionalGet(storeName, key) {
			return openDatabase().then(function (database) {
				if (!database.objectStoreNames.contains(storeName)) {
					database.close();
					return null;
				}
				return new Promise(function (resolve, reject) {
					var transaction = database.transaction(storeName, 'readonly');
					var request = transaction.objectStore(storeName).get(key);
					var result = null;
					request.onsuccess = function () { result = request.result || null; };
					request.onerror = function () { reject(request.error || new Error('Legacy Keylink identity could not be read.')); };
					transaction.oncomplete = function () { database.close(); resolve(result); };
					transaction.onabort = transaction.onerror = function () {
						database.close();
						reject(transaction.error || new Error('Legacy Keylink identity transaction failed.'));
					};
				});
			});
		}

		function getLegacyIdentity(ownerId, index) {
			if (index >= LEGACY_IDENTITY_STORES.length) { return Promise.resolve(null); }
			return optionalGet(LEGACY_IDENTITY_STORES[index], ownerId).then(function (record) {
				return record ? normalizeIdentity(record, ownerId) : getLegacyIdentity(ownerId, index + 1);
			});
		}

		return {
			getIdentity: function (ownerId) {
				return dbRequest(IDENTITY_STORE, 'readonly', function (store) { return store.get(ownerId); })
					.then(function (record) { return record ? normalizeIdentity(record, ownerId) : getLegacyIdentity(ownerId, 0); });
			},
			putIdentity: function (record) {
				var persisted = serializedIdentity(record);
				if (!persisted) {
					return Promise.reject(new Error('Keylink encryption identity is not serialized for Safari-safe storage.'));
				}
				return dbRequest(IDENTITY_STORE, 'readwrite', function (store) { return store.put(persisted, persisted.owner_id); });
			},
			getOwnerRecords: function (ownerId) {
				return dbRequest(SECRET_STORE, 'readonly', function (store) { return store.getAll(); })
					.then(function (records) {
						return records.map(function (record) { return normalizeSecret(record, record.local_id, ownerId); })
							.filter(function (record) { return record && record.owner_id === ownerId; });
					});
			},
			putRecord: function (ownerId, record) {
				var normalized = normalizeSecret(record, null, ownerId);
				if (!normalized) { return Promise.reject(new Error('Keylink record is missing its local storage key.')); }
				return dbRequest(SECRET_STORE, 'readwrite', function (store) { return store.put(normalized, normalized.local_id); });
			},
			close: function () {
				return openDatabase().then(function (database) { database.close(); });
			}
		};
	}

	return {
		DB_NAME: DB_NAME,
		DB_VERSION: DB_VERSION,
		IDENTITY_STORE: IDENTITY_STORE,
		SECRET_STORE: SECRET_STORE,
		createStorage: createStorage,
		normalizeIdentity: normalizeIdentity,
		serializedIdentity: serializedIdentity,
		normalizeSecret: normalizeSecret
	};
}));
