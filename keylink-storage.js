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
	var DB_VERSION = 2;
	var IDENTITY_STORE = 'identities_v2';
	var SECRET_STORE = 'secrets_v2';
	var LEGACY_IDENTITY_STORE = 'identities';
	var LEGACY_SECRET_STORE = 'secrets';

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
			created_at: source.created_at || source.createdAt || new Date().toISOString(),
			updated_at: source.updated_at || source.updatedAt || new Date().toISOString()
		});
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

	function migrateStore(transaction, sourceName, targetStore, normalize) {
		if (!transaction.db.objectStoreNames.contains(sourceName)) { return; }
		var cursorRequest = transaction.objectStore(sourceName).openCursor();
		cursorRequest.onsuccess = function () {
			var cursor = cursorRequest.result;
			if (!cursor) { return; }
			var normalized = normalize(cursor.value, cursor.primaryKey);
			if (normalized) { targetStore.put(normalized); }
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
						database.createObjectStore(IDENTITY_STORE, { keyPath: 'owner_id' });
					var secretStore;
					if (database.objectStoreNames.contains(SECRET_STORE)) {
						secretStore = transaction.objectStore(SECRET_STORE);
					} else {
						secretStore = database.createObjectStore(SECRET_STORE, { keyPath: 'local_id' });
						secretStore.createIndex('owner_id', 'owner_id', { unique: false });
						secretStore.createIndex('secret_id', 'secret_id', { unique: false });
						secretStore.createIndex('updated_at', 'updated_at', { unique: false });
					}
					migrateStore(transaction, LEGACY_IDENTITY_STORE, identityStore, normalizeIdentity);
					migrateStore(transaction, LEGACY_SECRET_STORE, secretStore, function (record, primaryKey) {
						return normalizeSecret(record, primaryKey);
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

		return {
			getIdentity: function (ownerId) {
				return dbRequest(IDENTITY_STORE, 'readonly', function (store) { return store.get(ownerId); })
					.then(function (record) { return record ? normalizeIdentity(record, ownerId) : null; });
			},
			putIdentity: function (record) {
				var normalized = normalizeIdentity(record);
				if (!normalized || !normalized.public_key || !normalized.private_key) {
					return Promise.reject(new Error('Keylink encryption identity is incomplete.'));
				}
				return dbRequest(IDENTITY_STORE, 'readwrite', function (store) { return store.put(normalized); });
			},
			getOwnerRecords: function (ownerId) {
				return dbRequest(SECRET_STORE, 'readonly', function (store) { return store.index('owner_id').getAll(ownerId); })
					.then(function (records) {
						return records.map(function (record) { return normalizeSecret(record, record.local_id, ownerId); }).filter(Boolean);
					});
			},
			putRecord: function (ownerId, record) {
				var normalized = normalizeSecret(record, null, ownerId);
				if (!normalized) { return Promise.reject(new Error('Keylink record is missing its local storage key.')); }
				return dbRequest(SECRET_STORE, 'readwrite', function (store) { return store.put(normalized); });
			},
			close: function () {
				return openDatabase().then(function (database) { database.close(); });
			}
		};
	}

	return {
		DB_NAME: DB_NAME,
		DB_VERSION: DB_VERSION,
		createStorage: createStorage,
		normalizeIdentity: normalizeIdentity,
		normalizeSecret: normalizeSecret
	};
}));
