'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { IDBFactory } = require('fake-indexeddb');
const KeylinkStorage = require('../keylink-storage.js');

function requestResult(request) {
	return new Promise((resolve, reject) => {
		request.onsuccess = () => resolve(request.result);
		request.onerror = () => reject(request.error);
	});
}

async function seedLegacyDatabase(indexedDB, ownerId, secretId) {
	const request = indexedDB.open(KeylinkStorage.DB_NAME, 1);
	request.onupgradeneeded = () => {
		const database = request.result;
		const identities = database.createObjectStore('identities', { keyPath: 'ownerId' });
		const secrets = database.createObjectStore('secrets', { keyPath: 'localId' });
		identities.put({
			ownerId,
			publicKey: 'legacy-public-key',
			privateKey: 'legacy-private-key',
			createdAt: '2026-08-01T00:00:00.000Z'
		});
		secrets.put({
			localId: ownerId + ':' + secretId,
			ownerId,
			secretId,
			label: 'Preserved secret',
			createdAt: '2026-08-01T00:00:00.000Z'
		});
	};
	const database = await requestResult(request);
	database.close();
}

test('upgrades legacy inline key paths into Safari-safe out-of-line stores', async () => {
	const indexedDB = new IDBFactory();
	const ownerId = 'sugar1qlegacyowner';
	const secretId = 'ab'.repeat(16);
	await seedLegacyDatabase(indexedDB, ownerId, secretId);

	const storage = KeylinkStorage.createStorage(indexedDB);
	const identity = await storage.getIdentity(ownerId);
	assert.equal(identity.owner_id, ownerId);
	assert.equal(identity.public_key, 'legacy-public-key');
	assert.equal(identity.private_key, 'legacy-private-key');

	const secrets = await storage.getOwnerRecords(ownerId);
	assert.equal(secrets.length, 1);
	assert.equal(secrets[0].local_id, ownerId + ':' + secretId);
	assert.equal(secrets[0].secret_id, secretId);
	assert.equal(secrets[0].label, 'Preserved secret');

	await storage.putIdentity({
		owner_id: ownerId,
		public_key: 'updated-public-key',
		private_key_jwk: JSON.stringify({ kty: 'OKP', crv: 'X25519', d: 'private', x: 'public' }),
		private_key: 'must-not-be-persisted'
	});
	const updated = await storage.getIdentity(ownerId);
	assert.equal(updated.public_key, 'updated-public-key');
	assert.equal(updated.private_key, null);
	assert.match(updated.private_key_jwk, /"X25519"/);

	const upgraded = await requestResult(indexedDB.open(KeylinkStorage.DB_NAME, KeylinkStorage.DB_VERSION));
	assert.equal(upgraded.transaction(KeylinkStorage.IDENTITY_STORE).objectStore(KeylinkStorage.IDENTITY_STORE).keyPath, null);
	assert.equal(upgraded.transaction(KeylinkStorage.SECRET_STORE).objectStore(KeylinkStorage.SECRET_STORE).keyPath, null);
	upgraded.close();
	await storage.close();
});

test('rejects new records before IndexedDB can receive a missing inline key', async () => {
	const storage = KeylinkStorage.createStorage(new IDBFactory());
	await assert.rejects(
		storage.putRecord('sugar1qowner', { label: 'Missing secret id' }),
		/missing its local storage key/
	);
	await storage.close();
});
