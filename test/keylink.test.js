'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const bitcoin = require('bitcoinjs-lib');
const Keylink = require('../keylink-crypto.js');

const sugarNetwork = {
	messagePrefix: '\x19Sugarchain Signed Message:\n',
	bip32: { public: 0x0488b21e, private: 0x0488ade4 },
	bech32: 'sugar', pubKeyHash: 0x3F, scriptHash: 0x7D, wif: 0x80
};

function sugarIdentity(fill) {
	const keys = bitcoin.ECPair.fromPrivateKey(Buffer.alloc(32, fill), { network: sugarNetwork });
	return {
		keys,
		address: bitcoin.payments.p2wpkh({ pubkey: keys.publicKey, network: sugarNetwork }).address,
		publicKey: keys.publicKey.toString('hex')
	};
}

async function sign(record, identity) {
	const digest = await Keylink.sha256Bytes(Keylink.stableStringify(Keylink.unsignedRecord(record)));
	return Object.assign({}, record, { signature: identity.keys.sign(Buffer.from(digest)).toString('hex') });
}

test('permanent Keylink URI contains only a stable random Secret ID', () => {
	const id = Keylink.createSecretId();
	const uri = Keylink.createSecretUri(id);
	assert.match(id, /^[0-9a-f]{32}$/);
	assert.equal(uri, `keylink://secret/${id}`);
	assert.equal(Keylink.parseSecretUri(uri), id);
	assert.equal(Keylink.parseSecretUri(id.toUpperCase()), id);
	assert.equal(uri.includes('meeting'), false);
});

test('secret stays encrypted while its content key moves between X25519 owners', async () => {
	const ownerA = sugarIdentity(1);
	const ownerB = sugarIdentity(2);
	const identityA = await Keylink.generateIdentity();
	const identityB = await Keylink.generateIdentity();
	const encrypted = await Keylink.encryptSecret('The meeting is behind the north entrance.');
	const publicA = await Keylink.exportPublicKey(identityA.publicKey);
	const publicB = await Keylink.exportPublicKey(identityB.publicKey);
	const envelopeA = await Keylink.wrapContentKey(encrypted.contentKey, publicA, encrypted.encryptedSecret.secret_id, ownerA.address, 1);
	const firstKey = await Keylink.unwrapContentKey(envelopeA, identityA);
	assert.equal(await Keylink.decryptSecret(encrypted.encryptedSecret, firstKey), 'The meeting is behind the north entrance.');

	const envelopeB = await Keylink.rewrapOwnerEnvelope(envelopeA, identityA, publicB, ownerB.address, 2);
	const secondKey = await Keylink.unwrapContentKey(envelopeB, identityB);
	assert.equal(await Keylink.decryptSecret(encrypted.encryptedSecret, secondKey), 'The meeting is behind the north entrance.');
	await assert.rejects(Keylink.unwrapContentKey(envelopeB, identityA), /not authorized/);
	assert.equal(Keylink.createSecretUri(envelopeA.secret_id), Keylink.createSecretUri(envelopeB.secret_id));

	encrypted.contentKey.fill(0);
	firstKey.fill(0);
	secondKey.fill(0);
});

test('secret length is capped at 300 characters', async () => {
	await Keylink.encryptSecret('x'.repeat(300));
	await assert.rejects(Keylink.encryptSecret('x'.repeat(301)), /at most 300/);
});

test('KLT1 is a deterministic 76-byte binary ownership anchor', async () => {
	const ownerA = sugarIdentity(3);
	const ownerB = sugarIdentity(4);
	const ownerBEncryption = await Keylink.generateIdentity();
	const secretId = '0123456789abcdeffedcba9876543210';
	const contentKey = crypto.getRandomValues(new Uint8Array(32));
	const envelope = await Keylink.wrapContentKey(contentKey, await Keylink.exportPublicKey(ownerBEncryption.publicKey), secretId, ownerB.address, 2);
	const transfer = await sign({
		protocol: 'KEYLINK1', type: 'ownership_transfer', secret_id: secretId,
		from: ownerA.address, to: ownerB.address, request_id: '11'.repeat(16),
		previous_state_version: 1, new_state_version: 2,
		timestamp: new Date().toISOString(), nonce: '22'.repeat(16),
		authorization: { policy: 'CURRENT_OWNER_MANUAL_APPROVAL', provider: 'ManualOwnerApprovalProvider', decision: 'approved' },
		owner_public_key: ownerA.publicKey, new_owner_envelope: envelope
	}, ownerA);
	const WorkerProtocol = await import('../keylink-worker-protocol.mjs');
	await WorkerProtocol.verifySignedRecord(transfer, ownerA.address, ownerA.publicKey);
	assert.equal(WorkerProtocol.addressesForPublicKey(ownerA.publicKey)[0], ownerA.address);
	const payload = await Keylink.createKlt1Payload(transfer);
	const browserHex = await Keylink.createKlt1Hex(transfer);
	const workerHex = await WorkerProtocol.createKlt1Hex(transfer);
	assert.equal(payload.length, 76);
	assert.equal(Buffer.from(payload.subarray(0, 4)).toString('ascii'), 'KLT1');
	assert.equal(Buffer.from(payload.subarray(4, 20)).toString('hex'), secretId);
	assert.equal(new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(40, false), 2);
	assert.equal(browserHex.length, 152);
	assert.equal(workerHex, browserHex);
	assert.equal(WorkerProtocol.transactionContainsKlt1({ result: { vout: [{ script: `6a4c4c${browserHex}` }] } }, browserHex), true);
	contentKey.fill(0);
});
