'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
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

test('PIN-required Keylink URI exposes only the requirement flag', () => {
	const id = '83f2c1a4264b81cd67cc037391ab72ef';
	const uri = Keylink.createSecretUri(id, true);
	assert.equal(uri, `keylink://secret/${id}?pin=1`);
	assert.deepEqual(Keylink.parseSecretUriDetails(uri), { secretId: id, pinRequired: true });
	assert.deepEqual(Keylink.parseSecretUriDetails(Keylink.createSecretUri(id)), { secretId: id, pinRequired: false });
	assert.equal(uri.includes('483921'), false);
});

test('Keylink PIN generation is secure, six-digit, and preserves leading zeroes', () => {
	const pins = Array.from({ length: 2000 }, () => Keylink.generatePin());
	assert.equal(pins.every((pin) => /^\d{6}$/.test(pin)), true);
	assert.equal(pins.some((pin) => pin.startsWith('0')), true);
	assert.equal(new Set(pins).size > 1, true);
	assert.doesNotMatch(fs.readFileSync(require.resolve('../keylink-crypto.js'), 'utf8'), /Math\.random\s*\(/);
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

test('X25519 private identity survives JSON serialization without IndexedDB CryptoKey cloning', async () => {
	const identity = await Keylink.generateIdentity();
	const serialized = JSON.stringify(await Keylink.exportPrivateKey(identity.privateKey));
	const restoredPrivate = await Keylink.importPrivateKey(serialized);
	const owner = sugarIdentity(9);
	const encrypted = await Keylink.encryptSecret('Safari-safe identity');
	const publicKey = await Keylink.exportPublicKey(identity.publicKey);
	const envelope = await Keylink.wrapContentKey(encrypted.contentKey, publicKey, encrypted.encryptedSecret.secret_id, owner.address, 1);
	const restoredContentKey = await Keylink.unwrapContentKey(envelope, { privateKey: restoredPrivate, publicKey: identity.publicKey });
	assert.equal(await Keylink.decryptSecret(encrypted.encryptedSecret, restoredContentKey), 'Safari-safe identity');
	encrypted.contentKey.fill(0);
	restoredContentKey.fill(0);
});

test('imported X25519 public key remains extractable and can be re-exported', async () => {
	const identity = await Keylink.generateIdentity();
	const serialized = await Keylink.exportPublicKey(identity.publicKey);
	const imported = await Keylink.importPublicKey(serialized);
	assert.equal(imported.extractable, true);
	assert.equal(await Keylink.exportPublicKey(imported), serialized);
});

test('reloaded X25519 identity can unwrap and view an existing secret', async () => {
	const owner = sugarIdentity(10);
	let identity = await Keylink.generateIdentity();
	const storedPublicKey = await Keylink.exportPublicKey(identity.publicKey);
	const storedPrivateKey = JSON.stringify(await Keylink.exportPrivateKey(identity.privateKey));
	const encrypted = await Keylink.encryptSecret('Persisted owner can still view this secret.');
	const envelope = await Keylink.wrapContentKey(
		encrypted.contentKey,
		storedPublicKey,
		encrypted.encryptedSecret.secret_id,
		owner.address,
		1
	);

	identity = null;
	const reloadedIdentity = {
		publicKey: await Keylink.importPublicKey(storedPublicKey),
		privateKey: await Keylink.importPrivateKey(storedPrivateKey)
	};
	const restoredContentKey = await Keylink.unwrapContentKey(envelope, reloadedIdentity);
	assert.equal(
		await Keylink.decryptSecret(encrypted.encryptedSecret, restoredContentKey),
		'Persisted owner can still view this secret.'
	);

	encrypted.contentKey.fill(0);
	restoredContentKey.fill(0);
});

test('reloaded owner can rewrap an existing secret for a new owner', async () => {
	const ownerA = sugarIdentity(11);
	const ownerB = sugarIdentity(12);
	let identityA = await Keylink.generateIdentity();
	const identityB = await Keylink.generateIdentity();
	const storedPublicA = await Keylink.exportPublicKey(identityA.publicKey);
	const storedPrivateA = JSON.stringify(await Keylink.exportPrivateKey(identityA.privateKey));
	const publicB = await Keylink.exportPublicKey(identityB.publicKey);
	const plaintext = 'Reloaded owner can approve this ownership transfer.';
	const encrypted = await Keylink.encryptSecret(plaintext);
	const envelopeA = await Keylink.wrapContentKey(
		encrypted.contentKey,
		storedPublicA,
		encrypted.encryptedSecret.secret_id,
		ownerA.address,
		1
	);

	identityA = null;
	const reloadedIdentityA = {
		publicKey: await Keylink.importPublicKey(storedPublicA),
		privateKey: await Keylink.importPrivateKey(storedPrivateA)
	};
	const ownerContentKey = await Keylink.unwrapContentKey(envelopeA, reloadedIdentityA);
	const plaintextBeforeTransfer = await Keylink.decryptSecret(encrypted.encryptedSecret, ownerContentKey);
	ownerContentKey.fill(0);

	const envelopeB = await Keylink.rewrapOwnerEnvelope(
		envelopeA,
		reloadedIdentityA,
		publicB,
		ownerB.address,
		2
	);
	const buyerContentKey = await Keylink.unwrapContentKey(envelopeB, identityB);
	const plaintextAfterTransfer = await Keylink.decryptSecret(encrypted.encryptedSecret, buyerContentKey);
	assert.equal(plaintextBeforeTransfer, plaintext);
	assert.equal(plaintextAfterTransfer, plaintextBeforeTransfer);

	encrypted.contentKey.fill(0);
	buyerContentKey.fill(0);
});

test('active Keylink PIN is encrypted for the current owner in local storage', async () => {
	const owner = sugarIdentity(13);
	const identity = await Keylink.generateIdentity();
	const secretId = '45'.repeat(16);
	const protectedPin = await Keylink.protectLocalPin('004281', identity, secretId, owner.address, 2);
	assert.equal(JSON.stringify(protectedPin).includes('004281'), false);
	assert.equal(await Keylink.revealLocalPin(protectedPin, identity, secretId, owner.address, 2), '004281');
	await assert.rejects(Keylink.revealLocalPin(protectedPin, identity, secretId, owner.address, 3), /does not match/);
});

test('Keylink UI exposes opt-in PIN controls and keeps autoapproval state-bound', () => {
	const html = fs.readFileSync(require.resolve('../index.html'), 'utf8');
	const client = fs.readFileSync(require.resolve('../keylink.js'), 'utf8');
	assert.match(html, /id="keylinkRequirePin"/);
	assert.match(html, /id="keylinkCreatePinValue"/);
	assert.match(html, /id="keylinkCreateAutoapprove"[^>]*checked/);
	assert.match(client, /state_version:\s*Number\(remote\.state_version\)/);
	assert.match(client, /PIN_AUTOAPPROVE_ADVANCE_AUTHORIZATION/);
	assert.match(client, /request\.pin_verified === true && request\.autoapprove_reserved === true/);
	assert.match(client, /navigator\.onLine === false/);
	assert.match(html, /id="keylinkDisablePinModal"/);
	assert.match(html, /id="keylinkSentModal"/);
	assert.match(html, /id="keylinkSentAddress"/);
	assert.doesNotMatch(client, /window\.confirm\('Disable PIN protection and invalidate the active PIN\?'\)/);
	assert.match(client, /showSentNotification\(pending\.transfer\.secret_id, pending\.transfer\.to\)/);
	assert.doesNotMatch(client, /Keylink transferred automatically\./);
	assert.doesNotMatch(client, /PIN protection enabled\. Autoapprove is on by default\./);
	assert.doesNotMatch(client, /PIN protection disabled\./);
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
