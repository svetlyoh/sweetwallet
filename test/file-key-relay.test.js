const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');

if (!globalThis.crypto) {
	globalThis.crypto = webcrypto;
}

const RelayCrypto = require('../file-key-relay-crypto.js');

test('recipient key URI round-trips a 32-byte X25519 public key', async () => {
	const pair = await RelayCrypto.generateKeyPair();
	const publicKey = await RelayCrypto.exportPublicKey(pair.publicKey);
	const uri = RelayCrypto.createRecipientUri(publicKey, 'Mobile wallet');
	const parsed = RelayCrypto.parseRecipientPublicKey(uri);

	assert.equal(parsed.publicKey, publicKey);
	assert.equal(parsed.label, 'Mobile wallet');
	assert.match(uri, /^sugarfilekey:\/\/recipient\?v=1&enc_pubkey=/);
});

test('relay capsule encrypts and decrypts a file only for the matching key', async () => {
	const recipient = await RelayCrypto.generateKeyPair();
	const recipientPublic = await RelayCrypto.exportPublicKey(recipient.publicKey);
	const plaintext = new TextEncoder().encode('Sugarchain File Key Relay test payload');
	const encrypted = await RelayCrypto.encryptRelay({
		fileBytes: plaintext,
		fileName: 'relay-test.txt',
		fileType: 'text/plain',
		recipientPublicKey: recipientPublic,
		recipientLabel: 'Test recipient',
		note: 'public note',
		relayMode: 'sugarchain'
	});
	const payload = RelayCrypto.withTransaction(encrypted.payload, 'ab'.repeat(32));
	const validated = await RelayCrypto.validateRelayPayload(payload);
	const fileKey = await RelayCrypto.unwrapFileKey(validated, recipient.privateKey, recipientPublic);
	const decrypted = await RelayCrypto.decryptFile(validated, fileKey, encrypted.encryptedFile);

	assert.deepEqual(decrypted, plaintext);
	assert.equal(fileKey.length, 32);
	assert.equal(validated.file_cipher, 'AES-256-GCM');
	assert.equal(RelayCrypto.createAnchorHeader(validated).length, 71);
	assert.ok(new TextEncoder().encode(RelayCrypto.createAnchorHeader(validated)).length <= 80);
	assert.ok(!encrypted.relayUri.includes('Sugarchain File Key Relay test payload'));

	fileKey.fill(0);
});

test('relay capsule rejects a different recipient encryption key', async () => {
	const intended = await RelayCrypto.generateKeyPair();
	const other = await RelayCrypto.generateKeyPair();
	const intendedPublic = await RelayCrypto.exportPublicKey(intended.publicKey);
	const otherPublic = await RelayCrypto.exportPublicKey(other.publicKey);
	const encrypted = await RelayCrypto.encryptRelay({
		fileBytes: new Uint8Array([1, 2, 3, 4]),
		fileName: 'private.bin',
		recipientPublicKey: intendedPublic,
		relayMode: 'offchain'
	});

	await assert.rejects(
		RelayCrypto.unwrapFileKey(encrypted.payload, other.privateKey, otherPublic),
		/was not encrypted for this wallet/
	);
});

test('relay capsule rejects manifest tampering', async () => {
	const recipient = await RelayCrypto.generateKeyPair();
	const recipientPublic = await RelayCrypto.exportPublicKey(recipient.publicKey);
	const encrypted = await RelayCrypto.encryptRelay({
		fileBytes: new Uint8Array([9, 8, 7]),
		fileName: 'manifest.bin',
		recipientPublicKey: recipientPublic,
		relayMode: 'offchain'
	});
	const tampered = Object.assign({}, encrypted.payload, { note: 'changed after creation' });

	await assert.rejects(RelayCrypto.validateRelayPayload(tampered), /manifest hash does not match/);
});

test('relay encryption key backup is password-encrypted and importable', async () => {
	const pair = await RelayCrypto.generateKeyPair();
	const publicKey = await RelayCrypto.exportPublicKey(pair.publicKey);
	const backup = await RelayCrypto.exportEncryptedKeyBackup(
		pair.privateKey,
		publicKey,
		'cd'.repeat(32),
		'correct horse battery staple'
	);
	const imported = await RelayCrypto.importEncryptedKeyBackup(backup, 'correct horse battery staple');

	assert.equal(imported.publicKey, publicKey);
	assert.equal(imported.ownerAddressHash, 'cd'.repeat(32));
	assert.ok(backup.ciphertext);
	assert.equal(Object.prototype.hasOwnProperty.call(backup, 'privateKey'), false);
	await assert.rejects(
		RelayCrypto.importEncryptedKeyBackup(backup, 'incorrect password'),
		/password was not accepted|file is damaged/
	);
});

test('transaction inspection finds the exact SGF1 anchor in script hex', () => {
	const anchor = 'SGF1|' + '01'.repeat(8) + '|' + '02'.repeat(16) + '|' + '03'.repeat(8);
	const scriptHex = '6a47' + Buffer.from(anchor, 'utf8').toString('hex');
	assert.equal(RelayCrypto.transactionContainsAnchor({ vout: [{ scriptPubKey: { hex: scriptHex } }] }, anchor), true);
	assert.equal(RelayCrypto.transactionContainsAnchor({ vout: [] }, anchor), false);
});
