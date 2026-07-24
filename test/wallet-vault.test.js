const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');

if (!globalThis.crypto) {
	Object.defineProperty(globalThis, 'crypto', {
		value: webcrypto
	});
}

const Vault = require('../wallet-vault.js');

const SAMPLE_WIF = 'cSampleSugarchainPrivateKeyForVaultTestsOnly000000000000000000';
const PASSWORD = 'correct horse battery staple';
const NEW_PASSWORD = 'longer sweet wallet phrase';
const WALLET = {
	privateKeyWif: SAMPLE_WIF,
	address: 'sugar1qtestsweetwalletaddress0000000000000000000000',
	publicKey: '03'.padEnd(66, '0'),
	walletId: 'test-wallet-id',
	network: Vault.NETWORK,
	createdAt: '2026-07-23T00:00:00.000Z'
};

test('encrypts the same private key to different ciphertext', async () => {
	const first = await Vault.createVault(WALLET, PASSWORD, { iterations: 1000 });
	const second = await Vault.createVault(WALLET, PASSWORD, { iterations: 1000 });

	assert.notEqual(first.cipher.ciphertext, second.cipher.ciphertext);
	assert.notEqual(first.cipher.nonce, second.cipher.nonce);
	assert.notEqual(first.wrappedVaultKey.salt, second.wrappedVaultKey.salt);
});

test('decrypts with the correct password and rejects the wrong password', async () => {
	const record = await Vault.createVault(WALLET, PASSWORD, { iterations: 1000 });

	assert.equal(await Vault.decryptVault(record, PASSWORD), SAMPLE_WIF);
	await assert.rejects(() => Vault.decryptVault(record, 'incorrect password'), /unlock/);
});

test('authenticates ciphertext and public metadata', async () => {
	const record = await Vault.createVault(WALLET, PASSWORD, { iterations: 1000 });
	const tamperedCiphertext = JSON.parse(JSON.stringify(record));
	const firstChar = tamperedCiphertext.cipher.ciphertext[0] === 'A' ? 'B' : 'A';
	tamperedCiphertext.cipher.ciphertext = firstChar + tamperedCiphertext.cipher.ciphertext.slice(1);

	await assert.rejects(() => Vault.decryptVault(tamperedCiphertext, PASSWORD), /unlock/);

	const tamperedMetadata = JSON.parse(JSON.stringify(record));
	tamperedMetadata.address = 'sugar1qotheraddress000000000000000000000000000';

	await assert.rejects(() => Vault.decryptVault(tamperedMetadata, PASSWORD), /unlock/);
});

test('does not serialize plaintext private key and can rewrap password', async () => {
	const record = await Vault.createVault(WALLET, PASSWORD, { iterations: 1000 });
	const serialized = JSON.stringify(record);

	assert.equal(serialized.includes(SAMPLE_WIF), false);

	const updated = await Vault.changePassword(record, PASSWORD, NEW_PASSWORD, { iterations: 1000 });
	assert.equal(await Vault.decryptVault(updated, NEW_PASSWORD), SAMPLE_WIF);
	await assert.rejects(() => Vault.decryptVault(updated, PASSWORD), /unlock/);
});

test('rejects cleanly when browser crypto is not in a secure context', async () => {
	const hadSecureContext = Object.prototype.hasOwnProperty.call(globalThis, 'isSecureContext');
	const originalSecureContext = globalThis.isSecureContext;
	Object.defineProperty(globalThis, 'isSecureContext', {
		value: false,
		configurable: true
	});

	try {
		assert.match(Vault.availabilityError(), /HTTPS or localhost/);
		await assert.rejects(() => Vault.createVault(WALLET, PASSWORD, { iterations: 1000 }), /HTTPS or localhost/);
	} finally {
		if (hadSecureContext) {
			Object.defineProperty(globalThis, 'isSecureContext', {
				value: originalSecureContext,
				configurable: true
			});
		} else {
			delete globalThis.isSecureContext;
		}
	}
});
