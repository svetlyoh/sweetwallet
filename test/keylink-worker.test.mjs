import { env, exports as workerExports } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import { reset } from 'cloudflare:test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { Buffer } from 'node:buffer';
import { addressesForPublicKey, sha256Bytes, stableStringify, unsignedRecord } from '../keylink-worker-protocol.mjs';

function identity(fill) {
	const privateKey = new Uint8Array(32).fill(fill);
	const publicKey = Buffer.from(secp256k1.getPublicKey(privateKey, true)).toString('hex');
	return {
		privateKey,
		address: addressesForPublicKey(publicKey)[0],
		publicKey
	};
}

function b64(length, fill) {
	return Buffer.alloc(length, fill).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function signed(record, actor) {
	const digest = await sha256Bytes(stableStringify(unsignedRecord(record)));
	return { ...record, signature: Buffer.from(secp256k1.sign(digest, actor.privateKey, { prehash: false, format: 'compact' })).toString('hex') };
}

function ownerEnvelope(secretId, owner, version, fill) {
	return {
		protocol: 'KEYLINK1', type: 'owner_envelope', secret_id: secretId, owner_id: owner,
		state_version: version, cipher: 'X25519-HKDF-SHA256+A256GCM',
		recipient_key_hash: b64(32, fill), ephemeral_public: b64(32, fill + 1),
		salt: b64(16, fill + 2), nonce: b64(12, fill + 3), ciphertext: b64(48, fill + 4)
	};
}

async function registration(secretId, owner) {
	return signed({
		protocol: 'KEYLINK1', type: 'secret_registration', secret_id: secretId,
		created_by: owner.address, current_owner: owner.address, owner_public_key: owner.publicKey,
		owner_encryption_key: b64(32, 7),
		encrypted_secret: { protocol: 'KEYLINK1', type: 'encrypted_secret', secret_id: secretId, cipher: 'AES-256-GCM', nonce: b64(12, 8), ciphertext: b64(48, 9) },
		owner_envelope: ownerEnvelope(secretId, owner.address, 1, 10), state_version: 1,
		nonce: 'ab'.repeat(16), created_at: new Date().toISOString()
	}, owner);
}

describe('KeylinkSecret Durable Object', () => {
	beforeEach(async () => reset());

	it('registers one encrypted secret idempotently', async () => {
		const owner = identity(1);
		const secretId = '01'.repeat(16);
		const stub = env.KEYLINK_SECRETS.getByName(secretId);
		const record = await registration(secretId, owner);
		const first = await stub.register(record);
		expect(first.current_owner).toBe(owner.address);
		expect(first.state_version).toBe(1);
		const repeated = await stub.register(record);
		expect(repeated.registration.signature).toBe(record.signature);
	});

	it('serves signed registrations through the HTTP API with local CORS', async () => {
		const owner = identity(2);
		const secretId = '0c'.repeat(16);
		const response = await workerExports.default.fetch(new Request('https://sweetwallet.net/api/keylink/secrets', {
			method: 'POST',
			headers: { 'content-type': 'application/json', origin: 'http://localhost:8080' },
			body: JSON.stringify(await registration(secretId, owner))
		}));
		expect(response.status).toBe(201);
		expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:8080');
		const body = await response.json();
		expect(body.state.current_owner).toBe(owner.address);
		const fetched = await workerExports.default.fetch(new Request(`https://sweetwallet.net/api/keylink/secrets/${secretId}`));
		expect(fetched.status).toBe(200);
		expect((await fetched.json()).state.secret_id).toBe(secretId);
	});

	it('accepts signed requests and current-owner denials', async () => {
		const owner = identity(3);
		const requester = identity(4);
		const secretId = '02'.repeat(16);
		const requestId = '03'.repeat(16);
		const stub = env.KEYLINK_SECRETS.getByName(secretId);
		await stub.register(await registration(secretId, owner));
		const request = await signed({
			protocol: 'KEYLINK1', type: 'ownership_request', request_id: requestId, secret_id: secretId,
			current_owner_id: owner.address, requester_id: requester.address, requester_public_key: requester.publicKey,
			requester_encryption_key: b64(32, 11), nonce: '04'.repeat(16), created_at: new Date().toISOString()
		}, requester);
		const requested = await stub.createRequest(request);
		expect(requested.requests[0].status).toBe('pending');
		const denial = await signed({ protocol: 'KEYLINK1', type: 'ownership_request_denial', request_id: requestId,
			secret_id: secretId, owner_id: owner.address, owner_public_key: owner.publicKey, nonce: '06'.repeat(16), created_at: new Date().toISOString() }, owner);
		const denied = await stub.denyRequest(denial);
		expect(denied.current_owner).toBe(owner.address);
		expect(denied.requests[0].status).toBe('denied');
	});

	it('atomically transfers to the approved requester and rejects stale ownership', async () => {
		const owner = identity(6);
		const requester = identity(7);
		const secretId = '07'.repeat(16);
		const requestId = '08'.repeat(16);
		const stub = env.KEYLINK_SECRETS.getByName(secretId);
		await stub.register(await registration(secretId, owner));
		await stub.createRequest(await signed({
			protocol: 'KEYLINK1', type: 'ownership_request', request_id: requestId, secret_id: secretId,
			current_owner_id: owner.address, requester_id: requester.address, requester_public_key: requester.publicKey,
			requester_encryption_key: b64(32, 12), nonce: '09'.repeat(16), created_at: new Date().toISOString()
		}, requester));
		const transfer = await signed({
			protocol: 'KEYLINK1', type: 'ownership_transfer', secret_id: secretId, from: owner.address, to: requester.address,
			request_id: requestId, previous_state_version: 1, new_state_version: 2, timestamp: new Date().toISOString(), nonce: '0a'.repeat(16),
			authorization: { policy: 'CURRENT_OWNER_MANUAL_APPROVAL', provider: 'ManualOwnerApprovalProvider', decision: 'approved' },
			owner_public_key: owner.publicKey, new_owner_envelope: ownerEnvelope(secretId, requester.address, 2, 13)
		}, owner);
		const moved = await stub.commitTransfer(transfer, 'ab'.repeat(32));
		expect(moved.current_owner).toBe(requester.address);
		expect(moved.state_version).toBe(2);
		expect(moved.requests[0].status).toBe('approved');
		const repeated = await stub.commitTransfer(transfer, 'ab'.repeat(32));
		expect(repeated.current_owner).toBe(requester.address);
	});
});
