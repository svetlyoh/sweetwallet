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

async function registration(secretId, owner, options = {}) {
	const record = {
		protocol: 'KEYLINK1', type: 'secret_registration', secret_id: secretId,
		created_by: owner.address, current_owner: owner.address, owner_public_key: owner.publicKey,
		owner_encryption_key: b64(32, 7),
		encrypted_secret: { protocol: 'KEYLINK1', type: 'encrypted_secret', secret_id: secretId, cipher: 'AES-256-GCM', nonce: b64(12, 8), ciphertext: b64(48, 9) },
		owner_envelope: ownerEnvelope(secretId, owner.address, 1, 10), state_version: 1,
		nonce: 'ab'.repeat(16), created_at: new Date().toISOString()
	};
	if (Object.prototype.hasOwnProperty.call(options, 'pinRequired')) {
		record.pin_required = options.pinRequired === true;
		record.autoapprove_enabled = options.pinRequired === true && options.autoapprove !== false;
	}
	return signed(record, owner);
}

async function ownershipRequest(secretId, owner, requester, requestId, stateVersion = 1) {
	return signed({
		protocol: 'KEYLINK1', type: 'ownership_request', request_id: requestId, secret_id: secretId,
		current_owner_id: owner.address, requester_id: requester.address, requester_public_key: requester.publicKey,
		requester_encryption_key: b64(32, 21), state_version: stateVersion, nonce: 'cd'.repeat(16), created_at: new Date().toISOString()
	}, requester);
}

async function pinPolicy(secretId, owner, values) {
	return signed({
		protocol: 'KEYLINK1', type: 'pin_policy_update', secret_id: secretId,
		owner_id: owner.address, owner_public_key: owner.publicKey, state_version: values.stateVersion || 1,
		pin_required: values.pinRequired, autoapprove_enabled: values.autoapprove,
		replace_pin: values.replacePin === true, replace_reserved: values.replaceReserved === true,
		nonce: 'ef'.repeat(16), created_at: new Date().toISOString()
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

describe('PIN-gated Keylink requests', () => {
	beforeEach(async () => reset());

	it('stores only a verifier and exposes no plaintext PIN', async () => {
		const owner = identity(14);
		const secretId = '14'.repeat(16);
		const stub = env.KEYLINK_SECRETS.getByName(secretId);
		const state = await stub.register(await registration(secretId, owner, { pinRequired: true }), '004281');
		expect(state.pin_required).toBe(true);
		expect(state.pin_setup_required).toBe(false);
		expect(JSON.stringify(state)).not.toContain('004281');
		expect(JSON.stringify(state)).not.toContain('pin_verifier');
		expect(JSON.stringify(state)).not.toContain('pin_salt');
		expect(JSON.stringify(state)).not.toContain('autoapprove_enabled');
	});

	it('silently discards wrong or missing PINs and admits a correct PIN', async () => {
		const owner = identity(15);
		const requester = identity(16);
		const secretId = '15'.repeat(16);
		await env.KEYLINK_SECRETS.getByName(secretId).register(await registration(secretId, owner, { pinRequired: true }), '483921');

		const wrongRequest = await ownershipRequest(secretId, owner, requester, '31'.repeat(16));
		const wrongResponse = await workerExports.default.fetch(new Request(`https://sweetwallet.net/api/keylink/secrets/${secretId}/requests`, {
			method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ request: wrongRequest, pin: '000000' })
		}));
		expect(wrongResponse.status).toBe(202);
		const wrongBody = await wrongResponse.json();
		expect(wrongBody).toEqual({ submitted: true, message: 'Request received.' });
		expect((await env.KEYLINK_SECRETS.getByName(secretId).publicState()).requests).toHaveLength(0);

		const bypassRequest = await ownershipRequest(secretId, owner, identity(17), '32'.repeat(16));
		const bypassResponse = await workerExports.default.fetch(new Request(`https://sweetwallet.net/api/keylink/secrets/${secretId}/requests`, {
			method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(bypassRequest)
		}));
		expect(await bypassResponse.json()).toEqual(wrongBody);
		expect((await env.KEYLINK_SECRETS.getByName(secretId).publicState()).requests).toHaveLength(0);

		const correctRequest = await ownershipRequest(secretId, owner, requester, '33'.repeat(16));
		const correctResponse = await workerExports.default.fetch(new Request(`https://sweetwallet.net/api/keylink/secrets/${secretId}/requests`, {
			method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ request: correctRequest, pin: '483921' })
		}));
		expect(await correctResponse.json()).toEqual(wrongBody);
		const state = await env.KEYLINK_SECRETS.getByName(secretId).publicState();
		expect(state.requests).toHaveLength(1);
		expect(state.requests[0].pin_verified).toBe(true);
		expect(state.requests[0].autoapprove_reserved).toBe(true);
	});

	it('applies a cooldown after repeated failed attempts without exposing the count', async () => {
		const owner = identity(18);
		const secretId = '18'.repeat(16);
		const stub = env.KEYLINK_SECRETS.getByName(secretId);
		await stub.register(await registration(secretId, owner, { pinRequired: true }), '725104');
		for (let index = 0; index < 5; index += 1) {
			const requester = identity(30 + index);
			await stub.submitRequest(await ownershipRequest(secretId, owner, requester, (40 + index).toString(16).padStart(2, '0').repeat(16)), '111111');
		}
		const validRequester = identity(40);
		const result = await stub.submitRequest(await ownershipRequest(secretId, owner, validRequester, '50'.repeat(16)), '725104');
		expect(result.accepted).toBe(false);
		expect((await stub.publicState()).requests).toHaveLength(0);
	});

	it('keeps valid PIN requests manual when autoapprove is off', async () => {
		const owner = identity(19);
		const requester = identity(20);
		const secretId = '19'.repeat(16);
		const stub = env.KEYLINK_SECRETS.getByName(secretId);
		await stub.register(await registration(secretId, owner, { pinRequired: true, autoapprove: false }), '314159');
		const result = await stub.submitRequest(await ownershipRequest(secretId, owner, requester, '61'.repeat(16)), '314159');
		expect(result.accepted).toBe(true);
		const state = await stub.publicState();
		expect(state.requests[0].pin_verified).toBe(true);
		expect(state.requests[0].autoapprove_reserved).toBe(false);
	});

	it('atomically reserves only the first of two correct PIN requests', async () => {
		const owner = identity(21);
		const secretId = '21'.repeat(16);
		const stub = env.KEYLINK_SECRETS.getByName(secretId);
		await stub.register(await registration(secretId, owner, { pinRequired: true }), '271828');
		const first = await ownershipRequest(secretId, owner, identity(22), '71'.repeat(16));
		const second = await ownershipRequest(secretId, owner, identity(23), '72'.repeat(16));
		const results = await Promise.all([stub.submitRequest(first, '271828'), stub.submitRequest(second, '271828')]);
		expect(results.filter((result) => result.accepted)).toHaveLength(2);
		const state = await stub.publicState();
		expect(state.requests).toHaveLength(2);
		expect(state.requests.filter((request) => request.pin_verified)).toHaveLength(2);
		expect(state.requests.filter((request) => request.autoapprove_reserved)).toHaveLength(1);
	});

	it('regenerates and disables PIN policy only with current-owner signatures', async () => {
		const owner = identity(24);
		const requester = identity(25);
		const secretId = '24'.repeat(16);
		const stub = env.KEYLINK_SECRETS.getByName(secretId);
		await stub.register(await registration(secretId, owner, { pinRequired: true }), '123456');
		await stub.updatePinPolicy(await pinPolicy(secretId, owner, { pinRequired: true, autoapprove: true, replacePin: true }), '654321');
		expect((await stub.submitRequest(await ownershipRequest(secretId, owner, requester, '81'.repeat(16)), '123456')).accepted).toBe(false);
		expect((await stub.submitRequest(await ownershipRequest(secretId, owner, requester, '82'.repeat(16)), '654321')).accepted).toBe(true);
		await stub.updatePinPolicy(await pinPolicy(secretId, owner, { pinRequired: false, autoapprove: false }), '');
		const state = await stub.publicState();
		expect(state.pin_required).toBe(false);
		expect(JSON.stringify(state)).not.toContain('654321');
	});

	it('consumes the old PIN on transfer and requires a fresh new-owner PIN', async () => {
		const owner = identity(27);
		const recipient = identity(28);
		const nextRequester = identity(29);
		const secretId = '27'.repeat(16);
		const requestId = '91'.repeat(16);
		const stub = env.KEYLINK_SECRETS.getByName(secretId);
		await stub.register(await registration(secretId, owner, { pinRequired: true }), '483921');
		await stub.submitRequest(await ownershipRequest(secretId, owner, recipient, requestId), '483921');
		const transfer = await signed({
			protocol: 'KEYLINK1', type: 'ownership_transfer', secret_id: secretId,
			from: owner.address, to: recipient.address, request_id: requestId,
			previous_state_version: 1, new_state_version: 2, timestamp: new Date().toISOString(), nonce: '92'.repeat(16),
			authorization: { policy: 'PIN_AUTOAPPROVE_ADVANCE_AUTHORIZATION', provider: 'LocalWalletPinAutoapproveProvider', decision: 'approved' },
			owner_public_key: owner.publicKey, new_owner_envelope: ownerEnvelope(secretId, recipient.address, 2, 41)
		}, owner);
		const txid = '93'.repeat(32);
		await stub.markTransferBroadcast(transfer, txid);
		let state = await stub.commitTransfer(transfer, txid);
		expect(state.current_owner).toBe(recipient.address);
		expect(state.pin_required).toBe(true);
		expect(state.pin_setup_required).toBe(true);

		const oldPinResult = await stub.submitRequest(await ownershipRequest(secretId, recipient, nextRequester, '94'.repeat(16), 2), '483921');
		expect(oldPinResult.accepted).toBe(false);
		await stub.updatePinPolicy(await pinPolicy(secretId, recipient, { stateVersion: 2, pinRequired: true, autoapprove: true, replacePin: true }), '725104');
		const freshPinResult = await stub.submitRequest(await ownershipRequest(secretId, recipient, nextRequester, '95'.repeat(16), 2), '725104');
		expect(freshPinResult.accepted).toBe(true);
		state = await stub.publicState();
		expect(state.pin_setup_required).toBe(false);
		expect(JSON.stringify(state)).not.toContain('483921');
		expect(JSON.stringify(state)).not.toContain('725104');
	});
});
