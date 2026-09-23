'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Activity = require('../sweetwallet-activity.js');

test('loads every successful detail in history order', async () => {
	const result = await Activity.loadTransactionDetails(['tx-1', 'tx-2', 'tx-3'], async (txid) => ({ txid }), (tx) => tx, 3);
	assert.equal(result.failedTxids.length, 0);
	assert.deepEqual(result.records.map((record) => record.txid), ['tx-1', 'tx-2', 'tx-3']);
	assert.equal(result.consumed, 3);
});

test('keeps successful details when one old-history transaction stays unavailable', async () => {
	const calls = {};
	const result = await Activity.loadTransactionDetails(['a', 'b', 'c', 'd', 'e'], async (txid) => {
		calls[txid] = (calls[txid] || 0) + 1;
		if (txid === 'c') throw new Error('temporary backend fault');
		return { txid };
	}, (tx) => tx, 4);
	assert.deepEqual(result.records.map((record) => record.txid), ['a', 'b', 'd', 'e']);
	assert.deepEqual(result.failedTxids, ['c']);
	assert.equal(calls.c, 2, 'a failed detail is retried once');
	assert.equal(result.consumed, 5, 'pagination advances by the history page, not rendered records');
});

test('limits concurrent detail requests and preserves source ordering despite out-of-order completion', async () => {
	let active = 0;
	let peak = 0;
	const ids = Array.from({ length: 22 }, (_, index) => 'old-' + index);
	const result = await Activity.loadTransactionDetails(ids, async (txid) => {
		active += 1;
		peak = Math.max(peak, active);
		await new Promise((resolve) => setTimeout(resolve, Number(txid.slice(4)) % 3 === 0 ? 8 : 1));
		active -= 1;
		return { txid, vin: undefined, vout: undefined };
	}, (tx) => ({ txid: tx.txid }), 4);
	assert.ok(peak <= 4, 'never exceeds the four-request detail pool');
	assert.deepEqual(result.records.map((record) => record.txid), ids);
	assert.equal(result.failedTxids.length, 0);
});

test('a later retry can replace a previous complete-detail failure', async () => {
	let attempt = 0;
	const fetch = async (txid) => {
		attempt += 1;
		if (attempt <= 2) throw new Error('first page unavailable');
		return { txid };
	};
	const first = await Activity.loadTransactionDetails(['retry'], fetch, (tx) => tx, 1);
	const second = await Activity.loadTransactionDetails(['retry'], fetch, (tx) => tx, 1);
	assert.deepEqual(first.failedTxids, ['retry']);
	assert.deepEqual(second.records.map((record) => record.txid), ['retry']);
});

test('transient detail failures receive a paced final retry before becoming partial', async () => {
	let calls = 0;
	const result = await Activity.loadTransactionDetails(['eventual'], async (txid) => {
		calls += 1;
		if (calls < 3) throw new Error('temporary fault');
		return { txid };
	}, (tx) => tx, 1, { attempts: 3, delayMs: 0 });
	assert.equal(calls, 3);
	assert.deepEqual(result.records.map((record) => record.txid), ['eventual']);
	assert.deepEqual(result.failedTxids, []);
});

test('history-level retry recovers without turning a brief outage into an empty activity screen', async () => {
	let calls = 0;
	const result = await Activity.retryTask(async () => {
		calls += 1;
		if (calls < 3) throw new Error('history unavailable');
		return ['tx-1'];
	}, 3, 0);
	assert.equal(calls, 3);
	assert.deepEqual(result, ['tx-1']);
});

test('refresh keeps cached rows for details that are temporarily unavailable', () => {
	const previous = [{ txid: 'old-a', confirmations: 2 }, { txid: 'old-b', confirmations: 4 }];
	const fresh = [{ txid: 'old-a', confirmations: 3 }];
	const merged = Activity.mergeRefreshRecords(['old-a', 'old-b'], fresh, previous);
	assert.deepEqual(merged, [{ txid: 'old-a', confirmations: 3 }, { txid: 'old-b', confirmations: 4 }]);
});

test('an unpaged fallback cannot pretend its first page is a later requested page', () => {
	const firstPage = { result: { tx: Array.from({ length: 10 }, (_, index) => 'tx-' + index), txcount: 56 } };
	const completeHistory = { result: { tx: Array.from({ length: 56 }, (_, index) => 'tx-' + index), txcount: 56 } };
	assert.equal(Activity.canUseUnpagedHistory(firstPage, 0), true);
	assert.equal(Activity.canUseUnpagedHistory(firstPage, 10), false);
	assert.equal(Activity.canUseUnpagedHistory(completeHistory, 10), true);
});

test('normalizes a batch Esplora transaction without inventing a confirmation count', () => {
	const record = Activity.normalizeEsploraTransaction({
		txid: 'batch-tx',
		fee: 1000,
		status: { confirmed: true, block_height: 42, block_time: 123456 },
		vin: [{ prevout: { value: 9000, scriptpubkey_address: 'sender' } }],
		vout: [
			{ value: 7000, scriptpubkey_address: 'wallet' },
			{ value: 1000, scriptpubkey_address: 'change' }
		]
	}, 'wallet');
	assert.equal(record.net, 7000);
	assert.equal(record.fee, 1000);
	assert.equal(record.confirmed, true);
	assert.equal(record.confirmations, null);
	assert.equal(record.height, 42);
	assert.deepEqual(record.detailAddresses, ['sender']);
});

test('distinguishes successful empty history, partial history, and a failed history request', () => {
	assert.equal(Activity.activityStatus(true, 0, 0), 'loaded');
	assert.equal(Activity.activityStatus(true, 4, 1), 'partial');
	assert.equal(Activity.activityStatus(true, 0, 1), 'error');
	assert.equal(Activity.activityStatus(false, 0, 0), 'error');
	assert.equal(Activity.activityStatus(false, 3, 0), 'partial');
});
