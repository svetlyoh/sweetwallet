(function (root, factory) {
	var api = factory();
	if (typeof module === 'object' && module.exports) { module.exports = api; }
	if (root) { root.SweetWalletActivity = api; }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
	'use strict';

	function retryTask(task, attempts, delayMs) {
		var limit = Math.max(1, Number(attempts) || 1);
		var delay = Math.max(0, Number(delayMs) || 0);
		var attempt = 0;

		function run() {
			attempt += 1;
			return Promise.resolve().then(task).catch(function (error) {
				if (attempt >= limit) { throw error; }
				return new Promise(function (resolve) {
					setTimeout(resolve, delay * attempt);
				}).then(run);
			});
		}

		return run();
	}

	function loadTransactionDetails(txids, fetchDetail, normalize, concurrency, retryOptions) {
		var ids = Array.isArray(txids) ? txids.filter(Boolean).map(String) : [];
		var limit = Math.max(1, Math.min(Number(concurrency) || 4, 5));
		var attempts = Math.max(1, Number(retryOptions && retryOptions.attempts) || 2);
		var retryDelay = Math.max(0, Number(retryOptions && retryOptions.delayMs) || 0);
		var slots = new Array(ids.length);
		var cursor = 0;

		function fetchOnce(txid) {
			return Promise.resolve().then(function () { return fetchDetail(txid); }).then(normalize);
		}

		function fetchWithRetry(txid) {
			return retryTask(function () { return fetchOnce(txid); }, attempts, retryDelay);
		}

		function worker() {
			var index = cursor++;
			if (index >= ids.length) { return Promise.resolve(); }
			return fetchWithRetry(ids[index]).then(function (record) {
				slots[index] = { txid: ids[index], record: record };
			}).catch(function () {
				slots[index] = { txid: ids[index], failed: true };
			}).then(worker);
		}

		var workers = [];
		for (var index = 0; index < Math.min(limit, ids.length); index += 1) {
			workers.push(worker());
		}
		return Promise.all(workers).then(function () {
			var records = [];
			var failedTxids = [];
			slots.forEach(function (slot) {
				if (slot && slot.record) {
					records.push(slot.record);
				} else if (slot) {
					failedTxids.push(slot.txid);
				}
			});
			return { records: records, failedTxids: failedTxids, consumed: ids.length };
		});
	}

	function activityStatus(historyLoaded, recordCount, failedCount) {
		if (!historyLoaded) { return recordCount > 0 ? 'partial' : 'error'; }
		if (failedCount > 0) { return recordCount > 0 ? 'partial' : 'error'; }
		return 'loaded';
	}

	function mergeRefreshRecords(txids, freshRecords, previousRecords) {
		var fresh = {};
		var previous = {};
		(freshRecords || []).forEach(function (record) {
			if (record && record.txid) { fresh[record.txid] = record; }
		});
		(previousRecords || []).forEach(function (record) {
			if (record && record.txid) { previous[record.txid] = record; }
		});
		return (txids || []).map(function (txid) {
			return fresh[txid] || previous[txid] || null;
		}).filter(Boolean);
	}

	function canUseUnpagedHistory(data, offset) {
		if (!(Number(offset) > 0)) { return true; }
		var result = data && data.result || {};
		var txids = Array.isArray(result.tx) ? result.tx : [];
		var total = Number(result.txcount);
		if (!Number.isFinite(total)) { return true; }
		return total <= txids.length || txids.length > Number(offset);
	}

	function normalizeEsploraTransaction(tx, walletAddress) {
		tx = tx || {};
		var status = tx.status || {};
		var inputs = Array.isArray(tx.vin) ? tx.vin : [];
		var outputs = Array.isArray(tx.vout) ? tx.vout : [];
		var inputTotal = 0;
		var outputTotal = 0;
		var fromWallet = 0;
		var toWallet = 0;
		var fromAddresses = [];
		var toAddresses = [];
		var seenFrom = {};
		var seenTo = {};

		inputs.forEach(function (input) {
			var prevout = input && input.prevout;
			if (!prevout) { return; }
			var value = Number(prevout.value || 0);
			var address = prevout.scriptpubkey_address || '';
			inputTotal += value;
			if (address === walletAddress) {
				fromWallet += value;
			} else if (address && !seenFrom[address]) {
				seenFrom[address] = true;
				fromAddresses.push(address);
			}
		});
		outputs.forEach(function (output) {
			var value = Number(output && output.value || 0);
			var address = output && output.scriptpubkey_address || '';
			outputTotal += value;
			if (address === walletAddress) {
				toWallet += value;
			} else if (address && !seenTo[address]) {
				seenTo[address] = true;
				toAddresses.push(address);
			}
		});
		if (!tx.txid) { throw new Error('Transaction response was incomplete.'); }
		var net = toWallet - fromWallet;
		var received = net >= 0;
		return {
			txid: tx.txid,
			net: net,
			fee: Number.isFinite(Number(tx.fee)) ? Number(tx.fee) : Math.max(0, inputTotal - outputTotal),
			time: Number(status.block_time || 0),
			confirmations: status.confirmed ? null : 0,
			confirmed: !!status.confirmed,
			height: Number(status.block_height || 0),
			detailLabel: received ? 'From' : 'To',
			detailAddresses: received ? fromAddresses : toAddresses
		};
	}

	return Object.freeze({
		retryTask: retryTask,
		loadTransactionDetails: loadTransactionDetails,
		activityStatus: activityStatus,
		mergeRefreshRecords: mergeRefreshRecords,
		canUseUnpagedHistory: canUseUnpagedHistory,
		normalizeEsploraTransaction: normalizeEsploraTransaction
	});
}));
