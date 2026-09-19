(function (root, factory) {
	var api = factory();
	if (typeof module === 'object' && module.exports) { module.exports = api; }
	if (root) { root.SweetWalletActivity = api; }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
	'use strict';

	function loadTransactionDetails(txids, fetchDetail, normalize, concurrency) {
		var ids = Array.isArray(txids) ? txids.filter(Boolean).map(String) : [];
		var limit = Math.max(1, Math.min(Number(concurrency) || 4, 5));
		var slots = new Array(ids.length);
		var cursor = 0;

		function fetchOnce(txid) {
			return Promise.resolve().then(function () { return fetchDetail(txid); }).then(normalize);
		}

		function fetchWithRetry(txid) {
			return fetchOnce(txid).catch(function () {
				return fetchOnce(txid);
			});
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

	return Object.freeze({ loadTransactionDetails: loadTransactionDetails, activityStatus: activityStatus });
}));
