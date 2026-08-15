(function () {
	'use strict';

	var Crypto = window.SweetWalletKeylinkCrypto;
	var Bridge = window.SweetWalletKeylinkBridge;
	var Storage = window.SweetWalletKeylinkStorage;
	var POLL_INTERVAL = 30000;
	var state = {
		ownerId: '',
		identityRecord: null,
		identityPair: null,
		records: [],
		filter: 'all',
		sort: 'active',
		query: '',
		pollTimer: 0,
		polling: false,
		pendingApproval: null,
		activeSecretId: '',
		plainSecret: ''
	};

	var $ = function (selector) { return document.querySelector(selector); };
	var $$ = function (selector) { return Array.prototype.slice.call(document.querySelectorAll(selector)); };

	function escapeHtml(value) {
		return String(value === undefined || value === null ? '' : value)
			.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;').replace(/'/g, '&#039;');
	}

	function toast(message, tone) {
		if (Bridge && Bridge.showToast) {
			Bridge.showToast(message, tone);
		}
	}

	function setBusy(button, busy, label) {
		if (!button) { return; }
		if (busy) {
			button.dataset.keylinkHtml = button.innerHTML;
			button.disabled = true;
			button.textContent = label || 'Working…';
		} else {
			button.disabled = false;
			if (button.dataset.keylinkHtml) {
				button.innerHTML = button.dataset.keylinkHtml;
				delete button.dataset.keylinkHtml;
			}
		}
		refreshIcons();
	}

	function refreshIcons() {
		if (window.lucide) {
			window.lucide.createIcons();
		}
	}

	function walletContext() {
		var context = Bridge && Bridge.getWalletContext ? Bridge.getWalletContext() : null;
		if (!context || !context.address || !context.publicKey || !context.canSign) {
			throw new Error('Open and unlock a SUGAR wallet before using Keylink.');
		}
		return context;
	}

	function localId(secretId) {
		return state.ownerId + ':' + String(secretId || '').toLowerCase();
	}

	function getIdentity(ownerId) {
		return Storage.getIdentity(ownerId);
	}

	function putIdentity(record) {
		return Storage.putIdentity(record);
	}

	function getOwnerRecords(ownerId) {
		return Storage.getOwnerRecords(ownerId);
	}

	function putRecord(record) {
		record.local_id = record.local_id || localId(record.secret_id);
		record.owner_id = state.ownerId;
		return Storage.putRecord(state.ownerId, record);
	}

	function legacyIdentity(ownerHash) {
		return new Promise(function (resolve) {
			if (!window.indexedDB) { resolve(null); return; }
			var request = window.indexedDB.open('sweetwallet_file_relay_v1');
			request.onerror = function () { resolve(null); };
			request.onsuccess = function () {
				var database = request.result;
				if (!database.objectStoreNames.contains('encryption_keys')) { database.close(); resolve(null); return; }
				var get = database.transaction('encryption_keys', 'readonly').objectStore('encryption_keys').get(ownerHash);
				get.onsuccess = function () { database.close(); resolve(get.result || null); };
				get.onerror = function () { database.close(); resolve(null); };
			};
		});
	}

	async function loadIdentityPair(record) {
		return {
			privateKey: record.private_key,
			publicKey: await Crypto.importPublicKey(record.public_key)
		};
	}

	async function ensureIdentity() {
		var context = walletContext();
		if (state.ownerId === context.address && state.identityRecord && state.identityPair) {
			return state.identityRecord;
		}
		state.ownerId = context.address;
		state.identityRecord = await getIdentity(context.address);
		if (!state.identityRecord) {
			var ownerHash = await Crypto.sha256Hex(context.address);
			var legacy = await legacyIdentity(ownerHash);
			if (legacy && legacy.privateKey && legacy.publicKey) {
				state.identityRecord = {
					owner_id: context.address,
					public_key: legacy.publicKey,
					private_key: legacy.privateKey,
					created_at: legacy.createdAt || new Date().toISOString(),
					updated_at: new Date().toISOString(),
					migrated_from: 'File Key Relay'
				};
				await putIdentity(state.identityRecord);
				toast('Your existing X25519 encryption identity was migrated to Keylink.');
			} else {
				var pair = await Crypto.generateIdentity();
				state.identityRecord = {
					owner_id: context.address,
					public_key: await Crypto.exportPublicKey(pair.publicKey),
					private_key: pair.privateKey,
					created_at: new Date().toISOString(),
					updated_at: new Date().toISOString()
				};
				await putIdentity(state.identityRecord);
			}
		}
		state.identityPair = await loadIdentityPair(state.identityRecord);
		return state.identityRecord;
	}

	function relayBase() {
		var localStatic = /^(localhost|127\.0\.0\.1)$/i.test(window.location.hostname) && !/^(8787|8788)$/.test(window.location.port);
		return localStatic ? 'https://sweetwallet.net' : window.location.origin;
	}

	async function relayRequest(path, options) {
		var response = await fetch(relayBase() + path, Object.assign({
			headers: { 'content-type': 'application/json' }
		}, options || {}));
		var data = await response.json().catch(function () { return null; });
		if (!response.ok || !data) {
			throw new Error(data && data.error || 'The Keylink relay is unavailable.');
		}
		return data;
	}

	function randomHex() {
		return Crypto.bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
	}

	async function signRecord(record) {
		return Object.assign({}, record, { signature: await Bridge.signRecord(record) });
	}

	function short(value, head, tail) {
		var text = String(value || '');
		var first = head || 6;
		var last = tail || 6;
		return text.length <= first + last + 1 ? text : text.slice(0, first) + '…' + text.slice(-last);
	}

	function relativeTime(value) {
		var time = Date.parse(value || '');
		if (!Number.isFinite(time)) { return ''; }
		var seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
		if (seconds < 60) { return seconds + 's ago'; }
		if (seconds < 3600) { return Math.floor(seconds / 60) + 'm ago'; }
		if (seconds < 86400) { return Math.floor(seconds / 3600) + 'h ago'; }
		if (seconds < 604800) { return Math.floor(seconds / 86400) + 'd ago'; }
		return new Date(time).toLocaleDateString();
	}

	function requestsFor(record) {
		return Array.isArray(record.requests) ? record.requests : [];
	}

	function incomingRequests(record) {
		if (record.current_owner !== state.ownerId) { return []; }
		return requestsFor(record).filter(function (request) { return request.status === 'pending'; });
	}

	function outgoingRequest(record) {
		return requestsFor(record).find(function (request) {
			return request.requester_id === state.ownerId && request.request_id === record.outgoing_request_id;
		}) || requestsFor(record).find(function (request) { return request.requester_id === state.ownerId; }) || null;
	}

	function primaryStatus(record) {
		var incoming = incomingRequests(record);
		if (incoming.length) { return { key: 'pending_incoming', label: 'Approval Requested', icon: 'bell-ring', detail: incoming.length + ' action' + (incoming.length === 1 ? '' : 's') + ' required' }; }
		var outgoing = outgoingRequest(record);
		if (outgoing && outgoing.status === 'pending') { return { key: 'pending_outgoing', label: 'Waiting for Owner', icon: 'clock-3', detail: 'Requested ' + relativeTime(outgoing.created_at) }; }
		if (outgoing && outgoing.status === 'denied') { return { key: 'denied', label: 'Request Denied', icon: 'circle-x', detail: 'Denied ' + relativeTime(outgoing.updated_at) }; }
		if (outgoing && outgoing.status === 'cancelled') { return { key: 'denied', label: 'Request Cancelled', icon: 'circle-x', detail: 'Cancelled ' + relativeTime(outgoing.updated_at) }; }
		if (outgoing && outgoing.status === 'superseded') { return { key: 'denied', label: 'Ownership Changed', icon: 'circle-x', detail: 'Request closed' }; }
		if (record.current_owner === state.ownerId) {
			if (record.created_by === state.ownerId && Number(record.state_version) === 1) { return { key: 'created', label: 'Created', icon: 'badge-plus', detail: 'Created by you · Owned' }; }
			if (record.created_by !== state.ownerId || Number(record.state_version) > 1) { return { key: 'obtained', label: 'Obtained', icon: 'arrow-down-to-line', detail: 'Owned by you' }; }
			return { key: 'owned', label: 'Owned', icon: 'key-round', detail: 'Owned by you' };
		}
		if (record.relationship === 'transferred' || record.transferred_to) { return { key: 'transferred', label: 'Transferred', icon: 'arrow-up-from-line', detail: 'To ' + short(record.transferred_to || record.current_owner, 10, 6) }; }
		return { key: 'pending_outgoing', label: 'Waiting for Owner', icon: 'clock-3', detail: 'Relay synchronization pending' };
	}

	function recordActivity(record) {
		var values = [record.updated_at, record.created_at];
		requestsFor(record).forEach(function (request) { values.push(request.updated_at, request.created_at); });
		return Math.max.apply(Math, values.map(function (value) { return Date.parse(value || '') || 0; }));
	}

	function matchesFilter(record) {
		var status = primaryStatus(record);
		if (state.filter === 'all') { return true; }
		if (state.filter === 'owned') { return record.current_owner === state.ownerId; }
		if (state.filter === 'created') { return record.created_by === state.ownerId; }
		if (state.filter === 'obtained') { return status.key === 'obtained'; }
		if (state.filter === 'pending') { return status.key === 'pending_incoming' || status.key === 'pending_outgoing' || status.key === 'denied'; }
		if (state.filter === 'transferred') { return status.key === 'transferred'; }
		return true;
	}

	function visibleRecords() {
		var query = state.query.toLowerCase();
		var records = state.records.filter(function (record) {
			if (!matchesFilter(record)) { return false; }
			if (!query) { return true; }
			var status = primaryStatus(record);
			return [record.secret_id, record.label, record.current_owner, record.created_by, record.transferred_to, status.label, status.detail]
				.join(' ').toLowerCase().includes(query);
		});
		return records.sort(function (left, right) {
			if (state.sort === 'created') { return Date.parse(right.created_at || '') - Date.parse(left.created_at || ''); }
			if (state.sort === 'owned') { return Number(right.current_owner === state.ownerId) - Number(left.current_owner === state.ownerId) || recordActivity(right) - recordActivity(left); }
			if (state.sort === 'pending') { return Number(primaryStatus(right).key.indexOf('pending') === 0) - Number(primaryStatus(left).key.indexOf('pending') === 0) || recordActivity(right) - recordActivity(left); }
			if (state.sort === 'transferred') { return Number(primaryStatus(right).key === 'transferred') - Number(primaryStatus(left).key === 'transferred') || recordActivity(right) - recordActivity(left); }
			return recordActivity(right) - recordActivity(left);
		});
	}

	function updateBadge() {
		var count = state.records.reduce(function (total, record) { return total + incomingRequests(record).length; }, 0);
		$$('[data-keylink-badge]').forEach(function (badge) {
			badge.textContent = count ? String(count) : '';
			badge.classList.toggle('hidden', !count);
		});
		var pendingFilter = $('[data-keylink-filter="pending"]');
		if (pendingFilter) { pendingFilter.textContent = 'Pending' + (count ? ' (' + count + ')' : ''); }
	}

	function emptyMessage() {
		if (!state.records.length) {
			return '<div class="keylink-empty"><i data-lucide="key-round"></i><h3>No Keylinks yet</h3><p>Create a secret or scan a Keylink to get started.</p><div><button type="button" class="button" data-keylink-action="create"><i data-lucide="plus"></i>Create Secret</button><button type="button" class="button subtle" data-keylink-action="scan"><i data-lucide="scan-qr-code"></i>Scan QR</button></div></div>';
		}
		if (state.filter === 'pending') { return '<div class="keylink-empty compact"><p>No pending requests.</p></div>'; }
		if (state.filter === 'transferred') { return '<div class="keylink-empty compact"><p>You haven\'t transferred any Keylinks yet.</p></div>'; }
		return '<div class="keylink-empty compact"><p>No Keylinks match this view.</p></div>';
	}

	function renderLibrary() {
		var list = $('#keylinkList');
		if (!list) { return; }
		var records = visibleRecords();
		list.innerHTML = records.length ? records.map(function (record) {
			var status = primaryStatus(record);
			var time = relativeTime(new Date(recordActivity(record)).toISOString());
			return '<button type="button" class="keylink-row status-' + status.key + '" data-keylink-secret="' + escapeHtml(record.secret_id) + '">' +
				'<span class="keylink-status-icon"><i data-lucide="' + status.icon + '"></i></span>' +
				'<span class="keylink-row-main"><span class="keylink-row-id">' + escapeHtml(short(record.secret_id)) + '</span>' +
				'<span class="keylink-row-label">' + escapeHtml(record.label || status.detail) + '</span>' +
				'<span class="keylink-row-meta"><strong>' + escapeHtml(status.label) + '</strong><span>' + escapeHtml(time) + '</span></span></span>' +
				'<i class="keylink-row-chevron" data-lucide="chevron-right"></i></button>';
		}).join('') : emptyMessage();
		$$('[data-keylink-filter]').forEach(function (button) { button.classList.toggle('active', button.dataset.keylinkFilter === state.filter); });
		updateBadge();
		refreshIcons();
	}

	async function reloadRecords() {
		state.records = await getOwnerRecords(state.ownerId);
		renderLibrary();
	}

	function findRecord(secretId) {
		return state.records.find(function (record) { return record.secret_id === secretId; }) || null;
	}

	function requestForId(record, requestId) {
		return requestsFor(record).find(function (request) { return request.request_id === requestId; });
	}

	async function mergeRemoteState(remote) {
		var record = findRecord(remote.secret_id) || {
			local_id: localId(remote.secret_id), owner_id: state.ownerId, protocol: Crypto.PROTOCOL,
			secret_id: remote.secret_id, label: '', created_at: remote.created_at
		};
		if (record.pending_transfer && record.pending_transfer.transfer &&
			Number(remote.state_version) < Number(record.pending_transfer.transfer.new_state_version)) {
			record.requests = remote.requests || record.requests || [];
			record.updated_at = record.pending_transfer.transfer.timestamp;
			await putRecord(record);
			return record;
		}
		var wasOwner = record.current_owner === state.ownerId || record.relationship === 'created' || record.relationship === 'obtained';
		record.created_by = remote.created_by;
		record.current_owner = remote.current_owner;
		record.state_version = remote.state_version;
		record.requests = remote.requests || [];
		record.transfers = remote.transfers || [];
		record.latest_transfer_txid = remote.latest_transfer_txid || record.latest_transfer_txid || null;
		record.updated_at = remote.updated_at || new Date().toISOString();
		if (remote.current_owner === state.ownerId) {
			record.encrypted_secret = remote.encrypted_secret;
			record.owner_envelope = remote.owner_envelope;
			record.relationship = remote.created_by === state.ownerId && Number(remote.state_version) === 1 ? 'created' : 'obtained';
			record.pending_transfer = null;
		} else if (wasOwner || record.pending_transfer) {
			record.relationship = 'transferred';
			record.transferred_to = remote.current_owner;
			record.owner_envelope = null;
			record.encrypted_secret = null;
			record.pending_transfer = null;
		}
		await putRecord(record);
		return record;
	}

	async function retryRecord(record) {
		if (record.pending_registration) {
			try {
				var registrationResult = await relayRequest('/api/keylink/secrets', { method: 'POST', body: JSON.stringify(record.pending_registration) });
				record.pending_registration = null;
				await putRecord(record);
				await mergeRemoteState(registrationResult.state);
			} catch (error) {
				// The local encrypted record remains queued for a later retry.
			}
		}
		if (record.pending_request) {
			try {
				var requestResult = await relayRequest('/api/keylink/secrets/' + record.secret_id + '/requests', { method: 'POST', body: JSON.stringify(record.pending_request) });
				record.pending_request = null;
				await putRecord(record);
				await mergeRemoteState(requestResult.state);
			} catch (error) {
				// The signed request remains queued for a later retry.
			}
		}
		if (record.pending_transfer && record.pending_transfer.ownership_txid) {
			try {
				var transferResult = await relayRequest('/api/keylink/secrets/' + record.secret_id + '/transfers', {
					method: 'POST', body: JSON.stringify(record.pending_transfer)
				});
				await mergeRemoteState(transferResult.state);
			} catch (error) {
				// A broadcast may need time to propagate before the relay can verify it.
			}
		}
	}

	async function pollAll(showErrors) {
		if (state.polling || !state.ownerId) { return; }
		state.polling = true;
		try {
			await reloadRecords();
			for (var index = 0; index < state.records.length; index += 1) {
				await retryRecord(state.records[index]);
			}
			await reloadRecords();
			var ids = Array.from(new Set(state.records.map(function (record) { return record.secret_id; })));
			for (var offset = 0; offset < ids.length; offset += 100) {
				var data = await relayRequest('/api/keylink/batch', { method: 'POST', body: JSON.stringify({ secret_ids: ids.slice(offset, offset + 100) }) });
				for (var stateIndex = 0; stateIndex < data.states.length; stateIndex += 1) {
					if (!data.states[stateIndex].error) { await mergeRemoteState(data.states[stateIndex]); }
				}
			}
			await reloadRecords();
		} catch (error) {
			if (showErrors) { toast(error.message || 'Keylink synchronization failed.', 'danger'); }
		} finally {
			state.polling = false;
		}
	}

	async function createSecret(event) {
		event.preventDefault();
		var button = $('#keylinkCreateSubmit');
		var secretInput = $('#keylinkSecretInput');
		var labelInput = $('#keylinkLabelInput');
		setBusy(button, true, 'Encrypting…');
		var encrypted;
		try {
			var context = walletContext();
			var identity = await ensureIdentity();
			encrypted = await Crypto.encryptSecret(secretInput.value);
			var ownerEnvelope = await Crypto.wrapContentKey(encrypted.contentKey, identity.public_key, encrypted.encryptedSecret.secret_id, context.address, 1);
			var registration = await signRecord({
				protocol: Crypto.PROTOCOL,
				type: 'secret_registration',
				secret_id: encrypted.encryptedSecret.secret_id,
				created_by: context.address,
				current_owner: context.address,
				owner_public_key: context.publicKey.toLowerCase(),
				owner_encryption_key: identity.public_key,
				encrypted_secret: encrypted.encryptedSecret,
				owner_envelope: ownerEnvelope,
				state_version: 1,
				nonce: randomHex(),
				created_at: new Date().toISOString()
			});
			var record = {
				local_id: localId(registration.secret_id), owner_id: state.ownerId, protocol: Crypto.PROTOCOL,
				secret_id: registration.secret_id, label: labelInput.value.trim().slice(0, 80),
				created_by: context.address, current_owner: context.address, relationship: 'created',
				encrypted_secret: registration.encrypted_secret, owner_envelope: registration.owner_envelope,
				state_version: 1, requests: [], pending_registration: registration,
				created_at: registration.created_at, updated_at: registration.created_at
			};
			await putRecord(record);
			secretInput.value = '';
			labelInput.value = '';
			$('#keylinkSecretCount').textContent = '0 / 300';
			showLibraryView();
			await reloadRecords();
			try {
				var result = await relayRequest('/api/keylink/secrets', { method: 'POST', body: JSON.stringify(registration) });
				record.pending_registration = null;
				await putRecord(record);
				await mergeRemoteState(result.state);
				await reloadRecords();
				openDetail(record.secret_id);
				toast('Keylink created. Its permanent QR will never change.');
			} catch (relayError) {
				toast('Secret encrypted locally. Relay registration will retry automatically.', 'warning');
			}
		} catch (error) {
			toast(error.message || 'Keylink could not be created.', 'danger');
		} finally {
			if (encrypted && encrypted.contentKey) { encrypted.contentKey.fill(0); }
			setBusy(button, false);
		}
	}

	function showCreateView() {
		$('#keylinkLibraryView').classList.add('hidden');
		$('#keylinkCreateView').classList.remove('hidden');
		$('#keylinkSecretInput').focus();
	}

	function showLibraryView() {
		$('#keylinkCreateView').classList.add('hidden');
		$('#keylinkLibraryView').classList.remove('hidden');
	}

	async function resolveSecret(secretId) {
		var data = await relayRequest('/api/keylink/secrets/' + secretId, { method: 'GET', headers: {} });
		return data.state;
	}

	async function scanOrPaste(value) {
		try {
			var secretId = Crypto.parseSecretUri(value);
			var remote = await resolveSecret(secretId);
			if (remote.current_owner === state.ownerId) {
				await mergeRemoteState(remote);
				await reloadRecords();
				openDetail(secretId);
				toast('You own this Keylink.');
				return;
			}
			showScanResult(remote);
		} catch (error) {
			toast(error.message || 'Keylink could not be resolved.', 'danger');
		}
	}

	function handleScannedKeylink(value) {
		try {
			Crypto.parseSecretUri(value);
		} catch (error) {
			return false;
		}
		scanOrPaste(value);
		return true;
	}

	function showScanResult(remote) {
		state.activeSecretId = remote.secret_id;
		$('#keylinkDetailTitle').textContent = 'Keylink';
		$('#keylinkDetailBody').innerHTML = '<div class="keylink-detail-hero"><span class="keylink-detail-icon"><i data-lucide="scan-qr-code"></i></span><code>' + escapeHtml(short(remote.secret_id)) + '</code><h3>This secret belongs to another owner.</h3></div>' +
			'<dl class="keylink-detail-grid"><div><dt>Current owner</dt><dd class="break-anywhere">' + escapeHtml(remote.current_owner) + '</dd></div><div><dt>Permanent QR</dt><dd>' + escapeHtml(Crypto.createSecretUri(remote.secret_id)) + '</dd></div></dl>' +
			'<div class="notice">QR possession is not ownership. The secret remains encrypted for the current owner.</div>';
		$('#keylinkDetailActions').innerHTML = '<button class="button" type="button" data-keylink-detail-action="request"><i data-lucide="hand"></i>Request Ownership</button><button class="button secondary" type="button" data-keylink-detail-action="close">Close</button>';
		$('#keylinkDetailModal').classList.add('active');
		refreshIcons();
	}

	async function requestOwnership() {
		var button = $('[data-keylink-detail-action="request"]');
		setBusy(button, true, 'Requesting…');
		try {
			var context = walletContext();
			var identity = await ensureIdentity();
			var remote = await resolveSecret(state.activeSecretId);
			if (remote.current_owner === context.address) {
				await mergeRemoteState(remote); await reloadRecords(); openDetail(remote.secret_id); return;
			}
			var ownershipRequest = await signRecord({
				protocol: Crypto.PROTOCOL, type: 'ownership_request', request_id: randomHex(), secret_id: remote.secret_id,
				current_owner_id: remote.current_owner, requester_id: context.address,
				requester_public_key: context.publicKey.toLowerCase(), requester_encryption_key: identity.public_key,
				nonce: randomHex(), created_at: new Date().toISOString()
			});
			var record = findRecord(remote.secret_id) || { local_id: localId(remote.secret_id), owner_id: state.ownerId, protocol: Crypto.PROTOCOL, secret_id: remote.secret_id, label: '', created_at: remote.created_at };
			record.created_by = remote.created_by;
			record.current_owner = remote.current_owner;
			record.state_version = remote.state_version;
			record.relationship = 'pending_outgoing';
			record.outgoing_request_id = ownershipRequest.request_id;
			record.pending_request = ownershipRequest;
			record.requests = (remote.requests || []).concat([Object.assign({}, ownershipRequest, { status: 'pending', updated_at: ownershipRequest.created_at })]);
			record.updated_at = ownershipRequest.created_at;
			await putRecord(record);
			$('#keylinkDetailModal').classList.remove('active');
			await reloadRecords();
			try {
				var result = await relayRequest('/api/keylink/secrets/' + remote.secret_id + '/requests', { method: 'POST', body: JSON.stringify(ownershipRequest) });
				record.pending_request = null; await putRecord(record); await mergeRemoteState(result.state); await reloadRecords();
				toast('Ownership request sent.');
			} catch (relayError) {
				toast('Request saved locally and will retry when the relay is available.', 'warning');
			}
		} catch (error) {
			toast(error.message || 'Ownership request failed.', 'danger');
		} finally { setBusy(button, false); }
	}

	function historyHtml(record) {
		var transfers = Array.isArray(record.transfers) ? record.transfers : [];
		if (!transfers.length && !record.latest_transfer_txid) { return '<p class="keylink-muted">No ownership transfers yet.</p>'; }
		return transfers.map(function (transfer) {
			return '<a class="keylink-history-row" href="' + escapeHtml(Bridge.explorerTx(transfer.ownership_txid)) + '" target="_blank" rel="noopener"><span>' + escapeHtml(short(transfer.from, 8, 5)) + ' → ' + escapeHtml(short(transfer.to, 8, 5)) + '</span><small>Version ' + Number(transfer.new_state_version) + ' · ' + escapeHtml(short(transfer.ownership_txid)) + '</small></a>';
		}).join('') || '<a class="keylink-history-row" href="' + escapeHtml(Bridge.explorerTx(record.latest_transfer_txid)) + '" target="_blank" rel="noopener">View latest ownership transaction</a>';
	}

	async function openDetail(secretId) {
		var record = findRecord(secretId);
		if (!record) { return; }
		state.activeSecretId = secretId;
		try {
			var remote = await resolveSecret(secretId);
			await mergeRemoteState(remote);
			await reloadRecords();
			record = findRecord(secretId);
			record.transfers = remote.transfers || [];
		} catch (error) {
			// Local details remain available while the relay is temporarily offline.
		}
		var status = primaryStatus(record);
		var incoming = incomingRequests(record);
		var outgoing = outgoingRequest(record);
		var owner = record.current_owner === state.ownerId ? 'You' : record.current_owner;
		var provenance = record.created_by === state.ownerId ? 'Created by you' : (record.current_owner === state.ownerId ? 'Obtained' : 'Previously owned');
		var requestsHtml = incoming.length ? '<section class="keylink-requests"><h3>Ownership Requests</h3>' + incoming.map(function (request) {
			return '<article class="keylink-request-card"><div><strong>' + escapeHtml(short(request.requester_id, 12, 8)) + '</strong><small>Requested ' + escapeHtml(relativeTime(request.created_at)) + '</small></div><button class="copy-button" type="button" data-copy-value="' + escapeHtml(request.requester_id) + '" aria-label="Copy requester address"><i data-lucide="copy"></i></button><div class="keylink-request-actions"><button class="button" type="button" data-keylink-request-approve="' + request.request_id + '">Approve</button><button class="button danger" type="button" data-keylink-request-deny="' + request.request_id + '">Deny</button></div></article>';
		}).join('') + '</section>' : '';
		var outgoingHtml = outgoing ? '<div class="notice ' + (outgoing.status === 'denied' ? 'danger' : '') + '"><strong>' + escapeHtml(outgoing.status === 'denied' ? 'Request Denied' : 'Waiting for approval') + '</strong><br>Current owner: ' + escapeHtml(short(record.current_owner, 12, 8)) + '</div>' : '';
		$('#keylinkDetailTitle').textContent = 'Keylink Secret';
		$('#keylinkDetailBody').innerHTML = '<div class="keylink-detail-hero"><span class="keylink-detail-icon status-' + status.key + '"><i data-lucide="' + status.icon + '"></i></span><code>' + escapeHtml(short(record.secret_id)) + '</code><h3>' + escapeHtml(status.label) + '</h3><p>' + escapeHtml(status.detail) + '</p></div>' +
			'<dl class="keylink-detail-grid"><div><dt>Secret ID</dt><dd class="break-anywhere">' + escapeHtml(record.secret_id) + '</dd></div><div><dt>Current owner</dt><dd class="break-anywhere">' + escapeHtml(owner) + '</dd></div><div><dt>Origin</dt><dd>' + escapeHtml(provenance) + '</dd></div><div><dt>State version</dt><dd>' + Number(record.state_version || 1) + '</dd></div></dl>' +
			(record.current_owner !== state.ownerId && status.key === 'transferred' ? '<div class="notice warning">Ownership transferred. This Keylink identity is no longer authorized to reveal this secret.</div>' : '') + outgoingHtml + requestsHtml +
			'<section class="keylink-history"><h3>Blockchain History</h3>' + historyHtml(record) + '</section>';
		var actions = [];
		if (record.current_owner === state.ownerId && record.encrypted_secret && record.owner_envelope) { actions.push('<button class="button" type="button" data-keylink-detail-action="view"><i data-lucide="eye"></i>View Secret</button>'); }
		actions.push('<button class="button subtle" type="button" data-keylink-detail-action="qr"><i data-lucide="qr-code"></i>Show QR</button>');
		if (outgoing && outgoing.status === 'pending') { actions.push('<button class="button danger" type="button" data-keylink-detail-action="cancel-request"><i data-lucide="x"></i>Cancel Request</button>'); }
		actions.push('<button class="button secondary" type="button" data-keylink-detail-action="close">Close</button>');
		$('#keylinkDetailActions').innerHTML = actions.join('');
		$('#keylinkDetailModal').classList.add('active');
		refreshIcons();
	}

	async function viewSecret() {
		try {
			var remote = await resolveSecret(state.activeSecretId);
			if (remote.current_owner !== state.ownerId) { throw new Error('This Keylink has been transferred. Your identity is no longer the current owner.'); }
			await ensureIdentity();
			var key = await Crypto.unwrapContentKey(remote.owner_envelope, state.identityPair);
			try { state.plainSecret = await Crypto.decryptSecret(remote.encrypted_secret, key); } finally { key.fill(0); }
			$('#keylinkSecretText').textContent = state.plainSecret;
			$('#keylinkSecretModal').classList.add('active');
		} catch (error) { toast(error.message || 'Secret could not be opened.', 'danger'); }
	}

	function closeSecretModal() {
		state.plainSecret = '';
		$('#keylinkSecretText').textContent = '';
		$('#keylinkSecretModal').classList.remove('active');
	}

	function showQr() {
		var record = findRecord(state.activeSecretId);
		if (!record) { return; }
		var uri = Crypto.createSecretUri(record.secret_id);
		var target = $('#keylinkQrCode');
		target.innerHTML = '';
		if (window.jQuery && window.jQuery.fn && window.jQuery.fn.qrcode) {
			window.jQuery(target).qrcode({ text: uri, width: 260, height: 260 });
		} else { target.textContent = uri; }
		$('#keylinkQrId').textContent = record.secret_id;
		$('#keylinkQrOwner').textContent = record.current_owner === state.ownerId ? 'You' : short(record.current_owner, 12, 8);
		$('#keylinkQrUri').value = uri;
		$('#keylinkQrModal').classList.add('active');
	}

	async function denyRequest(requestId) {
		if (!window.confirm('Deny this ownership request?')) { return; }
		try {
			var context = walletContext();
			var record = findRecord(state.activeSecretId);
			var decision = await signRecord({ protocol: Crypto.PROTOCOL, type: 'ownership_request_denial', request_id: requestId,
				secret_id: record.secret_id, owner_id: context.address, owner_public_key: context.publicKey.toLowerCase(), nonce: randomHex(), created_at: new Date().toISOString() });
			var result = await relayRequest('/api/keylink/secrets/' + record.secret_id + '/requests/' + requestId + '/deny', { method: 'POST', body: JSON.stringify(decision) });
			await mergeRemoteState(result.state); await reloadRecords(); openDetail(record.secret_id); toast('Ownership request denied.');
		} catch (error) { toast(error.message || 'Request could not be denied.', 'danger'); }
	}

	async function cancelRequest() {
		if (!window.confirm('Cancel this ownership request?')) { return; }
		try {
			var context = walletContext();
			var record = findRecord(state.activeSecretId);
			var outgoing = outgoingRequest(record);
			var decision = await signRecord({ protocol: Crypto.PROTOCOL, type: 'ownership_request_cancellation', request_id: outgoing.request_id,
				secret_id: record.secret_id, requester_id: context.address, requester_public_key: context.publicKey.toLowerCase(), nonce: randomHex(), created_at: new Date().toISOString() });
			var result = await relayRequest('/api/keylink/secrets/' + record.secret_id + '/requests/' + outgoing.request_id + '/cancel', { method: 'POST', body: JSON.stringify(decision) });
			await mergeRemoteState(result.state); await reloadRecords(); openDetail(record.secret_id); toast('Ownership request cancelled.');
		} catch (error) { toast(error.message || 'Request could not be cancelled.', 'danger'); }
	}

	async function prepareApproval(requestId) {
		try {
			var context = walletContext();
			await ensureIdentity();
			var remote = await resolveSecret(state.activeSecretId);
			if (remote.current_owner !== context.address) { throw new Error('You are no longer the current owner of this Keylink.'); }
			var request = requestForId({ requests: remote.requests }, requestId);
			if (!request || request.status !== 'pending') { throw new Error('This ownership request is no longer pending.'); }
			var envelope = await Crypto.rewrapOwnerEnvelope(remote.owner_envelope, state.identityPair, request.requester_encryption_key, request.requester_id, Number(remote.state_version) + 1);
			var transfer = await signRecord({
				protocol: Crypto.PROTOCOL, type: 'ownership_transfer', secret_id: remote.secret_id,
				from: context.address, to: request.requester_id, request_id: request.request_id,
				previous_state_version: Number(remote.state_version), new_state_version: Number(remote.state_version) + 1,
				timestamp: new Date().toISOString(), nonce: randomHex(),
				authorization: { policy: 'CURRENT_OWNER_MANUAL_APPROVAL', provider: 'ManualOwnerApprovalProvider', decision: 'approved' },
				owner_public_key: context.publicKey.toLowerCase(), new_owner_envelope: envelope
			});
			state.pendingApproval = { remote: remote, request: request, transfer: transfer, klt1: await Crypto.createKlt1Hex(transfer) };
			$('#keylinkTransferSecret').textContent = short(remote.secret_id);
			$('#keylinkTransferFrom').textContent = context.address;
			$('#keylinkTransferTo').textContent = request.requester_id;
			$('#keylinkTransferFee').textContent = context.feeSugar + ' SUGAR';
			$('#keylinkTransferModal').classList.add('active');
		} catch (error) { toast(error.message || 'Transfer could not be prepared.', 'danger'); }
	}

	async function confirmApproval() {
		var button = $('#keylinkConfirmTransfer');
		if (!state.pendingApproval) { return; }
		setBusy(button, true, 'Signing & broadcasting…');
		var pending = state.pendingApproval;
		try {
			var broadcast = await Bridge.broadcastKeylinkTransfer(pending.klt1);
			var record = findRecord(pending.transfer.secret_id);
			record.relationship = 'transferred';
			record.current_owner = pending.transfer.to;
			record.transferred_to = pending.transfer.to;
			record.state_version = pending.transfer.new_state_version;
			record.latest_transfer_txid = broadcast.txid;
			record.encrypted_secret = null;
			record.owner_envelope = null;
			record.updated_at = pending.transfer.timestamp;
			record.pending_transfer = { transfer: pending.transfer, ownership_txid: broadcast.txid };
			await putRecord(record);
			state.pendingApproval = null;
			$('#keylinkTransferModal').classList.remove('active');
			$('#keylinkDetailModal').classList.remove('active');
			await reloadRecords();
			try {
				var result = await relayRequest('/api/keylink/secrets/' + record.secret_id + '/transfers', { method: 'POST', body: JSON.stringify(record.pending_transfer) });
				await mergeRemoteState(result.state); await reloadRecords();
				toast('Keylink ownership transferred on Sugarchain.');
			} catch (relayError) {
				toast('Sugarchain accepted the transfer. Keylink will retry relay verification after propagation.', 'warning');
			}
		} catch (error) { toast(error.message || 'Keylink transfer failed.', 'danger'); }
		finally { setBusy(button, false); }
	}

	function showIdentity() {
		ensureIdentity().then(function (identity) {
			$('#keylinkIdentityOwner').textContent = identity.owner_id;
			$('#keylinkIdentityPublic').value = identity.public_key;
			$('#keylinkIdentityModal').classList.add('active');
		}).catch(function (error) { toast(error.message, 'danger'); });
	}

	async function exportIdentity(event) {
		event.preventDefault();
		try {
			var password = $('#keylinkBackupPassword').value;
			var confirmation = $('#keylinkBackupPasswordConfirm').value;
			if (password !== confirmation) { throw new Error('Backup passwords do not match.'); }
			await ensureIdentity();
			var backup = await Crypto.exportIdentityBackup(state.identityPair, password, state.ownerId);
			var url = URL.createObjectURL(new Blob([backup], { type: 'application/json' }));
			var anchor = document.createElement('a');
			anchor.href = url; anchor.download = 'sweetwallet-keylink-identity-' + state.ownerId.slice(0, 8) + '.json';
			document.body.appendChild(anchor); anchor.click(); anchor.remove(); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
			$('#keylinkBackupPassword').value = ''; $('#keylinkBackupPasswordConfirm').value = '';
			toast('Encrypted Keylink identity backup downloaded.');
		} catch (error) { toast(error.message || 'Identity backup failed.', 'danger'); }
	}

	async function importIdentity(event) {
		event.preventDefault();
		try {
			var file = $('#keylinkImportFile').files[0];
			if (!file) { throw new Error('Choose a Keylink identity backup file.'); }
			var imported = await Crypto.importIdentityBackup(await file.text(), $('#keylinkImportPassword').value);
			if (imported.ownerId && imported.ownerId !== state.ownerId) { throw new Error('This identity backup belongs to a different Sugarchain wallet.'); }
			var record = { owner_id: state.ownerId, public_key: await Crypto.exportPublicKey(imported.publicKey), private_key: imported.privateKey, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), imported: true };
			await putIdentity(record); state.identityRecord = record; state.identityPair = { privateKey: imported.privateKey, publicKey: imported.publicKey };
			$('#keylinkImportFile').value = ''; $('#keylinkImportPassword').value = '';
			showIdentity(); toast('Keylink encryption identity restored.');
		} catch (error) { toast(error.message || 'Identity import failed.', 'danger'); }
	}

	function closeModal(selector) {
		var modal = $(selector);
		if (modal) { modal.classList.remove('active'); }
	}

	function wireEvents() {
		$('#keylinkPanel').addEventListener('click', function (event) {
			var action = event.target.closest('[data-keylink-action]');
			if (action) {
				if (action.dataset.keylinkAction === 'create') { showCreateView(); }
				if (action.dataset.keylinkAction === 'scan') { Bridge.openQrScanner('keylink'); }
				if (action.dataset.keylinkAction === 'paste') { $('#keylinkPasteModal').classList.add('active'); $('#keylinkPasteInput').focus(); }
				if (action.dataset.keylinkAction === 'identity') { showIdentity(); }
			}
			var row = event.target.closest('[data-keylink-secret]');
			if (row) { openDetail(row.dataset.keylinkSecret); }
			var filter = event.target.closest('[data-keylink-filter]');
			if (filter) { state.filter = filter.dataset.keylinkFilter; renderLibrary(); }
		});
		$('#keylinkCreateForm').addEventListener('submit', createSecret);
		$('#keylinkCreateBack').addEventListener('click', showLibraryView);
		$('#keylinkSecretInput').addEventListener('input', function () { $('#keylinkSecretCount').textContent = Array.from(this.value).length + ' / 300'; });
		$('#keylinkSearch').addEventListener('input', function () { state.query = this.value.trim(); renderLibrary(); });
		$('#keylinkSort').addEventListener('change', function () { state.sort = this.value; renderLibrary(); });
		$('#keylinkPasteForm').addEventListener('submit', function (event) { event.preventDefault(); var value = $('#keylinkPasteInput').value; closeModal('#keylinkPasteModal'); $('#keylinkPasteInput').value = ''; scanOrPaste(value); });
		$('#keylinkDetailModal').addEventListener('click', function (event) {
			var action = event.target.closest('[data-keylink-detail-action]');
			if (action) {
				if (action.dataset.keylinkDetailAction === 'close') { closeModal('#keylinkDetailModal'); }
				if (action.dataset.keylinkDetailAction === 'request') { requestOwnership(); }
				if (action.dataset.keylinkDetailAction === 'view') { viewSecret(); }
				if (action.dataset.keylinkDetailAction === 'qr') { showQr(); }
				if (action.dataset.keylinkDetailAction === 'cancel-request') { cancelRequest(); }
			}
			var copy = event.target.closest('[data-copy-value]');
			if (copy) { Bridge.copyValue(copy.dataset.copyValue, 'Requester address copied.'); }
			var approve = event.target.closest('[data-keylink-request-approve]');
			if (approve) { prepareApproval(approve.dataset.keylinkRequestApprove); }
			var deny = event.target.closest('[data-keylink-request-deny]');
			if (deny) { denyRequest(deny.dataset.keylinkRequestDeny); }
		});
		$('#keylinkCopySecret').addEventListener('click', function () { if (state.plainSecret) { Bridge.copyValue(state.plainSecret, 'Secret copied.'); } });
		$('#keylinkCloseSecret').addEventListener('click', closeSecretModal);
		$('#keylinkCloseQr').addEventListener('click', function () { closeModal('#keylinkQrModal'); });
		$('#keylinkCopyQrUri').addEventListener('click', function () { Bridge.copyValue($('#keylinkQrUri').value, 'Permanent Keylink copied.'); });
		$('#keylinkCancelTransfer').addEventListener('click', function () { state.pendingApproval = null; closeModal('#keylinkTransferModal'); });
		$('#keylinkConfirmTransfer').addEventListener('click', confirmApproval);
		$('#keylinkCloseIdentity').addEventListener('click', function () { closeModal('#keylinkIdentityModal'); });
		$('#keylinkCopyIdentity').addEventListener('click', function () { Bridge.copyValue($('#keylinkIdentityPublic').value, 'Public encryption key copied.'); });
		$('#keylinkExportIdentity').addEventListener('submit', exportIdentity);
		$('#keylinkImportIdentity').addEventListener('submit', importIdentity);
		$$('[data-keylink-modal-close]').forEach(function (button) { button.addEventListener('click', function () { closeModal(button.dataset.keylinkModalClose); }); });
		window.addEventListener('sweetwallet:sensitive-cleared', function () {
			state.identityPair = null; state.identityRecord = null; state.ownerId = ''; state.records = []; state.plainSecret = '';
			window.clearInterval(state.pollTimer); state.pollTimer = 0; closeSecretModal();
		});
	}

	async function onPanelOpen() {
		try {
			await ensureIdentity();
			showLibraryView();
			await reloadRecords();
			pollAll(false);
			window.clearInterval(state.pollTimer);
			state.pollTimer = window.setInterval(function () { pollAll(false); }, POLL_INTERVAL);
		} catch (error) { toast(error.message || 'Keylink could not open.', 'danger'); }
	}

	function init() {
		if (!Crypto || !Bridge || !Storage || !$('#keylinkPanel')) { return; }
		wireEvents();
		refreshIcons();
	}

	window.SweetWalletKeylink = {
		onPanelOpen: onPanelOpen,
		handleScannedKeylink: handleScannedKeylink,
		resolveCurrentOwner: async function (secretId) { return (await resolveSecret(Crypto.parseSecretUri(secretId))).current_owner; }
	};
	document.addEventListener('DOMContentLoaded', init);
}());
