(function () {
	'use strict';

	var Crypto = window.SweetWalletFileRelayCrypto;
	var Bridge;
	var DB_NAME = 'sweetwallet_file_relay_v1';
	var DB_VERSION = 1;
	var KEY_STORE = 'encryption_keys';
	var HISTORY_KEY = 'sweetwallet_file_relay_history_v1';
	var MAX_FILE_BYTES = 100 * 1024 * 1024;
	var MAX_HISTORY = 100;

	var state = {
		ownerId: '',
		keyRecord: null,
		currentRelay: null,
		pendingRecipient: null,
		activeView: 'home',
		loadingKey: false
	};

	var $ = function (selector) {
		return document.querySelector(selector);
	};

	var $$ = function (selector) {
		return Array.prototype.slice.call(document.querySelectorAll(selector));
	};

	function toast(message, tone) {
		if (Bridge && Bridge.showToast) {
			Bridge.showToast(message, tone);
		}
	}

	function setBusy(button, busy, text) {
		if (!button) {
			return;
		}
		if (busy) {
			if (!button.dataset.originalText) {
				button.dataset.originalText = button.innerHTML;
			}
			button.disabled = true;
			button.textContent = text || 'Working...';
		} else {
			button.disabled = false;
			if (button.dataset.originalText) {
				button.innerHTML = button.dataset.originalText;
				delete button.dataset.originalText;
			}
		}
		if (window.lucide) {
			window.lucide.createIcons();
		}
	}

	function setNotice(selector, message, tone) {
		var element = $(selector);
		if (!element) {
			return;
		}
		element.textContent = message || '';
		element.className = 'notice' + (tone ? ' ' + tone : '');
	}

	function openDatabase() {
		return new Promise(function (resolve, reject) {
			if (!window.indexedDB) {
				reject(new Error('This browser cannot store the local File Relay encryption key.'));
				return;
			}
			var request = window.indexedDB.open(DB_NAME, DB_VERSION);
			request.onupgradeneeded = function () {
				var database = request.result;
				if (!database.objectStoreNames.contains(KEY_STORE)) {
					database.createObjectStore(KEY_STORE, { keyPath: 'ownerId' });
				}
			};
			request.onsuccess = function () {
				resolve(request.result);
			};
			request.onerror = function () {
				reject(request.error || new Error('File Relay key storage could not open.'));
			};
		});
	}

	function keyStoreOperation(mode, operation) {
		return openDatabase().then(function (database) {
			return new Promise(function (resolve, reject) {
				var transaction = database.transaction(KEY_STORE, mode);
				var store = transaction.objectStore(KEY_STORE);
				var request = operation(store);
				request.onsuccess = function () {
					resolve(request.result);
				};
				request.onerror = function () {
					reject(request.error || new Error('File Relay key storage failed.'));
				};
				transaction.oncomplete = function () {
					database.close();
				};
				transaction.onabort = transaction.onerror = function () {
					database.close();
				};
			});
		});
	}

	function getStoredKey(ownerId) {
		return keyStoreOperation('readonly', function (store) {
			return store.get(ownerId);
		});
	}

	function putStoredKey(record) {
		return keyStoreOperation('readwrite', function (store) {
			return store.put(record);
		});
	}

	function walletContext() {
		var context = Bridge && Bridge.getWalletContext ? Bridge.getWalletContext() : null;
		if (!context || !context.address || !context.canSign) {
			throw new Error('Open and unlock a SUGAR wallet before using File Key Relay.');
		}
		return context;
	}

	function ownerIdForAddress(address) {
		return Crypto.sha256Hex(String(address || ''));
	}

	function ensureKeyLoaded() {
		var context;
		try {
			context = walletContext();
		} catch (error) {
			return Promise.reject(error);
		}
		if (state.loadingKey) {
			return state.loadingKey;
		}
		state.loadingKey = ownerIdForAddress(context.address).then(function (ownerId) {
			if (state.ownerId === ownerId && state.keyRecord) {
				return state.keyRecord;
			}
			state.ownerId = ownerId;
			state.keyRecord = null;
			return getStoredKey(ownerId).then(function (record) {
				state.keyRecord = record || null;
				return state.keyRecord;
			});
		}).finally(function () {
			state.loadingKey = false;
		});
		return state.loadingKey;
	}

	function renderQr(targetSelector, value) {
		var target = $(targetSelector);
		if (!target) {
			return;
		}
		target.innerHTML = '';
		try {
			if (window.jQuery && window.jQuery.fn && window.jQuery.fn.qrcode) {
				window.jQuery(target).qrcode({
					text: value,
					width: 260,
					height: 260
				});
				return;
			}
		} catch (error) {
			setNotice('#relayQrStatus', 'QR rendering failed. Copy or download the Relay JSON instead.', 'warning');
		}
		target.textContent = value;
	}

	function showView(name) {
		state.activeView = name;
		$$('[data-relay-view]').forEach(function (view) {
			view.classList.toggle('hidden', view.dataset.relayView !== name);
		});
		if (name === 'setup') {
			renderKeySetup();
		}
		if (name === 'history') {
			renderHistory();
		}
		if (window.lucide) {
			window.lucide.createIcons();
		}
	}

	function renderKeySetup() {
		ensureKeyLoaded().then(function (record) {
			var hasKey = !!(record && record.publicKey && record.privateKey);
			$('#relayGenerateKey').classList.toggle('hidden', hasKey);
			$('#relayPublicKeyBox').classList.toggle('hidden', !hasKey);
			$('#relayKeyBackupBox').classList.toggle('hidden', !hasKey);
			if (!hasKey) {
				setNotice('#relayKeyStatus', 'No dedicated File Relay encryption key is stored for this SUGAR wallet.', 'warning');
				return;
			}
			$('#relayPublicKey').value = record.publicKey;
			$('#relayKeyLabel').value = record.label || '';
			var recipientUri = Crypto.createRecipientUri(record.publicKey, record.label || '');
			$('#relayRecipientUri').value = recipientUri;
			renderQr('#relayPublicKeyQr', recipientUri);
			setNotice('#relayKeyStatus', 'X25519 relay key ready. Its private key stays in this browser and cannot spend SUGAR.');
		}).catch(function (error) {
			setNotice('#relayKeyStatus', error.message || 'Relay key storage is unavailable.', 'danger');
		});
	}

	function generateEncryptionKey() {
		var button = $('#relayGenerateKey');
		var context;
		setBusy(button, true, 'Generating X25519 key...');
		Promise.resolve().then(function () {
			context = walletContext();
			return ownerIdForAddress(context.address);
		}).then(function (ownerId) {
			state.ownerId = ownerId;
			return Crypto.generateKeyPair();
		}).then(function (pair) {
			return Crypto.exportPublicKey(pair.publicKey).then(function (publicKey) {
				return {
					ownerId: state.ownerId,
					ownerAddress: context.address,
					keyType: Crypto.KEY_TYPE,
					publicKey: publicKey,
					privateKey: pair.privateKey,
					label: $('#relayKeyLabel').value.trim().slice(0, 80),
					createdAt: new Date().toISOString(),
					updatedAt: new Date().toISOString()
				};
			});
		}).then(function (record) {
			return putStoredKey(record).then(function () {
				state.keyRecord = record;
			});
		}).then(function () {
			renderKeySetup();
			toast('Dedicated File Relay encryption key created. Back it up before relying on it.');
		}).catch(function (error) {
			setNotice('#relayKeyStatus', error.message || 'Encryption key generation failed.', 'danger');
			toast(error.message || 'Encryption key generation failed.', 'danger');
		}).finally(function () {
			setBusy(button, false);
		});
	}

	function saveKeyLabel() {
		ensureKeyLoaded().then(function (record) {
			if (!record) {
				throw new Error('Generate the relay encryption key first.');
			}
			record.label = $('#relayKeyLabel').value.trim().slice(0, 80);
			record.updatedAt = new Date().toISOString();
			return putStoredKey(record);
		}).then(function () {
			renderKeySetup();
			toast('Public relay label saved on this device.');
		}).catch(function (error) {
			toast(error.message || 'Label could not be saved.', 'danger');
		});
	}

	function readFile(file) {
		if (!file) {
			return Promise.reject(new Error('Select a file first.'));
		}
		if (file.size > MAX_FILE_BYTES) {
			return Promise.reject(new Error('This browser workflow supports files up to 100 MB. Choose a smaller file.'));
		}
		return file.arrayBuffer().then(function (buffer) {
			return new Uint8Array(buffer);
		});
	}

	function downloadBlob(blob, fileName) {
		var url = URL.createObjectURL(blob);
		var anchor = document.createElement('a');
		anchor.href = url;
		anchor.download = fileName;
		anchor.rel = 'noopener';
		document.body.appendChild(anchor);
		anchor.click();
		anchor.remove();
		window.setTimeout(function () {
			URL.revokeObjectURL(url);
		}, 1000);
	}

	function safeEncryptedName(fileName) {
		return (String(fileName || 'encrypted-file').replace(/[\\/:*?"<>|]+/g, '_') || 'encrypted-file') + '.sugarfile';
	}

	function historyList() {
		try {
			var list = JSON.parse(window.localStorage.getItem(HISTORY_KEY) || '[]');
			return Array.isArray(list) ? list : [];
		} catch (error) {
			return [];
		}
	}

	function saveHistory(entry) {
		var list = historyList();
		var index = list.findIndex(function (item) {
			return item.owner_hash === state.ownerId && item.role === entry.role && item.capsule_id === entry.capsule_id;
		});
		var existing = index >= 0 ? list[index] : {};
		var now = new Date().toISOString();
		var safeEntry = {
			protocol: Crypto.PROTOCOL,
			role: entry.role === 'recipient' ? 'recipient' : 'sender',
			owner_hash: state.ownerId,
			capsule_id: String(entry.capsule_id || ''),
			txid: String(entry.txid || ''),
			recipient_key_hash: String(entry.recipient_key_hash || ''),
			sender_ephemeral_public: String(entry.sender_ephemeral_public || ''),
			encrypted_file_hash: String(entry.encrypted_file_hash || ''),
			manifest_hash: String(entry.manifest_hash || ''),
			status: String(entry.status || 'failed'),
			created_at: existing.created_at || entry.created_at || now,
			updated_at: now
		};
		if (index >= 0) {
			list[index] = safeEntry;
		} else {
			list.unshift(safeEntry);
		}
		try {
			window.localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, MAX_HISTORY)));
		} catch (error) {
			toast('Relay history could not be saved on this device.', 'warning');
		}
	}

	function historyFromPayload(payload, role, status) {
		return {
			role: role,
			capsule_id: payload.capsule_id,
			txid: payload.txid || '',
			recipient_key_hash: payload.recipient_key_hash,
			sender_ephemeral_public: payload.sender_ephemeral_public,
			encrypted_file_hash: payload.encrypted_file_hash,
			manifest_hash: payload.manifest_hash,
			status: status,
			created_at: payload.created_at
		};
	}

	function prepareEncryption(event) {
		event.preventDefault();
		var button = $('#relayEncryptButton');
		var file = $('#relayFileInput').files[0];
		var parsedRecipient;
		var plaintextBytes;
		setBusy(button, true, 'Encrypting locally...');
		setNotice('#relayEncryptStatus', 'Encrypting in this browser. The file and keys are not uploaded.');
		Promise.resolve().then(function () {
			walletContext();
			if (!file) {
				throw new Error('Select a file to encrypt.');
			}
			parsedRecipient = Crypto.parseRecipientPublicKey($('#relayRecipientKey').value);
			return readFile(file);
		}).then(function (fileBytes) {
			plaintextBytes = fileBytes;
			return Crypto.encryptRelay({
				fileBytes: fileBytes,
				fileName: file.name,
				fileType: file.type || 'application/octet-stream',
				recipientPublicKey: parsedRecipient.publicKey,
				recipientLabel: $('#relayRecipientLabel').value || parsedRecipient.label,
				note: $('#relayNote').value,
				relayMode: $('#relayMode').value
			});
		}).then(function (result) {
			state.currentRelay = result;
			$('#relayEncryptedHash').textContent = result.payload.encrypted_file_hash;
			$('#relayManifestHash').textContent = result.payload.manifest_hash;
			$('#relayEncryptOutput').classList.remove('hidden');
			$('#relayChainActions').classList.toggle('hidden', result.payload.relay_mode !== 'sugarchain');
			$('#relayCapsuleOutput').classList.add('hidden');
			setNotice('#relayEncryptStatus', result.payload.relay_mode === 'sugarchain' ?
				'File encrypted locally. Download the encrypted file, then review the fee and explicitly confirm the SGF1 anchor.' :
				'File encrypted locally in QR-only mode. No Sugarchain timestamp proof will be created.',
				result.payload.relay_mode === 'sugarchain' ? '' : 'warning');
			saveHistory(historyFromPayload(result.payload, 'sender', 'created'));
			if (result.payload.relay_mode === 'offchain') {
				finalizeRelayOutput(result.payload);
			}
			toast('File encrypted locally. Download the .sugarfile output.');
		}).catch(function (error) {
			setNotice('#relayEncryptStatus', (error.message || 'Encryption failed.') + ' Retry or use a different recipient public key.', 'danger');
			toast(error.message || 'File encryption failed.', 'danger');
		}).finally(function () {
			if (plaintextBytes) {
				plaintextBytes.fill(0);
			}
			setBusy(button, false);
		});
	}

	function downloadEncryptedFile() {
		if (!state.currentRelay || !state.currentRelay.encryptedFile) {
			toast('Encrypt a file first.', 'danger');
			return;
		}
		downloadBlob(new Blob([state.currentRelay.encryptedFile], { type: 'application/octet-stream' }),
			safeEncryptedName(state.currentRelay.payload.file_name));
	}

	function openAnchorConfirmation() {
		if (!state.currentRelay || state.currentRelay.payload.relay_mode !== 'sugarchain') {
			toast('Create a Sugarchain relay capsule first.', 'danger');
			return;
		}
		var context;
		try {
			context = walletContext();
		} catch (error) {
			toast(error.message, 'danger');
			return;
		}
		$('#relayConfirmAnchor').textContent = state.currentRelay.opReturnHeader;
		$('#relayConfirmFee').textContent = context.feeSugar + ' SUGAR';
		$('#relayConfirmChangeAddress').textContent = context.address;
		$('#relayAnchorConfirmModal').classList.add('active');
	}

	function closeAnchorConfirmation() {
		$('#relayAnchorConfirmModal').classList.remove('active');
	}

	function confirmAnchorBroadcast() {
		var button = $('#relayConfirmBroadcast');
		if (!state.currentRelay) {
			closeAnchorConfirmation();
			return;
		}
		setBusy(button, true, 'Signing & broadcasting...');
		Bridge.broadcastRelayAnchor(state.currentRelay.opReturnHeader).then(function (result) {
			var payload = Crypto.withTransaction(state.currentRelay.payload, result.txid);
			state.currentRelay.payload = payload;
			state.currentRelay.relayUri = Crypto.encodeRelayUri(payload);
			closeAnchorConfirmation();
			finalizeRelayOutput(payload);
			saveHistory(historyFromPayload(payload, 'sender', 'qr_generated'));
			setNotice('#relayEncryptStatus', 'SGF1 anchor accepted. The QR contains only the encrypted capsule and public references.');
			toast('File Relay anchor broadcasted.');
		}).catch(function (error) {
			closeAnchorConfirmation();
			setNotice('#relayEncryptStatus', (error.message || 'Broadcast rejected.') + ' Retry, switch backend, or choose QR-only mode.', 'danger');
			if (state.currentRelay) {
				saveHistory(historyFromPayload(state.currentRelay.payload, 'sender', 'failed'));
			}
			toast(error.message || 'Relay anchor broadcast failed.', 'danger');
		}).finally(function () {
			setBusy(button, false);
		});
	}

	function finalizeRelayOutput(payload) {
		var relayUri = Crypto.encodeRelayUri(payload);
		state.currentRelay.relayUri = relayUri;
		$('#relayCapsuleUri').value = relayUri;
		$('#relayCapsuleTxid').textContent = payload.txid || 'Off-chain / no txid';
		$('#relayCapsuleTxLink').classList.toggle('hidden', !payload.txid);
		if (payload.txid) {
			$('#relayCapsuleTxLink').href = Bridge.explorerTx(payload.txid);
		}
		$('#relayCapsuleOutput').classList.remove('hidden');
		renderQr('#relayCapsuleQr', relayUri);
		setNotice('#relayQrStatus', payload.txid ?
			'Public QR ready. Only the matching recipient private encryption key can unwrap the file key.' :
			'QR-only mode: encrypted capsule ready without a Sugarchain timestamp proof.', payload.txid ? '' : 'warning');
		saveHistory(historyFromPayload(payload, 'sender', 'qr_generated'));
	}

	function downloadRelayJson() {
		if (!state.currentRelay || !state.currentRelay.payload) {
			toast('Generate a relay capsule first.', 'danger');
			return;
		}
		var json = JSON.stringify(state.currentRelay.payload, null, 2);
		downloadBlob(new Blob([json], { type: 'application/json' }), 'sugarfilekey-' + state.currentRelay.payload.capsule_id + '.json');
	}

	function parseCapsuleInput(raw) {
		var record;
		var payload;
		var verificationMessage = '';
		setNotice('#relayDecryptStatus', 'Validating encrypted capsule and local recipient key...');
		return ensureKeyLoaded().then(function (loaded) {
			record = loaded;
			if (!record) {
				throw new Error('Set up or import your File Relay encryption key first.');
			}
			payload = Crypto.decodeRelayPayload(raw);
			return Crypto.validateRelayPayload(payload);
		}).then(function (validated) {
			payload = validated;
			return Crypto.sha256Hex(Crypto.base64UrlToBytes(record.publicKey));
		}).then(function (localHash) {
			if (localHash !== payload.recipient_key_hash) {
				saveHistory(historyFromPayload(payload, 'recipient', 'not_for_this_wallet'));
				throw new Error('This file key capsule was not encrypted for this wallet.');
			}
			if (!payload.txid) {
				verificationMessage = 'Off-chain capsule: cryptography validated, but no Sugarchain timestamp proof exists.';
				return null;
			}
			return Bridge.getTransaction(payload.txid).then(function (transaction) {
				var expectedHeader = Crypto.createAnchorHeader(payload);
				if (!Crypto.transactionContainsAnchor(transaction, expectedHeader)) {
					throw new Error('OP_RETURN mismatch. The transaction does not contain the expected SGF1 manifest anchor.');
				}
				verificationMessage = 'Sugarchain SGF1 anchor verified against transaction ' + payload.txid + '.';
			}).catch(function (error) {
				if (/OP_RETURN mismatch/i.test(error.message || '')) {
					throw error;
				}
				verificationMessage = 'The txid is not available for verification yet. You may retry after propagation; capsule cryptography will still be checked locally.';
			});
		}).then(function () {
			return Crypto.unwrapFileKey(payload, record.privateKey, record.publicKey);
		}).then(function (fileKey) {
			clearPendingRecipient();
			state.pendingRecipient = {
				payload: payload,
				fileKey: fileKey
			};
			$('#relayDecryptFileBox').classList.remove('hidden');
			setNotice('#relayAnchorVerification', verificationMessage, payload.txid && /^Sugarchain/.test(verificationMessage) ? '' : 'warning');
			setNotice('#relayDecryptStatus', 'Encrypted file key unwrapped locally. Select the matching .sugarfile to decrypt it.');
			saveHistory(historyFromPayload(payload, 'recipient', 'scanned'));
			toast('Relay capsule accepted for this encryption key.');
			return true;
		}).catch(function (error) {
			clearPendingRecipient();
			$('#relayDecryptFileBox').classList.add('hidden');
			setNotice('#relayDecryptStatus', (error.message || 'Capsule validation failed.') + ' Rescan the QR or ask the sender for a new relay.', 'danger');
			toast(error.message || 'Relay capsule could not be opened.', 'danger');
			return false;
		});
	}

	function clearPendingRecipient() {
		if (state.pendingRecipient && state.pendingRecipient.fileKey) {
			state.pendingRecipient.fileKey.fill(0);
		}
		state.pendingRecipient = null;
	}

	function decryptSelectedFile() {
		var button = $('#relayDecryptFileButton');
		var file = $('#relayEncryptedFileInput').files[0];
		if (!state.pendingRecipient) {
			toast('Scan or paste a matching relay capsule first.', 'danger');
			return;
		}
		setBusy(button, true, 'Decrypting locally...');
		readFile(file).then(function (bytes) {
			return Crypto.decryptFile(state.pendingRecipient.payload, state.pendingRecipient.fileKey, bytes);
		}).then(function (plaintext) {
			var payload = state.pendingRecipient.payload;
			downloadBlob(new Blob([plaintext], { type: payload.file_type }), payload.file_name);
			plaintext.fill(0);
			saveHistory(historyFromPayload(payload, 'recipient', 'decrypted'));
			setNotice('#relayDecryptStatus', 'File decrypted locally and offered for download. No plaintext was uploaded.');
			clearPendingRecipient();
			$('#relayDecryptFileBox').classList.add('hidden');
			$('#relayEncryptedFileInput').value = '';
			toast('File decrypted locally.');
		}).catch(function (error) {
			setNotice('#relayDecryptStatus', error.message || 'File decryption failed.', 'danger');
			if (state.pendingRecipient) {
				saveHistory(historyFromPayload(state.pendingRecipient.payload, 'recipient', 'failed'));
			}
			toast(error.message || 'File decryption failed.', 'danger');
		}).finally(function () {
			setBusy(button, false);
		});
	}

	function renderHistory() {
		var target = $('#relayHistoryList');
		if (!target) {
			return;
		}
		ensureKeyLoaded().catch(function () {
			return null;
		}).then(function () {
			var records = historyList().filter(function (record) {
				return record.owner_hash === state.ownerId;
			});
			if (!records.length) {
				target.innerHTML = '<div class="activity-empty">No File Relay records are stored for this wallet.</div>';
				return;
			}
			target.innerHTML = records.map(function (record) {
				var noTxLabel = record.status === 'created' ? 'Awaiting anchor' : (record.status === 'failed' ? 'No anchor' : 'Off-chain');
				var tx = record.txid ? '<a class="relay-history-link" href="' + Bridge.explorerTx(record.txid) + '" target="_blank" rel="noopener">View transaction</a>' : '<span>' + noTxLabel + '</span>';
				return '<article class="relay-history-item">' +
					'<div class="relay-history-heading"><strong>' + escapeHtml(record.role) + '</strong><span>' + escapeHtml(record.status) + '</span></div>' +
					'<div class="relay-history-id">' + escapeHtml(record.capsule_id) + '</div>' +
					'<div class="relay-history-meta"><span>' + escapeHtml(formatDate(record.updated_at)) + '</span>' + tx + '</div>' +
					'</article>';
			}).join('');
		});
	}

	function escapeHtml(value) {
		return String(value || '')
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#039;');
	}

	function formatDate(value) {
		try {
			return new Date(value).toLocaleString();
		} catch (error) {
			return value;
		}
	}

	function exportKeyBackup(event) {
		event.preventDefault();
		var button = $('#relayExportBackupButton');
		var password = $('#relayBackupPassword').value;
		if (password !== $('#relayBackupPasswordConfirm').value) {
			toast('Relay backup passwords do not match.', 'danger');
			return;
		}
		setBusy(button, true, 'Encrypting backup...');
		ensureKeyLoaded().then(function (record) {
			if (!record) {
				throw new Error('Generate the relay encryption key first.');
			}
			return Crypto.exportEncryptedKeyBackup(record.privateKey, record.publicKey, state.ownerId, password);
		}).then(function (backup) {
			downloadBlob(new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' }), 'sweetwallet-file-relay-key-backup.json');
			$('#relayBackupPassword').value = '';
			$('#relayBackupPasswordConfirm').value = '';
			toast('Encrypted File Relay key backup downloaded.');
		}).catch(function (error) {
			toast(error.message || 'Relay key backup could not be exported.', 'danger');
		}).finally(function () {
			setBusy(button, false);
		});
	}

	function importKeyBackup(event) {
		event.preventDefault();
		var button = $('#relayImportBackupButton');
		var file = $('#relayBackupFile').files[0];
		var password = $('#relayImportBackupPassword').value;
		var imported;
		if (!file) {
			toast('Select an encrypted relay key backup file.', 'danger');
			return;
		}
		setBusy(button, true, 'Importing key...');
		Promise.resolve().then(function () {
			walletContext();
			return file.text();
		}).then(function (text) {
			return Crypto.importEncryptedKeyBackup(JSON.parse(text), password);
		}).then(function (result) {
			imported = result;
			return ownerIdForAddress(walletContext().address);
		}).then(function (ownerId) {
			if (state.keyRecord && !window.confirm('Replace the existing File Relay encryption key for this wallet? Old capsules will require the backup of the old key.')) {
				throw new Error('Relay key import cancelled.');
			}
			state.ownerId = ownerId;
			var record = {
				ownerId: ownerId,
				ownerAddress: walletContext().address,
				keyType: Crypto.KEY_TYPE,
				publicKey: imported.publicKey,
				privateKey: imported.privateKey,
				label: '',
				createdAt: imported.createdAt,
				updatedAt: new Date().toISOString()
			};
			return putStoredKey(record).then(function () {
				state.keyRecord = record;
			});
		}).then(function () {
			$('#relayBackupFile').value = '';
			$('#relayImportBackupPassword').value = '';
			renderKeySetup();
			toast('File Relay encryption key imported for this wallet.');
		}).catch(function (error) {
			toast(error.message || 'Relay key backup import failed.', 'danger');
		}).finally(function () {
			setBusy(button, false);
		});
	}

	function importRelayJson(file) {
		if (!file) {
			return;
		}
		file.text().then(function (text) {
			$('#relayCapsuleInput').value = text;
			return parseCapsuleInput(text);
		}).catch(function (error) {
			setNotice('#relayDecryptStatus', error.message || 'Relay JSON could not be read.', 'danger');
		});
	}

	function handleScannedRecipient(raw) {
		try {
			var recipient = Crypto.parseRecipientPublicKey(raw);
			$('#relayRecipientKey').value = recipient.publicKey;
			if (recipient.label && !$('#relayRecipientLabel').value) {
				$('#relayRecipientLabel').value = recipient.label;
			}
			toast('Recipient encryption key filled from QR.');
			return true;
		} catch (error) {
			return false;
		}
	}

	function handleScannedCapsule(raw) {
		try {
			Crypto.decodeRelayPayload(raw);
		} catch (error) {
			return false;
		}
		$('#relayCapsuleInput').value = raw;
		parseCapsuleInput(raw);
		return true;
	}

	function resetTransientState() {
		clearPendingRecipient();
		if (state.currentRelay && state.currentRelay.encryptedFile) {
			state.currentRelay.encryptedFile.fill(0);
		}
		state.currentRelay = null;
		state.keyRecord = null;
		state.ownerId = '';
		$('#relayEncryptOutput').classList.add('hidden');
		$('#relayCapsuleOutput').classList.add('hidden');
		$('#relayDecryptFileBox').classList.add('hidden');
	}

	function onPanelOpen() {
		showView('home');
		ensureKeyLoaded().then(function (record) {
			$('#relayHomeKeyStatus').textContent = record ? 'Encryption key ready' : 'Set up your encryption key first';
		}).catch(function (error) {
			$('#relayHomeKeyStatus').textContent = error.message || 'Encryption key unavailable';
		});
	}

	function wireEvents() {
		$$('[data-relay-action]').forEach(function (button) {
			button.addEventListener('click', function () {
				showView(button.dataset.relayAction);
			});
		});
		$$('[data-relay-home]').forEach(function (button) {
			button.addEventListener('click', function () {
				showView('home');
			});
		});
		$('#relayGenerateKey').addEventListener('click', generateEncryptionKey);
		$('#relaySaveLabel').addEventListener('click', saveKeyLabel);
		$('#relayCopyPublicKey').addEventListener('click', function () {
			Bridge.copyValue($('#relayPublicKey').value);
		});
		$('#relayCopyRecipientUri').addEventListener('click', function () {
			Bridge.copyValue($('#relayRecipientUri').value);
		});
		$('#relayEncryptForm').addEventListener('submit', prepareEncryption);
		$('#relayDownloadEncrypted').addEventListener('click', downloadEncryptedFile);
		$('#relayReviewAnchor').addEventListener('click', openAnchorConfirmation);
		$('#relayCancelBroadcast').addEventListener('click', closeAnchorConfirmation);
		$('#relayConfirmBroadcast').addEventListener('click', confirmAnchorBroadcast);
		$('#relayCopyCapsule').addEventListener('click', function () {
			Bridge.copyValue($('#relayCapsuleUri').value);
		});
		$('#relayCopyTxid').addEventListener('click', function () {
			var txid = state.currentRelay && state.currentRelay.payload && state.currentRelay.payload.txid;
			if (txid) {
				Bridge.copyValue(txid);
			}
		});
		$('#relayDownloadJson').addEventListener('click', downloadRelayJson);
		$('#relayScanRecipient').addEventListener('click', function () {
			Bridge.openQrScanner('relay-recipient');
		});
		$('#relayScanCapsule').addEventListener('click', function () {
			Bridge.openQrScanner('relay-capsule');
		});
		$('#relayOpenCapsule').addEventListener('click', function () {
			parseCapsuleInput($('#relayCapsuleInput').value);
		});
		$('#relayImportJsonFile').addEventListener('change', function () {
			importRelayJson($('#relayImportJsonFile').files[0]);
		});
		$('#relayDecryptFileButton').addEventListener('click', decryptSelectedFile);
		$('#relaySwitchBackend').addEventListener('click', function () {
			Bridge.switchTab('settings');
		});
		$('#relayExportBackupForm').addEventListener('submit', exportKeyBackup);
		$('#relayImportBackupForm').addEventListener('submit', importKeyBackup);
	}

	function init() {
		Bridge = window.SweetWalletFileRelayBridge;
		if (!Crypto || !Bridge || !$('#fileRelayPanel')) {
			return;
		}
		wireEvents();
		$('#relayFeeAmount').textContent = Bridge.getWalletContext().feeSugar + ' SUGAR';
		window.addEventListener('sweetwallet:sensitive-cleared', resetTransientState);
	}

	window.SweetWalletFileRelay = {
		handleScannedRecipient: handleScannedRecipient,
		handleScannedCapsule: handleScannedCapsule,
		onPanelOpen: onPanelOpen,
		clearSensitive: resetTransientState
	};

	document.addEventListener('DOMContentLoaded', init);
}());
