(function () {
	'use strict';

	var SUGAR_NETWORK = {
		messagePrefix: '\x19Sugarchain Signed Message:\n',
		bip32: {
			public: 0x0488b21e,
			private: 0x0488ade4
		},
		bech32: 'sugar',
		pubKeyHash: 0x3F,
		scriptHash: 0x7D,
		wif: 0x80
	};

	var CONFIG = {
		ticker: 'SUGAR',
		decimals: 8,
		fee: 0.00001,
		uri: 'sugarchain:',
		primaryApi: 'https://api.sugar.wtf',
		fallbackApi: 'https://api.sugarchain.org',
		explorerAddress: function (address) {
			return 'https://sugar.wtf/#/address/' + encodeURIComponent(address);
		},
		explorerTx: function (txid) {
			return 'https://sugar.wtf/#/transaction/' + encodeURIComponent(txid);
		}
	};

	var Vault = window.SweetWalletVault;
	var STORAGE = {
		vault: 'sweetwallet_vault_v1',
		publicWallet: 'sweetwallet_public_wallet_v1',
		settings: 'sweetwallet_security_settings_v1',
		securityKeys: 'sweetwallet_security_keys_v1',
		recoveryCodes: 'sweetwallet_recovery_codes_v1'
	};

	var state = {
		keys: null,
		address: '',
		publicKeyHex: '',
		walletId: '',
		mode: 'closed',
		loginMode: 'pin',
		pinSubmitting: false,
		lockedUnlockMode: 'pin',
		lockedPinSubmitting: false,
		savedVault: null,
		publicWallet: null,
		settings: defaultSettings(),
		autoLockTimer: 0,
		backgroundAt: 0,
		balance: 0,
		fee: CONFIG.fee,
		timer: 0,
		lastTxHex: '',
		pendingTx: null,
		pendingPlan: null,
		broadcasting: false,
		showFullBalance: false,
		activity: {
			loaded: false,
			loading: false,
			offset: 0,
			total: 0,
			records: []
		},
		qrScanner: {
			active: false,
			stream: null,
			frame: 0,
			detecting: false,
			lastInvalid: ''
		},
		starterFundingRequested: {}
	};

	var $ = function (selector) {
		return document.querySelector(selector);
	};

	var $$ = function (selector) {
		return Array.prototype.slice.call(document.querySelectorAll(selector));
	};

	function storageGet(key, fallback) {
		try {
			var value = window.localStorage.getItem(key);
			return value || fallback;
		} catch (error) {
			return fallback;
		}
	}

	function storageSet(key, value) {
		try {
			window.localStorage.setItem(key, value);
		} catch (error) {
			// Non-sensitive preference only.
		}
	}

	function storageRemove(key) {
		try {
			window.localStorage.removeItem(key);
		} catch (error) {
			// Ignore storage failures.
		}
	}

	function storageJsonGet(key, fallback) {
		try {
			var value = window.localStorage.getItem(key);
			return value ? JSON.parse(value) : fallback;
		} catch (error) {
			return fallback;
		}
	}

	function storageJsonSet(key, value) {
		try {
			window.localStorage.setItem(key, JSON.stringify(value));
			return true;
		} catch (error) {
			showToast('Device storage is unavailable.', 'danger');
			return false;
		}
	}

	function defaultSettings() {
		return {
			autoLockMs: 300000,
			requirePasswordBeforeSend: false,
			requirePinBeforeSend: false,
			requireSecurityKeyBeforeSend: false,
			requireConfirmEveryTx: true,
			securityKeyRequired: false
		};
	}

	function loadSettings() {
		state.settings = Object.assign(defaultSettings(), storageJsonGet(STORAGE.settings, {}));
		state.settings.requireConfirmEveryTx = true;
		state.settings.securityKeyRequired = !!state.settings.requireSecurityKeyBeforeSend;
	}

	function saveSettings() {
		state.settings.securityKeyRequired = !!state.settings.requireSecurityKeyBeforeSend;
		state.settings.requireConfirmEveryTx = true;
		storageJsonSet(STORAGE.settings, state.settings);
		renderSecurityUi();
		resetAutoLockTimer();
	}

	function loadStoredRecords() {
		state.savedVault = storageJsonGet(STORAGE.vault, null);
		state.publicWallet = storageJsonGet(STORAGE.publicWallet, null);
	}

	function saveVaultRecord(record) {
		state.savedVault = record;
		storageJsonSet(STORAGE.vault, record);
		savePublicWallet({
			walletId: record.walletId,
			address: record.address,
			publicKey: record.publicKey || '',
			mode: 'saved',
			updatedAt: new Date().toISOString()
		});
	}

	function savePublicWallet(record) {
		state.publicWallet = Object.assign({
			network: Vault ? Vault.NETWORK : 'sugarchain-mainnet',
			createdAt: new Date().toISOString()
		}, record);
		storageJsonSet(STORAGE.publicWallet, state.publicWallet);
	}

	function hasQuickPin(record) {
		return !!(record && record.quickUnlock && record.quickUnlock.enabled);
	}

	function vaultAvailabilityError() {
		if (!Vault || !Vault.availabilityError) {
			return 'Encrypted storage support did not load.';
		}
		return Vault.availabilityError();
	}

	function setDisabled(selector, disabled, title) {
		var element = $(selector);
		if (!element) {
			return;
		}
		element.disabled = !!disabled;
		element.title = disabled ? (title || '') : '';
	}

	function setSecurityCapabilityNotice(message, tone) {
		var notice = $('#securityCapabilityNotice');
		if (!notice) {
			return;
		}
		notice.textContent = message || 'Saving the private key is optional. SweetWallet can keep this wallet session-only, or save it encrypted when this browser connection supports Web Crypto.';
		notice.classList.toggle('danger', tone === 'danger');
	}

	function openSecureDb() {
		return new Promise(function (resolve, reject) {
			if (!window.indexedDB) {
				reject(new Error('Browser secure storage is unavailable.'));
				return;
			}
			var request = window.indexedDB.open('sweetwallet_secure_store', 1);
			request.onupgradeneeded = function () {
				request.result.createObjectStore('keys', {
					keyPath: 'id'
				});
			};
			request.onsuccess = function () {
				resolve(request.result);
			};
			request.onerror = function () {
				reject(new Error('Browser secure storage is unavailable.'));
			};
		});
	}

	function dbGet(store, key) {
		return new Promise(function (resolve, reject) {
			var request = store.get(key);
			request.onsuccess = function () {
				resolve(request.result || null);
			};
			request.onerror = function () {
				reject(new Error('Secure storage read failed.'));
			};
		});
	}

	function dbPut(store, value) {
		return new Promise(function (resolve, reject) {
			var request = store.put(value);
			request.onsuccess = resolve;
			request.onerror = function () {
				reject(new Error('Secure storage write failed.'));
			};
		});
	}

	function dbDelete(store, key) {
		return new Promise(function (resolve, reject) {
			var request = store.delete(key);
			request.onsuccess = resolve;
			request.onerror = function () {
				reject(new Error('Secure storage delete failed.'));
			};
		});
	}

	function getDeviceKey(createIfMissing) {
		var dbRef;
		return openSecureDb().then(function (db) {
			dbRef = db;
			var tx = db.transaction('keys', 'readonly');
			return dbGet(tx.objectStore('keys'), 'quick-pin-device-key');
		}).then(function (record) {
			if (record && record.key) {
				dbRef.close();
				return record.key;
			}
			if (!createIfMissing) {
				dbRef.close();
				throw new Error('Quick-unlock secure storage is unavailable.');
			}
			return window.crypto.subtle.generateKey({
				name: 'AES-GCM',
				length: 256
			}, false, ['encrypt', 'decrypt']).then(function (key) {
				var tx = dbRef.transaction('keys', 'readwrite');
				return dbPut(tx.objectStore('keys'), {
					id: 'quick-pin-device-key',
					key: key,
					createdAt: new Date().toISOString()
				}).then(function () {
					dbRef.close();
					return key;
				});
			});
		});
	}

	function deleteDeviceKey() {
		return openSecureDb().then(function (db) {
			var tx = db.transaction('keys', 'readwrite');
			return dbDelete(tx.objectStore('keys'), 'quick-pin-device-key').finally(function () {
				db.close();
			});
		}).catch(function () {
			// Best effort. The encrypted PIN wrap is removed from localStorage too.
		});
	}

	function getBackend() {
		return storageGet('sweetwallet_backend', CONFIG.primaryApi).replace(/\/+$/, '');
	}

	function setBackend(url) {
		storageSet('sweetwallet_backend', url.replace(/\/+$/, ''));
	}

	function getAddressType() {
		var type = storageGet('sweetwallet_address_type', 'bech32');
		return ['bech32', 'segwit', 'legacy'].indexOf(type) >= 0 ? type : 'bech32';
	}

	function setAddressType(type) {
		if (['bech32', 'segwit', 'legacy'].indexOf(type) >= 0) {
			storageSet('sweetwallet_address_type', type);
		}
	}

	function backendCandidates() {
		var seen = {};
		return [getBackend(), CONFIG.primaryApi, CONFIG.fallbackApi].filter(function (url) {
			url = url.replace(/\/+$/, '');
			if (seen[url]) {
				return false;
			}
			seen[url] = true;
			return true;
		});
	}

	function requestApi(path, options) {
		var urls = backendCandidates();
		var lastError = null;
		var index = 0;

		function tryNext() {
			var base = urls[index++];
			if (!base) {
				throw lastError || new Error('All Sugarchain API backends are unavailable.');
			}

			return fetch(base + path, options).then(function (response) {
				if (!response.ok) {
					throw new Error('HTTP ' + response.status);
				}
				return response.json();
			}).then(function (data) {
				if (base !== getBackend()) {
					setBackend(base);
					updateBackendUi();
				}
				return data;
			}).catch(function (error) {
				lastError = error;
				return tryNext();
			});
		}

		return tryNext();
	}

	function formatAmount(satoshis) {
		var value = Number(satoshis || 0) / Math.pow(10, CONFIG.decimals);
		return value.toLocaleString(undefined, {
			minimumFractionDigits: 0,
			maximumFractionDigits: CONFIG.decimals
		});
	}

	function formatBalance(satoshis, full) {
		var value = Number(satoshis || 0) / Math.pow(10, CONFIG.decimals);
		return value.toLocaleString(undefined, {
			minimumFractionDigits: full ? CONFIG.decimals : 4,
			maximumFractionDigits: full ? CONFIG.decimals : 4
		});
	}

	function amountToSatoshis(value) {
		var normalized = String(value || '').trim();
		if (!/^\d+(\.\d{1,8})?$/.test(normalized)) {
			return NaN;
		}
		return Math.round(Number(normalized) * Math.pow(10, CONFIG.decimals));
	}

	function shortAddress(address) {
		if (!address) {
			return '';
		}
		return address.length > 18 ? address.slice(0, 10) + '...' + address.slice(-8) : address;
	}

	function escapeHtml(value) {
		return String(value === undefined || value === null ? '' : value)
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#039;');
	}

	function hexToBytes(hex) {
		var clean = String(hex || '').trim();
		var bytes = new Uint8Array(clean.length / 2);
		for (var index = 0; index < clean.length; index += 2) {
			bytes[index / 2] = parseInt(clean.slice(index, index + 2), 16);
		}
		return bytes;
	}

	function formatDate(seconds) {
		if (!seconds) {
			return 'Pending';
		}
		try {
			return new Date(Number(seconds) * 1000).toLocaleDateString(undefined, {
				month: 'short',
				day: 'numeric',
				year: 'numeric'
			});
		} catch (error) {
			return 'Confirmed';
		}
	}

	function resetActivity() {
		state.activity = {
			loaded: false,
			loading: false,
			offset: 0,
			total: 0,
			records: []
		};
		renderActivity();
	}

	function showToast(message, tone) {
		var toast = $('#toast');
		toast.textContent = message || '';
		toast.className = 'toast' + (tone ? ' ' + tone : '');
		window.clearTimeout(showToast.timer);
		if (message) {
			showToast.timer = window.setTimeout(function () {
				toast.textContent = '';
			}, 3600);
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
			button.innerHTML = text || 'Working...';
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

	function getP2WPKHScript(pubkey) {
		return bitcoin.payments.p2wpkh({
			pubkey: pubkey,
			network: SUGAR_NETWORK
		});
	}

	function getP2SHScript(redeem) {
		return bitcoin.payments.p2sh({
			redeem: redeem,
			network: SUGAR_NETWORK
		});
	}

	function getAddress(keys) {
		var type = getAddressType();
		if (type === 'segwit') {
			return bitcoin.payments.p2sh({
				redeem: getP2WPKHScript(keys.publicKey),
				network: SUGAR_NETWORK
			}).address;
		}
		if (type === 'legacy') {
			return bitcoin.payments.p2pkh({
				pubkey: keys.publicKey,
				network: SUGAR_NETWORK
			}).address;
		}
		return bitcoin.payments.p2wpkh({
			pubkey: keys.publicKey,
			network: SUGAR_NETWORK
		}).address;
	}

	function getScriptType(script) {
		if (script[0] === bitcoin.opcodes.OP_0 && script[1] === 20) {
			return 'bech32';
		}
		if (script[0] === bitcoin.opcodes.OP_HASH160 && script[1] === 20) {
			return 'segwit';
		}
		if (script[0] === bitcoin.opcodes.OP_DUP &&
			script[1] === bitcoin.opcodes.OP_HASH160 &&
			script[2] === 20) {
			return 'legacy';
		}
		return '';
	}

	function validateAddress(address) {
		address = String(address || '').trim();
		if (!address) {
			return false;
		}
		try {
			var base58 = bitcoin.address.fromBase58Check(address);
			return base58.version === SUGAR_NETWORK.pubKeyHash || base58.version === SUGAR_NETWORK.scriptHash;
		} catch (error) {
			try {
				var bech32 = bitcoin.address.fromBech32(address);
				return bech32.prefix === SUGAR_NETWORK.bech32;
			} catch (nested) {
				return false;
			}
		}
	}

	function parsePaymentTarget(raw) {
		var value = String(raw || '').trim();
		if (value.toLowerCase().indexOf('sugarchain:') === 0) {
			var noScheme = value.slice('sugarchain:'.length);
			var pieces = noScheme.split('?');
			var params = new URLSearchParams(pieces[1] || '');
			var amount = params.get('amount');
			return {
				address: pieces[0],
				amount: amount
			};
		}
		return {
			address: value,
			amount: ''
		};
	}

	function qrScannerSupported() {
		return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia && (window.jsQR || window.BarcodeDetector));
	}

	function setQrScannerStatus(message, tone) {
		var status = $('#qrScannerStatus');
		if (!status) {
			return;
		}
		status.textContent = message || '';
		status.className = 'notice' + (tone ? ' ' + tone : '');
	}

	function fillRecipientFromQr(raw) {
		var target = parsePaymentTarget(raw);
		if (!validateAddress(target.address)) {
			return false;
		}
		$('#sendAddress').value = target.address;
		if (target.amount) {
			$('#sendAmount').value = target.amount;
		}
		$('#sendAddress').dispatchEvent(new Event('input', { bubbles: true }));
		stopQrScanner();
		showToast('Recipient filled from QR.');
		return true;
	}

	function decodeQrFromCanvas(canvas, imageData) {
		if (window.jsQR) {
			var result = window.jsQR(imageData.data, imageData.width, imageData.height, {
				inversionAttempts: 'attemptBoth'
			});
			return Promise.resolve(result && result.data);
		}
		if (window.BarcodeDetector) {
			if (!state.qrScanner.detector) {
				state.qrScanner.detector = new window.BarcodeDetector({
					formats: ['qr_code']
				});
			}
			return state.qrScanner.detector.detect(canvas).then(function (codes) {
				return codes && codes[0] && (codes[0].rawValue || codes[0].rawData);
			});
		}
		return Promise.resolve('');
	}

	function scanQrFrame() {
		if (!state.qrScanner.active) {
			return;
		}
		var video = $('#qrScannerVideo');
		var canvas = $('#qrScannerCanvas');
		if (!video || !canvas) {
			return;
		}
		if (video.readyState >= 2 && video.videoWidth && video.videoHeight && !state.qrScanner.detecting) {
			canvas.width = video.videoWidth;
			canvas.height = video.videoHeight;
			var context = canvas.getContext('2d', { willReadFrequently: true });
			context.drawImage(video, 0, 0, canvas.width, canvas.height);
			var imageData = context.getImageData(0, 0, canvas.width, canvas.height);
			state.qrScanner.detecting = true;
			decodeQrFromCanvas(canvas, imageData).then(function (text) {
				if (!state.qrScanner.active || !text) {
					return;
				}
				if (!fillRecipientFromQr(text) && text !== state.qrScanner.lastInvalid) {
					state.qrScanner.lastInvalid = text;
					setQrScannerStatus('QR found, but it is not a Sugarchain receive address.', 'warning');
				}
			}).catch(function () {
				setQrScannerStatus('Could not read that QR. Try better light or move closer.', 'warning');
			}).finally(function () {
				state.qrScanner.detecting = false;
				if (state.qrScanner.active) {
					state.qrScanner.frame = window.requestAnimationFrame(scanQrFrame);
				}
			});
			return;
		}
		state.qrScanner.frame = window.requestAnimationFrame(scanQrFrame);
	}

	function openQrScanner() {
		if (!window.isSecureContext) {
			showToast('Camera scanning requires HTTPS or localhost.', 'danger');
			return;
		}
		if (!qrScannerSupported()) {
			showToast('QR camera scanning is not available in this browser.', 'danger');
			return;
		}
		state.qrScanner.active = true;
		state.qrScanner.lastInvalid = '';
		setQrScannerStatus('Point your camera at a Sugarchain receive QR.');
		$('#qrScannerModal').classList.add('active');
		navigator.mediaDevices.getUserMedia({
			video: {
				facingMode: {
					ideal: 'environment'
				}
			},
			audio: false
		}).then(function (stream) {
			if (!state.qrScanner.active) {
				stream.getTracks().forEach(function (track) {
					track.stop();
				});
				return;
			}
			state.qrScanner.stream = stream;
			$('#qrScannerVideo').srcObject = stream;
			return $('#qrScannerVideo').play();
		}).then(function () {
			if (state.qrScanner.active) {
				scanQrFrame();
			}
		}).catch(function (error) {
			stopQrScanner();
			showToast(error && error.name === 'NotAllowedError' ? 'Camera access was blocked.' : 'Camera could not start.', 'danger');
		});
	}

	function stopQrScanner() {
		state.qrScanner.active = false;
		state.qrScanner.detecting = false;
		if (state.qrScanner.frame) {
			window.cancelAnimationFrame(state.qrScanner.frame);
			state.qrScanner.frame = 0;
		}
		if (state.qrScanner.stream) {
			state.qrScanner.stream.getTracks().forEach(function (track) {
				track.stop();
			});
			state.qrScanner.stream = null;
		}
		if ($('#qrScannerVideo')) {
			$('#qrScannerVideo').pause();
			$('#qrScannerVideo').srcObject = null;
		}
		if ($('#qrScannerModal')) {
			$('#qrScannerModal').classList.remove('active');
		}
	}

	function createKeys() {
		return bitcoin.ECPair.makeRandom({
			network: SUGAR_NETWORK
		});
	}

	function renderQr(text) {
		var target = $('#receiveQr');
		target.innerHTML = '';
		if (window.jQuery && window.jQuery.fn && window.jQuery.fn.qrcode) {
			window.jQuery(target).qrcode({
				text: text,
				width: 216,
				height: 216
			});
		} else {
			target.textContent = text;
		}
	}

	function renderKeys() {
		if (!state.address) {
			return;
		}
		var pubkey = state.publicKeyHex || (state.keys ? state.keys.publicKey.toString('hex') : '');
		var redeem = '';
		if (pubkey) {
			try {
				redeem = '0014' + getP2WPKHScript(bitcoin.Buffer(pubkey, 'hex')).hash.toString('hex');
			} catch (error) {
				redeem = '';
			}
		}
		$('#keyAddress').value = state.address;
		$('#keyPublic').value = pubkey;
		$('#keyRedeem').value = redeem;
	}

	function updateBackendUi() {
		$('#backendInput').value = getBackend();
		$('#activeBackend').textContent = getBackend().replace(/^https?:\/\//, '');
	}

	function updateBalanceUi(loading) {
		var display = loading ? 'Loading' : formatBalance(state.balance, state.showFullBalance);
		var chipDisplay = loading ? 'Loading' : formatBalance(state.balance, false);
		$('#balanceMain').textContent = display;
		$('#balanceChipAmount').textContent = chipDisplay;
		$('#balanceChipTicker').textContent = CONFIG.ticker;
		$('#sendAvailable').textContent = loading ? 'Loading' : formatAmount(state.balance) + ' ' + CONFIG.ticker;
		var toggle = $('#toggleBalancePrecision');
		if (toggle) {
			toggle.setAttribute('aria-expanded', state.showFullBalance ? 'true' : 'false');
			toggle.setAttribute('aria-label', state.showFullBalance ? 'Show rounded balance' : 'Show full balance');
			toggle.innerHTML = state.showFullBalance ? '<i data-lucide="chevrons-up-down"></i>' : '<i data-lucide="chevrons-down-up"></i>';
			if (window.lucide) {
				window.lucide.createIcons();
			}
		}
	}

	function outputAddresses(output) {
		return output && output.scriptPubKey && output.scriptPubKey.addresses ? output.scriptPubKey.addresses : [];
	}

	function inputAddresses(input) {
		return input && input.scriptPubKey && input.scriptPubKey.addresses ? input.scriptPubKey.addresses : [];
	}

	function uniqueAddresses(addresses) {
		var seen = {};
		return addresses.filter(function (address) {
			if (!address || seen[address]) {
				return false;
			}
			seen[address] = true;
			return true;
		});
	}

	function normalizeTransaction(tx) {
		var inputs = tx.vin || [];
		var outputs = tx.vout || [];
		var inputTotal = inputs.reduce(function (sum, input) {
			return sum + Number(input.value || 0);
		}, 0);
		var outputTotal = outputs.reduce(function (sum, output) {
			return sum + Number(output.value || 0);
		}, 0);
		var fromWallet = inputs.reduce(function (sum, input) {
			return inputAddresses(input).indexOf(state.address) >= 0 ? sum + Number(input.value || 0) : sum;
		}, 0);
		var toWallet = outputs.reduce(function (sum, output) {
			return outputAddresses(output).indexOf(state.address) >= 0 ? sum + Number(output.value || 0) : sum;
		}, 0);
		var net = toWallet - fromWallet;
		var fee = Math.max(0, inputTotal - outputTotal);
		var txid = tx.txid || tx.hash || '';
		var fromAddresses = uniqueAddresses(inputs.reduce(function (addresses, input) {
			return addresses.concat(inputAddresses(input).filter(function (address) {
				return address !== state.address;
			}));
		}, []));
		var toAddresses = uniqueAddresses(outputs.reduce(function (addresses, output) {
			return addresses.concat(outputAddresses(output).filter(function (address) {
				return address !== state.address;
			}));
		}, []));
		var received = net >= 0;
		return {
			txid: txid,
			net: net,
			fee: fee,
			time: tx.time || tx.blocktime || 0,
			confirmations: Number(tx.confirmations || 0),
			height: tx.height || 0,
			detailLabel: received ? 'From' : 'To',
			detailAddresses: received ? fromAddresses : toAddresses
		};
	}

	function renderActivity() {
		var list = $('#activityList');
		var summary = $('#activityCount');
		var loadMore = $('#loadMoreActivity');
		if (!list || !summary || !loadMore) {
			return;
		}

		if (state.activity.loading && state.activity.records.length === 0) {
			list.innerHTML = '<div class="activity-empty">Loading transactions...</div>';
			summary.textContent = 'Loading transactions';
			loadMore.classList.add('hidden');
			return;
		}

		if (!state.activity.records.length) {
			list.innerHTML = '<div class="activity-empty">' + (state.activity.loaded ? 'No transactions found for this address.' : 'Open Activity to load address transactions.') + '</div>';
			summary.textContent = state.activity.loaded ? '0 transactions' : 'No transactions loaded';
			loadMore.classList.add('hidden');
			return;
		}

		summary.textContent = state.activity.records.length + ' of ' + state.activity.total + ' transactions';
		list.innerHTML = state.activity.records.map(function (record, index) {
			var received = record.net >= 0;
			var pending = record.confirmations <= 0;
			var rowClass = pending ? 'pending' : (received ? 'received' : 'sent');
			var title = pending ? 'Pending transaction' : (received ? 'Received SUGAR' : 'Sent SUGAR');
			var amountPrefix = record.net > 0 ? '+' : '';
			var feeText = record.fee > 0 ? 'Fee ' + formatAmount(record.fee) : 'Fee 0';
			var detailId = 'activity-detail-' + index;
			var detailAddresses = record.detailAddresses && record.detailAddresses.length ? record.detailAddresses : ['Unknown'];
			var addressHtml = detailAddresses.map(function (address) {
				if (validateAddress(address)) {
					return '<a class="activity-address activity-address-link" href="' + CONFIG.explorerAddress(address) + '" target="_blank" rel="noopener">' + escapeHtml(address) + '</a>';
				}
				return '<div class="activity-address">' + escapeHtml(address) + '</div>';
			}).join('');
			return '<div class="activity-item ' + rowClass + '">' +
				'<button class="activity-row" type="button" data-activity-toggle="' + detailId + '" aria-expanded="false">' +
					'<span class="activity-main">' +
						'<span class="activity-title">' + title + '</span>' +
						'<span class="activity-meta">' + escapeHtml(formatDate(record.time)) + '</span>' +
					'</span>' +
					'<span class="activity-side">' +
						'<span class="activity-amount">' + amountPrefix + formatAmount(record.net) + ' SUGAR</span>' +
					'</span>' +
				'</button>' +
				'<div id="' + detailId + '" class="activity-details hidden">' +
					'<div class="activity-detail-label">' + escapeHtml(record.detailLabel) + '</div>' +
					addressHtml +
					'<div class="activity-detail-label mt">Transaction</div>' +
					'<div class="activity-address">' + escapeHtml(record.txid) + '</div>' +
					'<div class="activity-detail-grid">' +
						'<span><span class="activity-detail-label">Confirmations</span><span class="activity-detail-value">' + record.confirmations + ' conf</span></span>' +
						'<span><span class="activity-detail-label">Fee</span><span class="activity-detail-value">' + feeText.replace(/^Fee /, '') + ' SUGAR</span></span>' +
					'</div>' +
					'<a class="activity-link" href="' + CONFIG.explorerTx(record.txid) + '" target="_blank" rel="noopener">View on blockchain explorer</a>' +
				'</div>' +
			'</div>';
		}).join('');
		loadMore.classList.toggle('hidden', state.activity.records.length >= state.activity.total);
		if (window.lucide) {
			window.lucide.createIcons();
		}
	}

	function loadActivity(reset) {
		if (!state.address || state.activity.loading) {
			return Promise.resolve();
		}
		if (reset) {
			state.activity.loaded = false;
			state.activity.offset = 0;
			state.activity.total = 0;
			state.activity.records = [];
		}
		state.activity.loading = true;
		renderActivity();
		var offset = state.activity.offset;
		return requestApi('/history/' + encodeURIComponent(state.address) + '?offset=' + encodeURIComponent(offset)).then(function (data) {
			if (data.error) {
				throw new Error(data.error.message || 'Unable to load activity.');
			}
			var result = data.result || {};
			var txids = result.tx || [];
			state.activity.total = Number(result.txcount || txids.length || state.activity.records.length);
			return Promise.all(txids.map(function (txid) {
				return requestApi('/transaction/' + encodeURIComponent(txid)).then(function (txData) {
					if (txData.error) {
						throw new Error(txData.error.message || 'Unable to load transaction.');
					}
					return normalizeTransaction(txData.result || {});
				});
			}));
		}).then(function (records) {
			var known = {};
			state.activity.records.forEach(function (record) {
				known[record.txid] = true;
			});
			records.forEach(function (record) {
				if (record.txid && !known[record.txid]) {
					state.activity.records.push(record);
					known[record.txid] = true;
				}
			});
			state.activity.offset = state.activity.records.length;
			state.activity.loaded = true;
		}).catch(function (error) {
			showToast(error.message || 'Activity load failed.', 'danger');
			state.activity.loaded = true;
		}).finally(function () {
			state.activity.loading = false;
			renderActivity();
		});
	}

	function walletStatusText() {
		if (!state.address) {
			return 'No wallet';
		}
		if (state.mode === 'watch') {
			return shortAddress(state.address) + ' watch-only';
		}
		if (state.mode === 'locked') {
			return shortAddress(state.address) + ' locked';
		}
		if (state.mode === 'saved') {
			return shortAddress(state.address) + ' saved';
		}
		return shortAddress(state.address) + ' session';
	}

	function updateAccessUi() {
		var canSign = !!state.keys;
		var isWatch = state.mode === 'watch';
		var isLocked = state.mode === 'locked';
		$$('[data-tab="send"]').forEach(function (button) {
			button.disabled = !canSign;
			button.title = canSign ? '' : (isWatch ? 'Watch-only wallets cannot send.' : 'Unlock the wallet before sending.');
		});
		if ($('#savedWalletInfo')) {
			$('#savedWalletInfo').classList.toggle('hidden', !state.savedVault);
		}
		if ($('#savedWalletAddress')) {
			$('#savedWalletAddress').textContent = state.savedVault ? shortAddress(state.savedVault.address) : 'None';
		}
		if (isLocked) {
			$('#securityStatus').textContent = 'Wallet is locked. Unlock it before saving new credentials or sending.';
		}
		updateLoginUi();
		updateLockedUi();
		updateMenuUi();
	}

	function updateMenuUi() {
		var isLocked = state.mode === 'locked';
		$$('#menuSheet .menu-item[data-tab]').forEach(function (button) {
			button.disabled = isLocked;
			button.title = isLocked ? 'Unlock the wallet to use this menu item.' : '';
		});
		if ($('#menuLockButton')) {
			var canLock = !!state.keys && !!state.savedVault && state.mode === 'saved';
			$('#menuLockButton').disabled = !canLock;
			$('#menuLockButton').title = canLock ? '' :
				(isLocked ? 'Wallet is already locked.' :
					(!state.savedVault || state.mode === 'session' ? 'Save this wallet before locking.' : 'Unlock the wallet before locking.'));
		}
	}

	function setLoginMode(mode) {
		if (['pin', 'password', 'privateKey'].indexOf(mode) < 0) {
			mode = 'pin';
		}
		state.loginMode = mode;
		if ($('#loginSecret')) {
			$('#loginSecret').value = '';
		}
		updateLoginUi();
	}

	function pinValue() {
		return ($('#pinInput') && $('#pinInput').value || '').replace(/\D/g, '').slice(0, 6);
	}

	function updatePinBoxes() {
		var value = pinValue();
		if ($('#pinInput')) {
			$('#pinInput').value = value;
		}
		$$('#pinEntry .pin-box').forEach(function (box, index) {
			box.classList.toggle('filled', index < value.length);
		});
	}

	function focusPinInput() {
		var input = $('#pinInput');
		if (input) {
			input.focus();
		}
	}

	function updateLoginUi() {
		if (!$('#loginSecret')) {
			return;
		}
		var input = $('#loginSecret');
		var pinWrap = $('#pinEntryWrap');
		var textWrap = $('#loginSecretWrap');
		var textLabel = $('#loginTextLabel');
		var submit = $('#loginSubmit');
		var toggle = $('.login-mode-toggle');
		if (toggle) {
			toggle.dataset.mode = state.loginMode;
		}
		$$('[data-login-mode]').forEach(function (button) {
			button.classList.toggle('active', button.dataset.loginMode === state.loginMode);
		});
		if (state.loginMode === 'password') {
			pinWrap.classList.add('hidden');
			textWrap.classList.remove('hidden');
			submit.classList.remove('hidden');
			textLabel.textContent = 'Wallet password';
			input.type = 'password';
			input.inputMode = 'text';
			input.autocomplete = 'current-password';
			input.placeholder = state.savedVault ? 'Enter wallet password' : 'Save a wallet first';
			submit.innerHTML = '<i data-lucide="lock-keyhole-open"></i> Log In';
		} else if (state.loginMode === 'privateKey') {
			pinWrap.classList.add('hidden');
			textWrap.classList.remove('hidden');
			submit.classList.remove('hidden');
			textLabel.textContent = 'Private key';
			input.type = 'password';
			input.inputMode = 'text';
			input.autocomplete = 'off';
			input.placeholder = 'Paste Sugarchain private key';
			submit.innerHTML = '<i data-lucide="key-round"></i> Log In';
		} else {
			pinWrap.classList.remove('hidden');
			textWrap.classList.add('hidden');
			submit.classList.add('hidden');
			updatePinBoxes();
		}
		if (window.lucide) {
			window.lucide.createIcons();
		}
	}

	function submitPinLogin() {
		if (state.pinSubmitting) {
			return;
		}
		var value = pinValue();
		if (value.length !== 6) {
			return;
		}
		state.pinSubmitting = true;
		$('#pinEntry').classList.add('active');
		showToast('Unlocking...');
		unlockSavedWithPin(value).then(function () {
			$('#pinInput').value = '';
			updatePinBoxes();
		}).catch(function (error) {
			$('#pinInput').value = '';
			updatePinBoxes();
			showToast(error.message || 'The password or PIN was not accepted.', 'danger');
			window.setTimeout(focusPinInput, 100);
		}).finally(function () {
			state.pinSubmitting = false;
			$('#pinEntry').classList.remove('active');
		});
	}

	function submitLogin() {
		if (state.loginMode === 'pin') {
			submitPinLogin();
			return;
		}
		var value = $('#loginSecret').value.trim();
		var button = $('#loginSubmit');
		if (!value) {
			showToast('Enter your ' + (state.loginMode === 'privateKey' ? 'private key.' : 'wallet password.'), 'danger');
			return;
		}
		setBusy(button, true, 'Unlocking...');
		var action;
		if (state.loginMode === 'privateKey') {
			action = Promise.resolve().then(function () {
				openWallet(bitcoin.ECPair.fromWIF(value, SUGAR_NETWORK), false, 'session');
			}).catch(function () {
				throw new Error('That private key is not valid for Sugarchain.');
			});
		} else if (state.loginMode === 'password') {
			action = unlockSavedWithPassword(value);
		} else {
			action = unlockSavedWithPin(value);
		}
		action.then(function () {
			$('#loginSecret').value = '';
		}).catch(function (error) {
			showToast(error.message || 'Wallet could not be unlocked.', 'danger');
		}).finally(function () {
			setBusy(button, false);
			updateLoginUi();
		});
	}

	function lockedPinValue() {
		return ($('#lockedPinInput') && $('#lockedPinInput').value || '').replace(/\D/g, '').slice(0, 6);
	}

	function updateLockedPinBoxes() {
		var value = lockedPinValue();
		if ($('#lockedPinInput')) {
			$('#lockedPinInput').value = value;
		}
		$$('#lockedPinEntry .pin-box').forEach(function (box, index) {
			box.classList.toggle('filled', index < value.length);
		});
	}

	function focusLockedPinInput() {
		var input = $('#lockedPinInput');
		if (input) {
			input.focus();
		}
	}

	function setLockedUnlockMode(mode) {
		if (['pin', 'password'].indexOf(mode) < 0) {
			mode = 'pin';
		}
		state.lockedUnlockMode = mode;
		if ($('#lockedPassword')) {
			$('#lockedPassword').value = '';
		}
		if ($('#lockedPinInput')) {
			$('#lockedPinInput').value = '';
			updateLockedPinBoxes();
		}
		updateLockedUi();
	}

	function updateLockedUi() {
		if (!$('#lockedUnlockForm')) {
			return;
		}
		var hasPin = hasQuickPin(state.savedVault);
		if (!hasPin && state.lockedUnlockMode === 'pin') {
			state.lockedUnlockMode = 'password';
		}
		var pinWrap = $('#lockedPinEntryWrap');
		var passwordWrap = $('#lockedPasswordWrap');
		var submit = $('#unlockLockedSubmit');
		var toggle = $('.locked-mode-toggle');
		if (toggle) {
			toggle.dataset.mode = state.lockedUnlockMode;
		}
		$$('[data-locked-mode]').forEach(function (button) {
			var active = button.dataset.lockedMode === state.lockedUnlockMode;
			button.classList.toggle('active', active);
			button.disabled = button.dataset.lockedMode === 'pin' && !hasPin;
			button.title = button.disabled ? 'Quick-unlock PIN is not enabled.' : '';
		});
		if ($('#lockedSavedWalletAddress')) {
			$('#lockedSavedWalletAddress').textContent = state.savedVault ? shortAddress(state.savedVault.address) : 'None';
		}
		if (state.lockedUnlockMode === 'password') {
			pinWrap.classList.add('hidden');
			passwordWrap.classList.remove('hidden');
			submit.classList.remove('hidden');
		} else {
			pinWrap.classList.remove('hidden');
			passwordWrap.classList.add('hidden');
			submit.classList.add('hidden');
			updateLockedPinBoxes();
		}
		if (window.lucide) {
			window.lucide.createIcons();
		}
	}

	function submitLockedPin() {
		if (state.lockedPinSubmitting) {
			return;
		}
		var value = lockedPinValue();
		if (value.length !== 6) {
			return;
		}
		state.lockedPinSubmitting = true;
		$('#lockedPinEntry').classList.add('active');
		showToast('Unlocking...');
		unlockSavedWithPin(value).then(function () {
			$('#lockedPinInput').value = '';
			updateLockedPinBoxes();
		}).catch(function (error) {
			$('#lockedPinInput').value = '';
			updateLockedPinBoxes();
			showToast(error.message || 'The password or PIN was not accepted.', 'danger');
			window.setTimeout(focusLockedPinInput, 100);
		}).finally(function () {
			state.lockedPinSubmitting = false;
			$('#lockedPinEntry').classList.remove('active');
		});
	}

	function submitLockedUnlock() {
		if (state.lockedUnlockMode === 'pin') {
			submitLockedPin();
			return;
		}
		var password = $('#lockedPassword').value.trim();
		var button = $('#unlockLockedSubmit');
		if (!password) {
			showToast('Enter your wallet password.', 'danger');
			return;
		}
		setBusy(button, true, 'Unlocking...');
		unlockSavedWithPassword(password).then(function () {
			$('#lockedPassword').value = '';
		}).catch(function (error) {
			showToast(error.message || 'Wallet could not be unlocked.', 'danger');
		}).finally(function () {
			setBusy(button, false);
			updateLockedUi();
		});
	}

	function updateWalletUi() {
		var loggedIn = !!state.address;
		$('#loginScreen').classList.toggle('active', !loggedIn);
		$('#walletScreen').classList.toggle('active', loggedIn);
		$('#walletScreen').classList.toggle('wallet-locked', state.mode === 'locked');
		document.body.classList.toggle('wallet-open', loggedIn);
		if (!loggedIn) {
			updateAccessUi();
			return;
		}
		$('#receiveAddress').textContent = state.address;
		$('#walletStatus').textContent = walletStatusText();
		renderQr(CONFIG.uri + state.address);
		renderKeys();
		updateBalanceUi(false);
		updateAccessUi();
		renderSecurityUi();
	}

	function refreshBalance(showSuccess) {
		if (!state.address) {
			return Promise.resolve(0);
		}
		updateBalanceUi(true);
		return requestApi('/balance/' + encodeURIComponent(state.address)).then(function (data) {
			if (data.error) {
				throw new Error(data.error.message || 'Unable to load balance.');
			}
			state.balance = Number(data.result && data.result.balance || 0);
			updateBalanceUi(false);
			if (showSuccess) {
				showToast('Balance refreshed from the live chain.');
			}
			return state.balance;
		}).catch(function (error) {
			updateBalanceUi(false);
			showToast(error.message || 'Balance refresh failed.', 'danger');
			return state.balance;
		});
	}

	function requestStarterFunding(balanceSatoshis) {
		if (!state.address || state.starterFundingRequested[state.address]) {
			return;
		}
		var minimum = 0.01 * Math.pow(10, CONFIG.decimals);
		if (Number(balanceSatoshis || 0) >= minimum) {
			return;
		}
		state.starterFundingRequested[state.address] = true;
		showToast('Requesting starter SUGAR...');
		fetch('/api/faucet/fund', {
			method: 'POST',
			headers: {
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				address: state.address
			})
		}).then(function (response) {
			return response.json().then(function (data) {
				if (!response.ok && data && data.error) {
					throw new Error(data.error);
				}
				return data;
			});
		}).then(function (data) {
			if (data.funded) {
				showToast('Starter SUGAR sent: ' + Number(data.amount || 0).toFixed(3));
				window.setTimeout(function () {
					refreshBalance(false);
					loadActivity(true);
				}, 5000);
			} else if (data.reason === 'balance_ok') {
				showToast('Wallet already has SUGAR.');
			} else if (data.error) {
				throw new Error(data.error);
			}
		}).catch(function (error) {
			state.starterFundingRequested[state.address] = false;
			showToast(error.message || 'Starter funding failed.', 'danger');
		});
	}

	function startBalanceLoop() {
		window.clearInterval(state.timer);
		state.timer = window.setInterval(function () {
			refreshBalance(false);
		}, 30000);
	}

	function clearSensitiveMemory() {
		stopQrScanner();
		state.keys = null;
		state.pendingTx = null;
		state.pendingPlan = null;
		state.lastTxHex = '';
		$('#backupWif').value = '';
		$('#backupBox').classList.add('hidden');
	}

	function resetAutoLockTimer() {
		window.clearTimeout(state.autoLockTimer);
		if (!state.address || !state.keys || state.settings.autoLockMs < 0) {
			return;
		}
		state.autoLockTimer = window.setTimeout(function () {
			lockWallet('Wallet locked after inactivity.');
		}, state.settings.autoLockMs);
	}

	function touchActivity() {
		resetAutoLockTimer();
	}

	function openWallet(keys, created, mode, walletId, addressOverride) {
		state.keys = keys;
		state.address = addressOverride || getAddress(keys);
		state.publicKeyHex = keys.publicKey.toString('hex');
		state.walletId = walletId || state.walletId || (state.savedVault && state.savedVault.walletId) || '';
		state.mode = mode || 'session';
		state.balance = 0;
		state.pendingTx = null;
		state.pendingPlan = null;
		state.lastTxHex = '';
		resetActivity();
		savePublicWallet({
			walletId: state.walletId,
			address: state.address,
			publicKey: state.publicKeyHex,
			mode: state.mode,
			updatedAt: new Date().toISOString()
		});
		updateWalletUi();
		switchTab('activity');
		refreshBalance(false).then(function (balance) {
			if (created) {
				requestStarterFunding(balance);
			}
		});
		startBalanceLoop();
		resetAutoLockTimer();
		showToast(created ? 'Wallet created. Copy your private key before closing this view.' : 'Wallet opened.');
	}

	function openWatchOnly(record, message) {
		window.clearInterval(state.timer);
		clearSensitiveMemory();
		state.address = record.address;
		state.publicKeyHex = record.publicKey || '';
		state.walletId = record.walletId || '';
		state.mode = 'watch';
		state.balance = 0;
		resetActivity();
		savePublicWallet({
			walletId: state.walletId,
			address: state.address,
			publicKey: state.publicKeyHex,
			mode: 'watch',
			updatedAt: new Date().toISOString()
		});
		updateWalletUi();
		switchTab('activity');
		refreshBalance(false);
		startBalanceLoop();
		if (message) {
			showToast(message);
		}
	}

	function lockWallet(message) {
		if (!state.address || state.mode === 'watch') {
			return;
		}
		if (!state.savedVault) {
			closeWallet();
			return;
		}
		clearSensitiveMemory();
		state.address = state.savedVault.address;
		state.publicKeyHex = state.savedVault.publicKey || '';
		state.walletId = state.savedVault.walletId || '';
		state.mode = 'locked';
		state.lockedUnlockMode = 'pin';
		updateWalletUi();
		switchTab('locked');
		if (message) {
			showToast(message);
		}
	}

	function closeWallet() {
		window.clearInterval(state.timer);
		window.clearTimeout(state.autoLockTimer);
		clearSensitiveMemory();
		state.address = '';
		state.publicKeyHex = '';
		state.walletId = '';
		state.mode = 'closed';
		state.balance = 0;
		resetActivity();
		$('#loginSecret').value = '';
		$('#createdKey').value = '';
		$('#createdCard').classList.add('hidden');
		$('#sendForm').reset();
		$('#sendSummary').classList.remove('active');
		closeMenu();
		updateWalletUi();
		showToast('Wallet closed.');
	}

	function openSavedWalletWithWif(record, wif) {
		var keys = bitcoin.ECPair.fromWIF(wif, SUGAR_NETWORK);
		var derivedAddress = getAddress(keys);
		if (record.address && record.address !== derivedAddress) {
			state.walletId = record.walletId || '';
			openWallet(keys, false, 'saved', record.walletId, record.address);
		} else {
			openWallet(keys, false, 'saved', record.walletId);
		}
	}

	function unlockSavedWithPassword(password) {
		var record = state.savedVault || storageJsonGet(STORAGE.vault, null);
		if (!record) {
			return Promise.reject(new Error('No saved wallet was found on this device.'));
		}
		return Vault.decryptVault(record, password).then(function (wif) {
			state.savedVault = record;
			openSavedWalletWithWif(record, wif);
			return true;
		});
	}

	function pinDelayForFailures(failures) {
		if (failures >= 7) {
			return -1;
		}
		if (failures === 6) {
			return 120000;
		}
		if (failures === 5) {
			return 30000;
		}
		return 1500;
	}

	function recordPinFailure(record) {
		record.quickUnlock.failures = Number(record.quickUnlock.failures || 0) + 1;
		var delay = pinDelayForFailures(record.quickUnlock.failures);
		if (delay < 0) {
			record.quickUnlock.enabled = false;
			record.quickUnlock.lockedUntil = 0;
			saveVaultRecord(record);
			return deleteDeviceKey().then(function () {
				throw new Error('Quick-unlock PIN was disabled after too many failed attempts. Use the wallet password.');
			});
		}
		record.quickUnlock.lockedUntil = Date.now() + delay;
		saveVaultRecord(record);
		throw new Error('The password or PIN was not accepted. Try again after the delay.');
	}

	function clearPinFailures(record) {
		if (record && record.quickUnlock) {
			record.quickUnlock.failures = 0;
			record.quickUnlock.lockedUntil = 0;
			saveVaultRecord(record);
		}
	}

	function unlockSavedWithPin(pin) {
		var record = state.savedVault || storageJsonGet(STORAGE.vault, null);
		if (!record || !hasQuickPin(record)) {
			return Promise.reject(new Error('Quick-unlock PIN is not enabled.'));
		}
		var lockedUntil = Number(record.quickUnlock.lockedUntil || 0);
		if (lockedUntil > Date.now()) {
			var seconds = Math.ceil((lockedUntil - Date.now()) / 1000);
			return Promise.reject(new Error('Try the PIN again in ' + seconds + ' seconds.'));
		}
		return getDeviceKey(false).then(function (deviceKey) {
			return Vault.unwrapVaultKeyWithPin(record, pin, deviceKey);
		}).then(function (vaultKeyBytes) {
			return Vault.decryptWithVaultKey(record, vaultKeyBytes);
		}).then(function (wif) {
			clearPinFailures(record);
			state.savedVault = record;
			openSavedWalletWithWif(record, wif);
			return true;
		}).catch(function () {
			return recordPinFailure(record);
		});
	}

	function saveCurrentPrivateKey(password) {
		if (!state.keys) {
			return Promise.reject(new Error('Unlock a wallet before saving the private key.'));
		}
		var cryptoError = vaultAvailabilityError();
		if (cryptoError) {
			return Promise.reject(new Error(cryptoError));
		}
		return Vault.createVault({
			privateKeyWif: state.keys.toWIF(),
			address: state.address,
			publicKey: state.publicKeyHex,
			walletId: state.walletId || undefined,
			network: Vault.NETWORK
		}, password).then(function (record) {
			state.walletId = record.walletId;
			saveVaultRecord(record);
			state.mode = 'saved';
			updateWalletUi();
			return record;
		});
	}

	function requireSavedWalletPassword(reason) {
		if (!state.savedVault) {
			return Promise.reject(new Error('No saved encrypted wallet was found.'));
		}
		return askSecret('Wallet Password', reason || 'Enter your wallet password.', 'Wallet password').then(function (password) {
			return Vault.decryptVault(state.savedVault, password).then(function (wif) {
				return {
					password: password,
					wif: wif
				};
			});
		});
	}

	function removeSavedPrivateKey(keepWatchOnly) {
		var publicRecord = {
			walletId: state.walletId || (state.savedVault && state.savedVault.walletId) || '',
			address: state.address || (state.savedVault && state.savedVault.address) || '',
			publicKey: state.publicKeyHex || (state.savedVault && state.savedVault.publicKey) || '',
			mode: 'watch',
			updatedAt: new Date().toISOString()
		};
		storageRemove(STORAGE.vault);
		storageRemove(STORAGE.recoveryCodes);
		deleteDeviceKey();
		state.savedVault = null;
		state.settings.requirePinBeforeSend = false;
		state.settings.requirePasswordBeforeSend = false;
		state.settings.requireSecurityKeyBeforeSend = false;
		saveSettings();
		clearSensitiveMemory();
		if (keepWatchOnly && publicRecord.address) {
			openWatchOnly(publicRecord, 'The saved private key has been removed from this device. Keep your external wallet backup secure.');
			return;
		}
		storageRemove(STORAGE.publicWallet);
		state.publicWallet = null;
		closeWallet();
		showToast('The saved private key has been removed from this device.');
	}

	function deleteWalletFromDevice() {
		storageRemove(STORAGE.vault);
		storageRemove(STORAGE.publicWallet);
		storageRemove(STORAGE.securityKeys);
		storageRemove(STORAGE.recoveryCodes);
		storageRemove(STORAGE.settings);
		deleteDeviceKey();
		loadSettings();
		loadStoredRecords();
		closeWallet();
		showToast('Wallet records were deleted from this device. Blockchain history remains public.');
	}

	function loadSecurityKeys() {
		return storageJsonGet(STORAGE.securityKeys, []);
	}

	function saveSecurityKeys(keys) {
		storageJsonSet(STORAGE.securityKeys, keys);
		renderSecurityUi();
	}

	function renderSecurityKeys() {
		var list = $('#securityKeyList');
		if (!list) {
			return;
		}
		var keys = loadSecurityKeys();
		list.innerHTML = keys.map(function (key, index) {
			return '<div class="security-key-item">' +
				'<span>' +
					'<span class="security-key-name">' + escapeHtml(key.name || 'Security key') + '</span>' +
					'<span class="security-key-meta">Registered ' + escapeHtml(new Date(key.registeredAt).toLocaleDateString()) + '</span>' +
				'</span>' +
				'<span class="field-pair">' +
					'<button class="copy-button" type="button" data-security-key-rename="' + index + '" aria-label="Rename security key"><i data-lucide="pencil"></i></button>' +
					'<button class="copy-button" type="button" data-security-key-remove="' + index + '" aria-label="Remove security key"><i data-lucide="trash-2"></i></button>' +
				'</span>' +
			'</div>';
		}).join('');
	}

	function renderSecurityUi() {
		if (!$('#securityStatus')) {
			return;
		}
		var vault = state.savedVault;
		var securityKeys = loadSecurityKeys();
		var modeLabel = state.mode === 'saved' ? 'Saved and unlocked' :
			state.mode === 'locked' ? 'Saved and locked' :
				state.mode === 'watch' ? 'Watch-only' :
					state.mode === 'session' ? 'Session-only' : 'Closed';
		var vaultLabel = vault ? 'encrypted private key saved' : 'no saved private key';
		var pinLabel = hasQuickPin(vault) ? 'PIN enabled' : 'PIN disabled';
		$('#securityStatus').textContent = modeLabel + ': ' + vaultLabel + ', ' + pinLabel + ', ' + securityKeys.length + ' security key' + (securityKeys.length === 1 ? '' : 's') + '.';
		setSecurityCapabilityNotice();
		$('#autoLockTimeout').value = String(state.settings.autoLockMs);
		$('#securityKeyRequired').checked = !!state.settings.requireSecurityKeyBeforeSend;
		$('#requireSecurityKeyBeforeSend').checked = !!state.settings.requireSecurityKeyBeforeSend;
		$('#requirePasswordBeforeSend').checked = !!state.settings.requirePasswordBeforeSend;
		$('#requirePinBeforeSend').checked = !!state.settings.requirePinBeforeSend;
		$('#requireConfirmEveryTx').checked = true;
		if ($('#savedWalletInfo')) {
			$('#savedWalletInfo').classList.toggle('hidden', !vault);
		}
		if ($('#savedWalletAddress')) {
			$('#savedWalletAddress').textContent = vault ? shortAddress(vault.address) : 'None';
		}
		updateLockedUi();
		setDisabled('#addSecurityKeyButton', !webAuthnSupported(), 'Security-key approval requires HTTPS or localhost in a WebAuthn-capable browser.');
		setDisabled('#addBackupSecurityKeyButton', !webAuthnSupported(), 'Security-key approval requires HTTPS or localhost in a WebAuthn-capable browser.');
		renderSecurityKeys();
		if (window.lucide) {
			window.lucide.createIcons();
		}
	}

	function webAuthnSupported() {
		return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create && navigator.credentials.get);
	}

	function webAuthnUserId() {
		return Vault.randomBytes(16);
	}

	function credentialToRecord(credential, name) {
		var response = credential.response || {};
		return {
			id: credential.id,
			rawId: Vault.bytesToBase64Url(credential.rawId),
			name: name || 'Security key',
			type: credential.type || 'public-key',
			transports: response.getTransports ? response.getTransports() : [],
			registeredAt: new Date().toISOString(),
			counter: 0
		};
	}

	function requireUnlockedForSecurityKey() {
		if (!state.keys) {
			return Promise.reject(new Error('Unlock the wallet before changing security-key settings.'));
		}
		if (!state.savedVault) {
			return Promise.reject(new Error('Save the wallet with a password before registering a security key.'));
		}
		return requireSavedWalletPassword('Enter your wallet password to manage security keys.').then(function () {
			return true;
		});
	}

	function requestSecurityKeyAssertion(records, label, challengeBytes) {
		if (!webAuthnSupported()) {
			return Promise.reject(new Error('Security-key approval is not available in this browser.'));
		}
		var challenge = challengeBytes || Vault.randomBytes(32);
		return navigator.credentials.get({
			publicKey: {
				challenge: challenge,
				allowCredentials: records.map(function (record) {
					return {
						id: Vault.base64UrlToBytes(record.rawId),
						type: 'public-key',
						transports: record.transports || undefined
					};
				}),
				timeout: 60000,
				userVerification: 'preferred'
			}
		}).then(function (credential) {
			var match = records.filter(function (record) {
				return record.id === credential.id || record.rawId === Vault.bytesToBase64Url(credential.rawId);
			})[0];
			if (!match) {
				throw new Error('Security-key approval failed.');
			}
			var authData = new Uint8Array(credential.response.authenticatorData || []);
			var flags = authData.length > 32 ? authData[32] : 0;
			if ((flags & 0x01) !== 0x01) {
				throw new Error('Security-key user presence was not confirmed.');
			}
			return {
				credentialId: match.id,
				label: label || 'Security key approval',
				challenge: Vault.bytesToBase64Url(challenge)
			};
		});
	}

	function addSecurityKey(kind) {
		return requireUnlockedForSecurityKey().then(function () {
			if (!webAuthnSupported()) {
				throw new Error('Security-key approval is not available in this browser.');
			}
			var name = window.prompt(kind === 'backup' ? 'Name this backup security key.' : 'Name this security key.');
			if (!name) {
				throw new Error('Security key name is required.');
			}
			return navigator.credentials.create({
				publicKey: {
					challenge: Vault.randomBytes(32),
					rp: {
						name: 'SweetWallet'
					},
					user: {
						id: webAuthnUserId(),
						name: state.address,
						displayName: 'SweetWallet ' + shortAddress(state.address)
					},
					pubKeyCredParams: [{
						type: 'public-key',
						alg: -7
					}, {
						type: 'public-key',
						alg: -257
					}],
					authenticatorSelection: {
						userVerification: 'preferred',
						residentKey: 'discouraged',
						requireResidentKey: false
					},
					timeout: 60000,
					attestation: 'none'
				}
			}).then(function (credential) {
				var record = credentialToRecord(credential, name);
				return requestSecurityKeyAssertion([record], 'Test security key approval').then(function () {
					var keys = loadSecurityKeys();
					keys.push(record);
					saveSecurityKeys(keys);
					showToast(kind === 'backup' ? 'Backup security key added.' : 'Security key added.');
				});
			});
		}).catch(function (error) {
			showToast(error.message || 'Security-key registration failed.', 'danger');
		});
	}

	function generateRecoveryCodes() {
		if (!state.savedVault) {
			showToast('Save the wallet before generating recovery codes.', 'danger');
			return;
		}
		requireSavedWalletPassword('Enter your wallet password to generate recovery codes.').then(function () {
			var codes = [];
			for (var index = 0; index < 8; index += 1) {
				var raw = Vault.bytesToBase64Url(Vault.randomBytes(10)).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
				codes.push('SW-' + raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8, 12));
			}
			var salt = Vault.bytesToBase64Url(Vault.randomBytes(16));
			return Promise.all(codes.map(function (code) {
				return Vault.sha256Base64Url(salt + ':' + code);
			})).then(function (hashes) {
				storageJsonSet(STORAGE.recoveryCodes, {
					salt: salt,
					hashes: hashes.map(function (hash) {
						return {
							hash: hash,
							used: false
						};
					}),
					createdAt: new Date().toISOString()
				});
				$('#recoveryCodesOutput').value = codes.join('\n');
				$('#recoveryCodesBox').classList.remove('hidden');
				showToast('Recovery codes generated. Store them offline now.');
			});
		}).catch(function (error) {
			showToast(error.message || 'Recovery code generation failed.', 'danger');
		});
	}

	function useRecoveryCodeForApproval() {
		var store = storageJsonGet(STORAGE.recoveryCodes, null);
		if (!store || !store.hashes || !store.hashes.length) {
			return Promise.reject(new Error('No recovery codes are available.'));
		}
		return requireSavedWalletPassword('Enter your wallet password before using a recovery code.').then(function () {
			return askSecret('Recovery Code', 'Enter one recovery code for this transaction.', 'SW-XXXX-XXXX-XXXX').then(function (code) {
				return Vault.sha256Base64Url(store.salt + ':' + code.trim().toUpperCase());
			}).then(function (hash) {
				var match = store.hashes.filter(function (entry) {
					return entry.hash === hash && !entry.used;
				})[0];
				if (!match) {
					throw new Error('Recovery code was not accepted.');
				}
				match.used = true;
				storageJsonSet(STORAGE.recoveryCodes, store);
				state.settings.requireSecurityKeyBeforeSend = false;
				saveSettings();
				showToast('Recovery code accepted. Register a replacement security key before re-enabling strict approval.');
				return true;
			});
		});
	}

	function loadUnspent(amount) {
		return requestApi('/unspent/' + encodeURIComponent(state.address) + '?amount=' + encodeURIComponent(amount)).then(function (data) {
			if (data.error) {
				throw new Error(data.error.message || 'Unable to load UTXOs.');
			}
			return (data.result || []).map(function (utxo) {
				return {
					txid: utxo.txid || utxo.hash,
					index: utxo.index !== undefined ? utxo.index : utxo.vout,
					value: Number(utxo.value || utxo.satoshis || 0),
					script: utxo.script || utxo.scriptPubKey || ''
				};
			});
		});
	}

	function selectUtxos(totalSatoshis) {
		return loadUnspent(totalSatoshis).then(function (utxos) {
			var selected = [];
			var value = 0;
			utxos.forEach(function (utxo) {
				if (value >= totalSatoshis || !utxo.txid || utxo.index === undefined || !utxo.script) {
					return;
				}
				var script = bitcoin.Buffer(utxo.script, 'hex');
				var type = getScriptType(script);
				if (!type) {
					return;
				}
				value += utxo.value;
				selected.push({
					txid: utxo.txid,
					index: utxo.index,
					value: utxo.value,
					script: utxo.script,
					type: type
				});
			});
			if (value < totalSatoshis) {
				throw new Error('Not enough spendable SUGAR.');
			}
			return {
				utxos: selected,
				inputTotal: value,
				change: value - totalSatoshis
			};
		});
	}

	function createTransactionBuilder(outputs, selection, sign) {
		if (sign && !state.keys) {
			throw new Error('Unlock the wallet before signing.');
		}
		var txb = new bitcoin.TransactionBuilder(SUGAR_NETWORK);
		txb.setVersion(2);
		outputs.forEach(function (output) {
			txb.addOutput(output.address, output.amount);
		});
		selection.utxos.forEach(function (utxo) {
			if (utxo.type === 'bech32') {
				var p2wpkh = getP2WPKHScript(state.keys.publicKey);
				txb.addInput(utxo.txid, utxo.index, null, p2wpkh.output);
			} else {
				txb.addInput(utxo.txid, utxo.index);
			}
		});
		if (selection.change > 0) {
			txb.addOutput(state.address, selection.change);
		}
		if (sign) {
			selection.utxos.forEach(function (utxo, index) {
				if (utxo.type === 'bech32') {
					txb.sign(index, state.keys, null, null, utxo.value, null);
				} else if (utxo.type === 'segwit') {
					var redeem = getP2WPKHScript(state.keys.publicKey);
					var p2sh = getP2SHScript(redeem);
					txb.sign(index, state.keys, p2sh.redeem.output, null, utxo.value, null);
				} else if (utxo.type === 'legacy') {
					txb.sign(index, state.keys);
				} else {
					throw new Error('Unsupported UTXO script type.');
				}
			});
		}
		return txb;
	}

	function buildUnsignedTransaction(outputs, selection) {
		return createTransactionBuilder(outputs, selection, false).buildIncomplete().toHex();
	}

	function buildSignedTransaction(outputs, selection) {
		return createTransactionBuilder(outputs, selection, true).build().toHex();
	}

	function canonicalApprovalPayload(plan) {
		return {
			network: Vault.NETWORK,
			walletId: state.walletId || state.address,
			from: state.address,
			to: plan.pending.outputs[0].address,
			amount: plan.pending.outputs[0].amount,
			fee: plan.pending.fee,
			total: plan.pending.total,
			asset: CONFIG.ticker,
			change: plan.selection.change,
			inputs: plan.selection.utxos.map(function (utxo) {
				return {
					txid: utxo.txid,
					index: utxo.index,
					value: utxo.value
				};
			}),
			unsignedTransactionHash: plan.unsignedTxHash,
			expiresAt: plan.expiresAt,
			approvalSessionId: plan.approvalSessionId,
			challenge: plan.challenge
		};
	}

	function prepareTransactionPlan(pending) {
		var plan = {
			pending: pending,
			expiresAt: new Date(Date.now() + 120000).toISOString(),
			approvalSessionId: Vault.bytesToBase64Url(Vault.randomBytes(16)),
			challenge: Vault.bytesToBase64Url(Vault.randomBytes(16))
		};
		return selectUtxos(pending.total).then(function (selection) {
			plan.selection = selection;
			plan.unsignedTxHex = buildUnsignedTransaction(pending.outputs, selection);
			return Vault.sha256Hex(plan.unsignedTxHex);
		}).then(function (hash) {
			plan.unsignedTxHash = hash;
			return Vault.sha256Hex(Vault.stableStringify(canonicalApprovalPayload(plan)));
		}).then(function (approvalHash) {
			plan.approvalHash = approvalHash;
			return plan;
		});
	}

	function broadcastRaw(raw) {
		var form = new URLSearchParams();
		form.set('raw', raw);
		return requestApi('/broadcast', {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded;charset=UTF-8'
			},
			body: form.toString()
		});
	}

	function reauthenticateForSend() {
		var chain = Promise.resolve();
		if (state.settings.requirePasswordBeforeSend) {
			chain = chain.then(function () {
				if (!state.savedVault) {
					throw new Error('Save this wallet before requiring a password for sends.');
				}
				return requireSavedWalletPassword('Enter your wallet password before sending.');
			});
		}
		if (state.settings.requirePinBeforeSend) {
			chain = chain.then(function () {
				if (!hasQuickPin(state.savedVault)) {
					throw new Error('Quick-unlock PIN is not enabled.');
				}
				return askSecret('Quick-Unlock PIN', 'Enter your quick-unlock PIN before sending.', '6+ digit PIN', 'numeric').then(function (pin) {
					return getDeviceKey(false).then(function (deviceKey) {
						return Vault.unwrapVaultKeyWithPin(state.savedVault, pin, deviceKey);
					});
				});
			});
		}
		return chain;
	}

	function approveSecurityKeyForSend(plan) {
		if (!state.settings.requireSecurityKeyBeforeSend) {
			return Promise.resolve(true);
		}
		var records = loadSecurityKeys();
		if (!records.length) {
			throw new Error('Register a security key before enabling Security Key Approval.');
		}
		var challengeBytes = hexToBytes(plan.approvalHash);
		return requestSecurityKeyAssertion(records, 'Transaction approval', challengeBytes).catch(function (error) {
			var useRecovery = window.confirm((error.message || 'Security-key approval failed.') + ' Use a one-time recovery code instead?');
			if (!useRecovery) {
				throw new Error('Security-key approval failed.');
			}
			return useRecoveryCodeForApproval();
		});
	}

	function prepareSend() {
		if (!state.keys) {
			showToast(state.mode === 'watch' ? 'Watch-only wallets cannot send.' : 'Unlock the wallet before sending.', 'danger');
			if (state.mode === 'locked') {
				switchTab('locked');
			}
			return;
		}
		var target = parsePaymentTarget($('#sendAddress').value);
		var address = target.address;
		var amountInput = target.amount || $('#sendAmount').value;
		if (target.amount && !$('#sendAmount').value) {
			$('#sendAmount').value = target.amount;
		}
		var amount = amountToSatoshis(amountInput);
		var fee = amountToSatoshis($('#sendFee').value || state.fee);

		if (!validateAddress(address)) {
			showToast('Enter a valid Sugarchain address.', 'danger');
			return;
		}
		if (!Number.isFinite(amount) || amount <= 0) {
			showToast('Enter a valid amount.', 'danger');
			return;
		}
		if (!Number.isFinite(fee) || fee < amountToSatoshis(CONFIG.fee)) {
			showToast('Use a fee of at least ' + CONFIG.fee + ' SUGAR.', 'danger');
			return;
		}

		var total = amount + fee;
		if (total > state.balance) {
			showToast('Not enough SUGAR for amount plus fee.', 'danger');
			return;
		}

		state.pendingTx = {
			outputs: [{
				address: address,
				amount: amount
			}],
			fee: fee,
			total: total
		};

		$('#summaryAddress').textContent = address;
		$('#summaryAmount').textContent = formatAmount(amount) + ' ' + CONFIG.ticker;
		$('#summaryFee').textContent = formatAmount(fee) + ' ' + CONFIG.ticker;
		$('#summaryTotal').textContent = formatAmount(total) + ' ' + CONFIG.ticker;
		$('#sendSummary').classList.add('active');
		showConfirm();
	}

	function confirmSend() {
		if (!state.pendingTx || state.broadcasting) {
			return;
		}
		var button = $('#confirmSend');
		state.broadcasting = true;
		setBusy(button, true, 'Preparing...');
		prepareTransactionPlan(state.pendingTx).then(function (plan) {
			state.pendingPlan = plan;
			setBusy(button, true, 'Authenticating...');
			return reauthenticateForSend().then(function () {
				setBusy(button, true, state.settings.requireSecurityKeyBeforeSend ? 'Security key...' : 'Signing...');
				return approveSecurityKeyForSend(plan);
			}).then(function () {
				if (new Date(plan.expiresAt).getTime() < Date.now()) {
					throw new Error('The transaction changed and must be reviewed again.');
				}
				return buildSignedTransaction(plan.pending.outputs, plan.selection);
			});
		}).then(function (raw) {
			state.lastTxHex = raw;
			setBusy(button, true, 'Broadcasting...');
			return broadcastRaw(raw);
		}).then(function (data) {
			if (data.error) {
				throw new Error(data.error.message || 'Broadcast failed.');
			}
			var txid = data.result || data.txid || '';
			$('#lastTxLink').href = CONFIG.explorerTx(txid);
			$('#lastTxLink').textContent = txid;
			$('#lastTxBox').classList.remove('hidden');
			$('#sendForm').reset();
			$('#sendFee').value = state.fee;
			$('#sendSummary').classList.remove('active');
			resetActivity();
			hideConfirm();
			state.pendingTx = null;
			state.pendingPlan = null;
			showToast('Transaction broadcasted.');
			refreshBalance(false);
		}).catch(function (error) {
			showToast(error.message || 'Transaction failed.', 'danger');
		}).finally(function () {
			state.broadcasting = false;
			setBusy(button, false);
		});
	}

	function switchTab(name) {
		if (name === 'send' && !state.keys) {
			showToast(state.mode === 'watch' ? 'Watch-only wallets cannot send.' : 'Unlock the wallet before sending.', 'danger');
			name = state.mode === 'locked' ? 'locked' : 'activity';
		}
		$$('.panel').forEach(function (panel) {
			panel.classList.toggle('active', panel.dataset.panel === name);
		});
		closeMenu();
		if (name === 'activity' && !state.activity.loaded) {
			loadActivity(true);
		}
		if (name === 'security') {
			renderSecurityUi();
		}
	}

	function openMenu() {
		updateMenuUi();
		$('#menuSheet').classList.add('active');
		$('#menuToggle').setAttribute('aria-expanded', 'true');
	}

	function closeMenu() {
		$('#menuSheet').classList.remove('active');
		$('#menuToggle').setAttribute('aria-expanded', 'false');
	}

	function showConfirm() {
		$('#confirmModal').classList.add('active');
	}

	function hideConfirm() {
		$('#confirmModal').classList.remove('active');
	}

	function askSecret(title, label, placeholder, inputMode) {
		return new Promise(function (resolve, reject) {
			var modal = document.createElement('div');
			modal.className = 'modal active';
			modal.setAttribute('role', 'dialog');
			modal.setAttribute('aria-modal', 'true');
			modal.innerHTML = '<form class="modal-card secret-card" autocomplete="off">' +
				'<h2>' + escapeHtml(title || 'Wallet Password') + '</h2>' +
				'<div class="form-row">' +
					'<label for="secretPromptInput">' + escapeHtml(label || 'Enter wallet password') + '</label>' +
					'<input id="secretPromptInput" type="password" autocomplete="off" inputmode="' + escapeHtml(inputMode || 'text') + '" placeholder="' + escapeHtml(placeholder || '') + '">' +
				'</div>' +
				'<div class="modal-actions">' +
					'<button class="button secondary" type="button" data-secret-cancel>Cancel</button>' +
					'<button class="button" type="submit">Continue</button>' +
				'</div>' +
			'</form>';
			function close() {
				modal.remove();
			}
			modal.querySelector('form').addEventListener('submit', function (event) {
				event.preventDefault();
				var value = modal.querySelector('#secretPromptInput').value;
				close();
				if (!value) {
					reject(new Error('Wallet password is required.'));
					return;
				}
				resolve(value);
			});
			modal.querySelector('[data-secret-cancel]').addEventListener('click', function () {
				close();
				reject(new Error('Wallet password is required.'));
			});
			document.body.appendChild(modal);
			window.setTimeout(function () {
				var input = modal.querySelector('#secretPromptInput');
				if (input) {
					input.focus();
				}
			}, 0);
		});
	}

	function copyValue(value) {
		value = String(value || '');
		if (!value) {
			return;
		}
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(value).then(function () {
				showToast('Copied.');
			}).catch(function () {
				showToast('Select the text and copy it manually.', 'warning');
			});
			return;
		}
		var textarea = document.createElement('textarea');
		textarea.value = value;
		document.body.appendChild(textarea);
		textarea.select();
		document.execCommand('copy');
		textarea.remove();
		showToast('Copied.');
	}

	function wireEvents() {
		$$('[data-login-mode]').forEach(function (button) {
			button.addEventListener('click', function () {
				setLoginMode(button.dataset.loginMode);
				if (state.loginMode === 'pin') {
					focusPinInput();
				} else {
					$('#loginSecret').focus();
				}
			});
		});

		$('#pinEntry').addEventListener('click', focusPinInput);
		$('#pinEntry').addEventListener('keydown', function (event) {
			if (/^\d$/.test(event.key)) {
				event.preventDefault();
				$('#pinInput').value = (pinValue() + event.key).slice(0, 6);
				updatePinBoxes();
				if (pinValue().length === 6) {
					submitPinLogin();
				}
			} else if (event.key === 'Backspace') {
				event.preventDefault();
				$('#pinInput').value = pinValue().slice(0, -1);
				updatePinBoxes();
			}
		});
		$('#pinInput').addEventListener('input', function () {
			updatePinBoxes();
			if (pinValue().length === 6) {
				submitPinLogin();
			}
		});
		$('#pinInput').addEventListener('focus', function () {
			$('#pinEntry').classList.add('active');
		});
		$('#pinInput').addEventListener('blur', function () {
			if (!state.pinSubmitting) {
				$('#pinEntry').classList.remove('active');
			}
		});

		$('#createWallet').addEventListener('click', function () {
			var keys = createKeys();
			var wif = keys.toWIF();
			$('#createdKey').value = wif;
			$('#createdCard').classList.remove('hidden');
			openWallet(keys, true);
		});

		$('#loginForm').addEventListener('submit', function (event) {
			event.preventDefault();
			submitLogin();
		});

		$$('[data-locked-mode]').forEach(function (button) {
			button.addEventListener('click', function () {
				if (button.disabled) {
					return;
				}
				setLockedUnlockMode(button.dataset.lockedMode);
				if (state.lockedUnlockMode === 'pin') {
					focusLockedPinInput();
				} else {
					$('#lockedPassword').focus();
				}
			});
		});

		$('#lockedPinEntry').addEventListener('click', focusLockedPinInput);
		$('#lockedPinEntry').addEventListener('keydown', function (event) {
			if (/^\d$/.test(event.key)) {
				event.preventDefault();
				$('#lockedPinInput').value = (lockedPinValue() + event.key).slice(0, 6);
				updateLockedPinBoxes();
				if (lockedPinValue().length === 6) {
					submitLockedPin();
				}
			} else if (event.key === 'Backspace') {
				event.preventDefault();
				$('#lockedPinInput').value = lockedPinValue().slice(0, -1);
				updateLockedPinBoxes();
			}
		});
		$('#lockedPinInput').addEventListener('input', function () {
			updateLockedPinBoxes();
			if (lockedPinValue().length === 6) {
				submitLockedPin();
			}
		});
		$('#lockedPinInput').addEventListener('focus', function () {
			$('#lockedPinEntry').classList.add('active');
		});
		$('#lockedPinInput').addEventListener('blur', function () {
			if (!state.lockedPinSubmitting) {
				$('#lockedPinEntry').classList.remove('active');
			}
		});

		$('#lockedUnlockForm').addEventListener('submit', function (event) {
			event.preventDefault();
			submitLockedUnlock();
		});

		$('#menuToggle').addEventListener('click', openMenu);
		$('#menuClose').addEventListener('click', closeMenu);
		$('#menuBackdrop').addEventListener('click', closeMenu);

		$('#menuLockButton').addEventListener('click', function () {
			if ($('#menuLockButton').disabled) {
				return;
			}
			lockWallet('Wallet locked.');
		});

		$$('[data-tab]').forEach(function (button) {
			button.addEventListener('click', function () {
				switchTab(button.dataset.tab);
			});
		});

		$('#activityList').addEventListener('click', function (event) {
			var toggle = event.target.closest('[data-activity-toggle]');
			if (!toggle) {
				return;
			}
			var detail = document.getElementById(toggle.dataset.activityToggle);
			if (!detail) {
				return;
			}
			var open = detail.classList.toggle('hidden') === false;
			toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
			toggle.closest('.activity-item').classList.toggle('open', open);
		});

		$('#refreshBalance').addEventListener('click', function () {
			refreshBalance(true);
		});

		$('#toggleBalancePrecision').addEventListener('click', function () {
			state.showFullBalance = !state.showFullBalance;
			updateBalanceUi(false);
		});

		$('#refreshActivity').addEventListener('click', function () {
			loadActivity(true);
		});

		$('#loadMoreActivity').addEventListener('click', function () {
			loadActivity(false);
		});

		$('#copyReceive').addEventListener('click', function () {
			copyValue(state.address);
		});

		$$('[data-copy-target]').forEach(function (button) {
			button.addEventListener('click', function () {
				var target = $(button.dataset.copyTarget);
				copyValue(target && target.value);
			});
		});

		$('#saveVaultForm').addEventListener('submit', function (event) {
			event.preventDefault();
			var password = $('#savePassword').value;
			var confirmPassword = $('#savePasswordConfirm').value;
			if (password !== confirmPassword) {
				showToast('Wallet passwords do not match.', 'danger');
				return;
			}
			var button = $('#saveVaultButton');
			setBusy(button, true, 'Encrypting...');
			Promise.resolve().then(function () {
				return saveCurrentPrivateKey(password);
			}).then(function () {
				$('#savePassword').value = '';
				$('#savePasswordConfirm').value = '';
				setSecurityCapabilityNotice('Private key saved encrypted on this device.');
				showToast('Private key saved encrypted on this device.');
			}).catch(function (error) {
				var message = error.message || 'Private key could not be saved.';
				if (/HTTPS|localhost|Web Crypto|Secure browser crypto|Secure random/i.test(message)) {
					setSecurityCapabilityNotice(message + ' You can continue using this wallet session-only, or reopen SweetWallet from a trusted HTTPS address to save it encrypted.', 'danger');
				}
				showToast(message, 'danger');
			}).finally(function () {
				setBusy(button, false);
			});
		});

		$('#sessionOnlyButton').addEventListener('click', function () {
			if (!state.savedVault) {
				showToast('This wallet is already session-only.');
				return;
			}
			if (!window.confirm('Remove the encrypted saved private key and keep this wallet session-only until you close it?')) {
				return;
			}
			requireSavedWalletPassword('Enter your wallet password to remove saved private-key storage.').then(function () {
				var publicRecord = {
					walletId: state.walletId || state.savedVault.walletId,
					address: state.address || state.savedVault.address,
					publicKey: state.publicKeyHex || state.savedVault.publicKey,
					mode: state.keys ? 'session' : 'watch',
					updatedAt: new Date().toISOString()
				};
				storageRemove(STORAGE.vault);
				deleteDeviceKey();
				state.savedVault = null;
				state.settings.requirePinBeforeSend = false;
				state.settings.requirePasswordBeforeSend = false;
				saveSettings();
				savePublicWallet(publicRecord);
				if (state.keys) {
					state.mode = 'session';
					updateWalletUi();
					showToast('Saved private key removed. This wallet is now session-only.');
				} else {
					openWatchOnly(publicRecord, 'Saved private key removed. This wallet is now watch-only.');
				}
			}).catch(function (error) {
				showToast(error.message || 'Saved private key was not removed.', 'danger');
			});
		});

		$('#exportBackupButton').addEventListener('click', function () {
			var backupPromise;
			if (state.savedVault) {
				backupPromise = requireSavedWalletPassword('Enter your wallet password to export the backup.').then(function (result) {
					return result.wif;
				});
			} else if (state.keys) {
				backupPromise = Promise.resolve(state.keys.toWIF());
			} else {
				backupPromise = Promise.reject(new Error('Unlock the wallet before exporting a private-key backup.'));
			}
			backupPromise.then(function (wif) {
				$('#backupWif').value = wif;
				$('#backupBox').classList.remove('hidden');
				showToast('Backup displayed. Do not store it in chat, email, screenshots, or unencrypted cloud notes.');
			}).catch(function (error) {
				showToast(error.message || 'Backup could not be exported.', 'danger');
			});
		});

		$('#copyBackupButton').addEventListener('click', function () {
			var value = $('#backupWif').value;
			if (!value || !window.confirm('Copy this private key to the clipboard? Clipboard history may be saved by your device or apps.')) {
				return;
			}
			copyValue(value);
			window.setTimeout(function () {
				if (navigator.clipboard && navigator.clipboard.writeText) {
					navigator.clipboard.writeText('').catch(function () {});
				}
			}, 60000);
		});

		$('#removeSavedKeyButton').addEventListener('click', function () {
			if (!state.savedVault) {
				showToast('No saved private key is stored on this device.');
				return;
			}
			var keepWatchOnly = window.confirm('Remove the saved private key? Press OK to retain this wallet as watch-only, or Cancel to remove the wallet record completely.');
			requireSavedWalletPassword('Enter your wallet password to remove the saved private key.').then(function () {
				removeSavedPrivateKey(keepWatchOnly);
			}).catch(function (error) {
				showToast(error.message || 'Saved private key was not removed.', 'danger');
			});
		});

		$('#watchOnlyButton').addEventListener('click', function () {
			if (!state.address) {
				showToast('Open a wallet first.', 'danger');
				return;
			}
			if (!window.confirm('Convert this device record to watch-only? Sending will be disabled until you import or unlock a private key again.')) {
				return;
			}
			if (state.savedVault) {
				requireSavedWalletPassword('Enter your wallet password to convert to watch-only.').then(function () {
					removeSavedPrivateKey(true);
				}).catch(function (error) {
					showToast(error.message || 'Wallet was not converted.', 'danger');
				});
				return;
			}
			openWatchOnly({
				walletId: state.walletId,
				address: state.address,
				publicKey: state.publicKeyHex
			}, 'Wallet converted to watch-only on this device.');
		});

		$('#deleteWalletButton').addEventListener('click', function () {
			if (!window.confirm('Delete all SweetWallet records from this device? Public blockchain history cannot be deleted.')) {
				return;
			}
			var phrase = window.prompt('Type DELETE WALLET to confirm.');
			if (phrase !== 'DELETE WALLET') {
				showToast('Delete cancelled.');
				return;
			}
			var passwordCheck = state.savedVault ? requireSavedWalletPassword('Enter your wallet password to delete this wallet from the device.') : Promise.resolve();
			passwordCheck.then(deleteWalletFromDevice).catch(function (error) {
				showToast(error.message || 'Wallet was not deleted.', 'danger');
			});
		});

		$('#changePasswordForm').addEventListener('submit', function (event) {
			event.preventDefault();
			if (!state.savedVault) {
				showToast('Save the private key before changing a wallet password.', 'danger');
				return;
			}
			if ($('#newPassword').value !== $('#newPasswordConfirm').value) {
				showToast('New wallet passwords do not match.', 'danger');
				return;
			}
			var button = $('#changePasswordButton');
			setBusy(button, true, 'Updating...');
			Vault.changePassword(state.savedVault, $('#currentPassword').value, $('#newPassword').value).then(function (record) {
				saveVaultRecord(record);
				$('#currentPassword').value = '';
				$('#newPassword').value = '';
				$('#newPasswordConfirm').value = '';
				showToast('Wallet password changed.');
			}).catch(function (error) {
				showToast(error.message || 'Wallet password could not be changed.', 'danger');
			}).finally(function () {
				setBusy(button, false);
			});
		});

		$('#pinForm').addEventListener('submit', function (event) {
			event.preventDefault();
			if (!state.savedVault) {
				showToast('Save the private key before enabling quick-unlock PIN.', 'danger');
				return;
			}
			var button = $('#setPinButton');
			setBusy(button, true, 'Protecting...');
			var vaultKeyBytes;
			Vault.getVaultKeyBytes(state.savedVault, $('#pinPassword').value).then(function (bytes) {
				vaultKeyBytes = bytes;
				return getDeviceKey(true);
			}).then(function (deviceKey) {
				return Vault.wrapVaultKeyForPin(vaultKeyBytes, $('#quickPin').value, deviceKey, state.savedVault);
			}).then(function (quickUnlock) {
				var record = JSON.parse(JSON.stringify(state.savedVault));
				record.quickUnlock = quickUnlock;
				record.updatedAt = new Date().toISOString();
				saveVaultRecord(record);
				$('#pinPassword').value = '';
				$('#quickPin').value = '';
				showToast('Quick-unlock PIN enabled. The PIN is combined with this browser device key.');
			}).catch(function (error) {
				showToast(error.message || 'Quick-unlock PIN could not be enabled.', 'danger');
			}).finally(function () {
				setBusy(button, false);
			});
		});

		$('#disablePinButton').addEventListener('click', function () {
			if (!state.savedVault || !hasQuickPin(state.savedVault)) {
				showToast('Quick-unlock PIN is already disabled.');
				return;
			}
			requireSavedWalletPassword('Enter your wallet password to disable quick-unlock PIN.').then(function () {
				var record = JSON.parse(JSON.stringify(state.savedVault));
				record.quickUnlock = {
					enabled: false,
					version: 1
				};
				record.updatedAt = new Date().toISOString();
				saveVaultRecord(record);
				return deleteDeviceKey();
			}).then(function () {
				state.settings.requirePinBeforeSend = false;
				saveSettings();
				showToast('Quick-unlock PIN disabled.');
			}).catch(function (error) {
				showToast(error.message || 'Quick-unlock PIN was not disabled.', 'danger');
			});
		});

		$('#autoLockTimeout').addEventListener('change', function () {
			var value = Number($('#autoLockTimeout').value);
			if (value < 0 && !window.confirm('Never auto-lock leaves the decrypted private key in memory until you close or lock the wallet. Continue?')) {
				$('#autoLockTimeout').value = String(state.settings.autoLockMs);
				return;
			}
			state.settings.autoLockMs = value;
			saveSettings();
			showToast('Auto-lock setting updated.');
		});

		$('#lockNowButton').addEventListener('click', function () {
			lockWallet('Wallet locked.');
		});

		function syncSecurityKeyRequirement(checked) {
			if (checked && !loadSecurityKeys().length) {
				showToast('Add a security key before requiring Security Key Approval.', 'danger');
				renderSecurityUi();
				return;
			}
			if (checked && loadSecurityKeys().length < 2) {
				showToast('Register a backup security key before relying on strict send approval.', 'warning');
			}
			state.settings.requireSecurityKeyBeforeSend = !!checked;
			saveSettings();
		}

		$('#securityKeyRequired').addEventListener('change', function () {
			syncSecurityKeyRequirement($('#securityKeyRequired').checked);
		});

		$('#requireSecurityKeyBeforeSend').addEventListener('change', function () {
			syncSecurityKeyRequirement($('#requireSecurityKeyBeforeSend').checked);
		});

		$('#requirePasswordBeforeSend').addEventListener('change', function () {
			if ($('#requirePasswordBeforeSend').checked && !state.savedVault) {
				showToast('Save the private key before requiring a wallet password for sends.', 'danger');
				renderSecurityUi();
				return;
			}
			state.settings.requirePasswordBeforeSend = $('#requirePasswordBeforeSend').checked;
			saveSettings();
		});

		$('#requirePinBeforeSend').addEventListener('change', function () {
			if ($('#requirePinBeforeSend').checked && !hasQuickPin(state.savedVault)) {
				showToast('Enable quick-unlock PIN before requiring PIN for sends.', 'danger');
				renderSecurityUi();
				return;
			}
			state.settings.requirePinBeforeSend = $('#requirePinBeforeSend').checked;
			saveSettings();
		});

		$('#requireConfirmEveryTx').addEventListener('change', function () {
			state.settings.requireConfirmEveryTx = true;
			saveSettings();
			showToast('SweetWallet always requires confirmation for every transaction.');
		});

		$('#addSecurityKeyButton').addEventListener('click', function () {
			addSecurityKey('primary');
		});

		$('#addBackupSecurityKeyButton').addEventListener('click', function () {
			addSecurityKey('backup');
		});

		$('#generateRecoveryCodesButton').addEventListener('click', generateRecoveryCodes);

		$('#securityKeyList').addEventListener('click', function (event) {
			var rename = event.target.closest('[data-security-key-rename]');
			var remove = event.target.closest('[data-security-key-remove]');
			var keys = loadSecurityKeys();
			if (rename) {
				var renameIndex = Number(rename.dataset.securityKeyRename);
				var newName = window.prompt('Rename security key.', keys[renameIndex] && keys[renameIndex].name);
				if (newName && keys[renameIndex]) {
					keys[renameIndex].name = newName;
					saveSecurityKeys(keys);
				}
			}
			if (remove) {
				var removeIndex = Number(remove.dataset.securityKeyRemove);
				if (keys[removeIndex] && window.confirm('Remove this security key from SweetWallet?')) {
					keys.splice(removeIndex, 1);
					saveSecurityKeys(keys);
					if (!keys.length) {
						state.settings.requireSecurityKeyBeforeSend = false;
						saveSettings();
					}
				}
			}
		});

		$('#sendAddress').addEventListener('input', function () {
			var target = parsePaymentTarget($('#sendAddress').value);
			if (target.amount && !$('#sendAmount').value) {
				$('#sendAmount').value = target.amount;
			}
		});

		$('#scanQrButton').addEventListener('click', openQrScanner);
		$('#closeQrScanner').addEventListener('click', stopQrScanner);

		$('#sendMax').addEventListener('click', function () {
			var fee = amountToSatoshis($('#sendFee').value || state.fee);
			var max = Math.max(0, state.balance - fee);
			$('#sendAmount').value = (max / Math.pow(10, CONFIG.decimals)).toFixed(CONFIG.decimals).replace(/0+$/, '').replace(/\.$/, '');
		});

		$('#sendForm').addEventListener('submit', function (event) {
			event.preventDefault();
			prepareSend();
		});

		$('#cancelSend').addEventListener('click', hideConfirm);
		$('#confirmSend').addEventListener('click', confirmSend);

		$('#broadcastForm').addEventListener('submit', function (event) {
			event.preventDefault();
			var raw = $('#rawTx').value.trim();
			if (!/^[0-9a-fA-F]+$/.test(raw)) {
				showToast('Paste a raw transaction hex string.', 'danger');
				return;
			}
			var button = $('#broadcastButton');
			setBusy(button, true, 'Broadcasting...');
			broadcastRaw(raw).then(function (data) {
				if (data.error) {
					throw new Error(data.error.message || 'Broadcast failed.');
				}
				var txid = data.result || data.txid || '';
				$('#broadcastResult').innerHTML = '<a href="' + CONFIG.explorerTx(txid) + '" target="_blank" rel="noopener">' + txid + '</a>';
				$('#rawTx').value = '';
				showToast('Raw transaction broadcasted.');
			}).catch(function (error) {
				showToast(error.message || 'Broadcast failed.', 'danger');
			}).finally(function () {
				setBusy(button, false);
			});
		});

		$('#backendForm').addEventListener('submit', function (event) {
			event.preventDefault();
			var url = $('#backendInput').value.trim().replace(/\/+$/, '');
			if (!/^https?:\/\//.test(url)) {
				showToast('Backend URL must start with http:// or https://.', 'danger');
				return;
			}
			var button = $('#backendButton');
			setBusy(button, true, 'Checking...');
			fetch(url + '/info').then(function (response) {
				if (!response.ok) {
					throw new Error('Backend did not answer /info.');
				}
				return response.json();
			}).then(function (data) {
				if (data.error) {
					throw new Error(data.error.message || 'Backend returned an error.');
				}
				setBackend(url);
				updateBackendUi();
				showToast('Backend switched.');
				refreshBalance(false);
			}).catch(function (error) {
				$('#backendInput').value = getBackend();
				showToast(error.message || 'Backend is unavailable.', 'danger');
			}).finally(function () {
				setBusy(button, false);
			});
		});

		$('#addressType').addEventListener('change', function () {
			setAddressType($('#addressType').value);
			if (state.keys) {
				openWallet(state.keys, false, state.mode, state.walletId);
				showToast('Address type changed.');
			} else if (state.mode === 'watch' || state.mode === 'locked') {
				showToast('Unlock or import a private key before changing address type.', 'warning');
			}
		});

		$('#logoutButton').addEventListener('click', closeWallet);

		['click', 'keydown', 'touchstart', 'input'].forEach(function (eventName) {
			document.addEventListener(eventName, touchActivity, {
				passive: true
			});
		});

		document.addEventListener('visibilitychange', function () {
			if (document.hidden) {
				state.backgroundAt = Date.now();
				return;
			}
			if (state.backgroundAt && Date.now() - state.backgroundAt > 60000) {
				lockWallet('Wallet locked after backgrounding.');
			}
			state.backgroundAt = 0;
			resetAutoLockTimer();
		});
	}

	function init() {
		if (!window.bitcoin) {
			showToast('Wallet library failed to load.', 'danger');
			return;
		}
		if (!Vault) {
			showToast('Encrypted vault library failed to load.', 'danger');
			return;
		}
		loadSettings();
		loadStoredRecords();
		$('#sendFee').value = state.fee;
		$('#addressType').value = getAddressType();
		updateBackendUi();
		updateWalletUi();
		wireEvents();
		renderSecurityUi();
		if (state.savedVault) {
			setLoginMode('pin');
		} else if (state.publicWallet && state.publicWallet.address) {
			openWatchOnly(state.publicWallet);
		} else {
			setLoginMode('pin');
			switchTab('activity');
		}
		if (window.lucide) {
			window.lucide.createIcons();
		}
	}

	document.addEventListener('DOMContentLoaded', init);
})();
