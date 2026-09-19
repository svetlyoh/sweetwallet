'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Access = require('../sweetwallet-access.js');

function screen() {
	const values = new Set();
	return {
		classList: {
			toggle(name, active) { active ? values.add(name) : values.delete(name); },
			contains(name) { return values.has(name); }
		}
	};
}

function documentHarness() {
	const loginScreen = screen();
	const walletScreen = screen();
	return {
		loginScreen,
		walletScreen,
		document: {
			getElementById(id) {
				return id === 'loginScreen' ? loginScreen : (id === 'walletScreen' ? walletScreen : null);
			}
		}
	};
}

function assertView(mode, expectedLogin, expectedWallet) {
	const harness = documentHarness();
	const result = Access.applyScreenVisibility(harness.document, mode);
	assert.equal(result.loginVisible, expectedLogin, mode + ' login visibility');
	assert.equal(result.walletVisible, expectedWallet, mode + ' wallet visibility');
	assert.equal(harness.loginScreen.classList.contains('active'), expectedLogin);
	assert.equal(harness.walletScreen.classList.contains('active'), expectedWallet);
	assert.notEqual(harness.loginScreen.classList.contains('active'), harness.walletScreen.classList.contains('active'), 'exactly one top-level screen is active');
}

const savedWithPin = { quickUnlock: { enabled: true, pinLength: 6 } };
const savedWithoutPin = { quickUnlock: { enabled: false } };

test('screen visibility follows access state instead of public address presence', () => {
	assertView('closed', true, false);
	assertView('locked', true, false);
	assertView('session', false, true);
	assertView('saved', false, true);
	assertView('watch', false, true);
});

test('saved startup chooses usable unlock modes while fresh browsers start at welcome', () => {
	assert.equal(Access.initialLoginMode(savedWithPin), 'pin');
	assert.equal(Access.initialLoginMode(savedWithoutPin), 'password');
	assert.equal(Access.initialLoginMode(null), 'password');
	assert.equal(Access.loginPresentation('pin', savedWithPin).pinVisible, true);
	assert.equal(Access.loginPresentation('password', savedWithoutPin).secretVisible, true);
	assert.equal(Access.accessExperience('closed', null, 'welcome'), 'welcome');
	assert.equal(Access.accessExperience('closed', null, 'import'), 'import');
	assert.equal(Access.accessExperience('locked', savedWithPin), 'unlock');
	assert.equal(Access.accessExperience('session', null), 'wallet');
});

test('login mode switches expose the requested usable control and describe unavailable methods', () => {
	const pin = Access.loginPresentation('pin', savedWithPin);
	const password = Access.loginPresentation('password', savedWithPin);
	assert.equal(pin.pinVisible, true);
	assert.equal(pin.submitVisible, false);
	assert.equal(password.secretVisible, true);
	assert.equal(password.submitVisible, true);
	const unavailablePin = Access.loginPresentation('pin', null);
	const unavailablePassword = Access.loginPresentation('password', null);
	assert.equal(unavailablePin.pinVisible, false);
	assert.match(unavailablePin.availability.message, /No quick-unlock PIN/);
	assert.equal(unavailablePassword.secretVisible, false);
	assert.match(unavailablePassword.availability.message, /No saved wallet/);
});

test('fresh, import, and returning experiences keep their controls separate', () => {
	const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
	const client = fs.readFileSync(path.join(__dirname, '..', 'sweetwallet.js'), 'utf8');
	assert.match(html, /id="welcomeAccessView"[\s\S]*?Create New Wallet[\s\S]*?I Already Have a Wallet/);
	assert.match(html, /id="importAccessView"[\s\S]*?id="importPrivateKey"[\s\S]*?Open Wallet/);
	assert.match(html, /id="unlockAccessView"[\s\S]*?data-login-mode="pin"[\s\S]*?data-login-mode="password"/);
	assert.doesNotMatch(html, /data-login-mode="privateKey"/);
	assert.doesNotMatch(html, /id="createdCard"|id="createdKey"/);
	assert.match(client, /function submitImportWallet\(\)[\s\S]*?That private key is not valid for Sugarchain\./);
	assert.match(client, /input\.value = '';[\s\S]*?openWallet\(keys, false, 'session'\)/);
});

test('new wallet backups are deliberate and disconnect never displays a private key', () => {
	const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
	const client = fs.readFileSync(path.join(__dirname, '..', 'sweetwallet.js'), 'utf8');
	assert.match(html, /id="pinSetupBackupStep"[\s\S]*?id="newWalletBackupKey"[^>]*type="password"[\s\S]*?id="backupAcknowledged"/);
	assert.match(client, /openPinSetupFlow\(true\)/);
	assert.match(client, /state\.pinSetup\.step === 'backup'[\s\S]*?backupAcknowledged/);
	assert.match(html, /id="disconnectConfirmStep"[\s\S]*?Make sure you already have your private-key backup/);
	assert.doesNotMatch(html, /disconnectBackupWif|copyDisconnectBackup|Disconnecting requires you to save your private key first/);
	assert.doesNotMatch(client, /disconnectFlow\.backupWif|setDisconnectStep\('backup'\)/);
});

test('lock and unlock transition between the same canonical access screen and wallet dashboard', () => {
	assertView('saved', false, true);
	assert.equal(Access.loginAvatarVisible('saved', true), false);
	assert.equal(Access.headerAvatarVisible('saved', true, true), true);
	assertView('locked', true, false);
	assert.equal(Access.loginAvatarVisible('locked', true), true);
	assert.equal(Access.headerAvatarVisible('locked', false, true), false);
	assertView('saved', false, true);
	assert.equal(Access.loginAvatarVisible('saved', true), false);
	assert.equal(Access.headerAvatarVisible('saved', true, true), true);
});

test('watch-only wallets keep the dashboard but never present an authentication avatar in the header', () => {
	assertView('watch', false, true);
	assert.equal(Access.loginAvatarVisible('watch', true), false);
	assert.equal(Access.headerAvatarVisible('watch', false, true), false);
});

test('the document has one canonical wallet authentication form and no locked login surface', () => {
	const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
	const client = fs.readFileSync(path.join(__dirname, '..', 'sweetwallet.js'), 'utf8');
	assert.equal((html.match(/id="loginForm"/g) || []).length, 1);
	assert.doesNotMatch(html, /lockedUnlockForm|lockedAvatarWrap|lockedPinEntry|lockedPasswordWrap|data-locked-mode/);
	assert.doesNotMatch(client, /function updateLockedUi|function submitLockedPin|function submitLockedUnlock|lockedPinInput/);
});
