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

test('reselecting Password preserves the typed credential while a real mode change clears stale input', () => {
	const duplicatePasswordActivation = Access.loginModeTransition('password', 'password', savedWithPin);
	assert.equal(duplicatePasswordActivation.mode, 'password');
	assert.equal(duplicatePasswordActivation.changed, false);
	assert.equal(duplicatePasswordActivation.clearPassword, false);

	const switchFromPin = Access.loginModeTransition('pin', 'password', savedWithPin);
	assert.equal(switchFromPin.mode, 'password');
	assert.equal(switchFromPin.changed, true);
	assert.equal(switchFromPin.clearPassword, true);

	const fallback = Access.loginModeTransition('password', 'unexpected', savedWithPin);
	assert.equal(fallback.mode, 'pin');
	assert.equal(fallback.clearPassword, true);

	const client = fs.readFileSync(path.join(__dirname, '..', 'sweetwallet.js'), 'utf8');
	assert.match(client, /Access\.loginModeTransition\(state\.loginMode, mode, state\.savedVault\)/);
	assert.match(client, /if \(transition\.clearPassword && \$\('#loginSecret'\)\)/);
});

test('lock-screen mode buttons activate PIN before the password keyboard can consume a touch', () => {
	const client = fs.readFileSync(path.join(__dirname, '..', 'sweetwallet.js'), 'utf8');
	assert.match(client, /function activateLoginMode\(mode\)[\s\S]*?Access\.loginModeAvailability\(mode, state\.savedVault\)[\s\S]*?setLoginMode\(mode\)[\s\S]*?state\.loginMode === 'pin'[\s\S]*?focusPinInput\(\)/);
	assert.match(client, /button\.addEventListener\('pointerdown'[\s\S]*?event\.preventDefault\(\)[\s\S]*?activateLoginMode\(button\.dataset\.loginMode\)/);
	assert.match(client, /button\.addEventListener\('click'[\s\S]*?event\.detail !== 0[\s\S]*?activateLoginMode\(button\.dataset\.loginMode\)/);
});

test('the invisible PIN input is contained inside the PIN cells and cannot cover Password', () => {
	const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
	assert.match(html, /id="pinEntry"[^>]*>[\s\S]*?<input id="pinInput" class="pin-input"[\s\S]*?<\/div>\s*<\/div>\s*<div class="login-mode-toggle unlock-mode-toggle"/);
	assert.doesNotMatch(html, /<\/div>\s*<input id="pinInput" class="pin-input"[\s\S]*?<div class="login-mode-toggle unlock-mode-toggle"/);
	assert.equal(Access.loginPresentation('password', savedWithPin).secretVisible, true);
	assert.equal(Access.loginPresentation('password', savedWithPin).submitVisible, true);
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

test('new wallet backups are deliberate and disconnect only offers a masked authorized copy control', () => {
	const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
	const client = fs.readFileSync(path.join(__dirname, '..', 'sweetwallet.js'), 'utf8');
	assert.match(html, /id="pinSetupBackupStep"[\s\S]*?id="newWalletBackupKey"[^>]*type="password"[\s\S]*?id="backupAcknowledged"/);
	assert.match(client, /openPinSetupFlow\(true\)/);
	assert.match(client, /state\.pinSetup\.step === 'backup'[\s\S]*?backupAcknowledged/);
	assert.match(html, /id="disconnectConfirmStep"[\s\S]*?Make sure you already have your private-key backup/);
	assert.doesNotMatch(html, /disconnectBackupWif|Disconnecting requires you to save your private key first/);
	assert.doesNotMatch(client, /setDisconnectStep\('backup'\)/);
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

test('locking clears key material without rewriting the encrypted vault', () => {
	const client = fs.readFileSync(path.join(__dirname, '..', 'sweetwallet.js'), 'utf8');
	const lockBody = client.match(/function lockWallet\(message\) \{([\s\S]*?)\n\t\}/);
	assert.ok(lockBody, 'lockWallet is present');
	assert.match(lockBody[1], /clearSensitiveMemory\(\)[\s\S]*?state\.mode = 'locked'/);
	assert.doesNotMatch(lockBody[1], /Vault\.createVault|Vault\.changePassword|saveVaultRecord|storageJsonSet\(STORAGE\.vault/);
	assert.match(client, /function unlockSavedWithPassword\(password\)[\s\S]*?state\.mode === 'locked' \? storageJsonGet\(STORAGE\.vault, null\)/);
});

test('watch-only wallets keep the dashboard but never present an authentication avatar in the header', () => {
	assertView('watch', false, true);
	assert.equal(Access.loginAvatarVisible('watch', true), false);
	assert.equal(Access.headerAvatarVisible('watch', false, true), false);
});

test('avatar editing is authorized only for an unlocked wallet with its private key', () => {
	assert.equal(Access.avatarEditingAllowed('closed', false), false);
	assert.equal(Access.avatarEditingAllowed('locked', false), false);
	assert.equal(Access.avatarEditingAllowed('watch', false), false);
	assert.equal(Access.avatarEditingAllowed('saved', true), true);
	assert.equal(Access.avatarEditingAllowed('session', true), true);
});

test('the document has one canonical wallet authentication form and no locked login surface', () => {
	const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
	const client = fs.readFileSync(path.join(__dirname, '..', 'sweetwallet.js'), 'utf8');
	assert.equal((html.match(/id="loginForm"/g) || []).length, 1);
	assert.doesNotMatch(html, /lockedUnlockForm|lockedAvatarWrap|lockedPinEntry|lockedPasswordWrap|data-locked-mode/);
	assert.doesNotMatch(client, /function updateLockedUi|function submitLockedPin|function submitLockedUnlock|lockedPinInput/);
});
