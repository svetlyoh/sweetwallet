'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'sweetwallet.css'), 'utf8');

test('Security has one compact Password control and one compact Quick PIN control', () => {
	assert.match(html, /aria-label="Wallet access"[\s\S]*?id="walletPasswordStatus"[\s\S]*?id="saveWalletAccessButton"[\s\S]*?id="changeWalletPasswordButton"[\s\S]*?id="walletPinStatus"[\s\S]*?id="setupPinAccessButton"/);
	assert.match(html, /id="changePasswordModal"[\s\S]*?id="changePasswordModalForm"[\s\S]*?Current wallet password[\s\S]*?New wallet password/);
	assert.doesNotMatch(html, /id="saveVaultForm"|id="changePasswordForm"|id="pinForm"|id="pinPassword"|id="quickPin"/);
	assert.doesNotMatch(client, /#saveVaultForm|#changePasswordForm|#pinForm|#pinPassword|#quickPin|#disablePinButton/);
});

test('Security state renderer exposes the appropriate access action for each wallet state', () => {
	assert.match(client, /var hasVault = !!vault;[\s\S]*?var hasPin = hasQuickPin\(vault\);[\s\S]*?var canSign = !!state\.keys;/);
	assert.match(client, /walletPasswordStatus.*hasVault \? 'Set' : 'Not set'/);
	assert.match(client, /walletPinStatus.*!hasVault \? 'Unavailable until wallet password is set'[\s\S]*?hasPin \? 'Enabled/);
	assert.match(client, /saveWalletAccessButton.*hasVault \|\| !canSign/);
	assert.match(client, /changeWalletPasswordButton.*!hasVault/);
	assert.match(client, /setupPinAccessButton.*hasPin \? 'Manage PIN' : 'Set Up PIN'/);
});

test('wallet passwords are consumed verbatim at unlock and PIN setup still verifies the saved vault', () => {
	assert.match(client, /function readWalletPassword\(selector\)[\s\S]*?return input \? input\.value : ''/);
	assert.match(client, /var value = readWalletPassword\('#loginSecret'\);[\s\S]*?if \(!value\)/);
	assert.doesNotMatch(client, /loginSecret'\)\.value\.trim\(\)/);
	assert.match(client, /Vault\.getVaultKeyBytes\(state\.savedVault, password\)/);
	assert.match(client, /Vault\.decryptVault\(state\.savedVault, password\)/);
	assert.match(client, /openWalletPasswordSetupFlow[\s\S]*?state\.pinSetup\.action = 'save-wallet'/);
});

test('new and changed passwords are verified against the persisted encrypted vault before success', () => {
	assert.match(client, /function persistVerifiedVaultRecord\(record, password, expectedWif\)[\s\S]*?verifyVaultRecord\(record, password, expectedWif\)[\s\S]*?persistVaultRecord\(record\)[\s\S]*?verifyVaultRecord\(persisted, password, expectedWif\)/);
	assert.match(client, /function saveCurrentPrivateKey\(password\)[\s\S]*?persistVerifiedVaultRecord\(record, password, activeWif\)/);
	assert.match(client, /function submitChangePasswordFlow\(\)[\s\S]*?persistVerifiedVaultRecord\(record, newPassword, activeWif\)/);
	assert.match(client, /function unlockSavedWithPassword\(password\)[\s\S]*?state\.mode === 'locked' \? storageJsonGet\(STORAGE\.vault, null\)/);
});

test('Change Wallet Password labels are scoped to white modal text', () => {
	assert.match(css, /#changePasswordModal label\s*\{[\s\S]*?color:\s*#fff;/);
});
