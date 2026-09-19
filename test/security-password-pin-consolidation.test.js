'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');

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
	assert.match(client, /var value = \$\('#loginSecret'\)\.value;[\s\S]*?if \(!value\)/);
	assert.doesNotMatch(client, /\$\('#loginSecret'\)\.value\.trim\(\)/);
	assert.match(client, /Vault\.getVaultKeyBytes\(state\.savedVault, password\)/);
	assert.match(client, /Vault\.decryptVault\(state\.savedVault, password\)/);
	assert.match(client, /openWalletPasswordSetupFlow[\s\S]*?state\.pinSetup\.action = 'save-wallet'/);
});
