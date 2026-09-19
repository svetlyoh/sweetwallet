'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Avatar = require('../noverel-avatar.js');

const root = path.join(__dirname, '..');
const avatarRoot = path.join(root, 'avatars');
const manifest = JSON.parse(fs.readFileSync(path.join(avatarRoot, 'avatar-manifest.json'), 'utf8'));

function storageMock(initial = {}) {
	const values = new Map(Object.entries(initial));
	return {
		getItem: (key) => values.has(key) ? values.get(key) : null,
		setItem: (key, value) => values.set(key, String(value)),
		removeItem: (key) => values.delete(key)
	};
}

test('Avatar by Noverel catalog contains 128 valid unique entries and PNGs', async () => {
	const manager = Avatar.createAvatarManager({ storage: storageMock(), crypto, manifestUrl: Avatar.MANIFEST_URL });
	const loaded = await manager.loadManifest(manifest);
	assert.equal(loaded.length, 128);
	assert.equal(new Set(loaded.map((entry) => entry.id)).size, 128);
	assert.equal(fs.readdirSync(avatarRoot).filter((name) => name.endsWith('.png')).length, 128);
	for (const entry of loaded) {
		assert.match(entry.id, Avatar.ID_PATTERN);
		assert.equal(fs.existsSync(path.join(avatarRoot, `${entry.id}.png`)), true, `${entry.id}.png is missing`);
		assert.match(entry.imageUrl, /\/avatars\/[a-z0-9-]+\.png$/);
	}
});

test('selection stores only harmless metadata in the common browser mirror', async () => {
	const storage = storageMock();
	const manager = Avatar.createAvatarManager({ storage, crypto, manifestUrl: Avatar.MANIFEST_URL });
	await manager.loadManifest(manifest);
	manager.select('amber-fox');
	const profile = JSON.parse(storage.getItem(Avatar.STORAGE_KEY));
	assert.deepEqual(Object.keys(profile).sort(), ['avatarId', 'catalogVersion', 'displayName', 'schemaVersion', 'source', 'updatedAt']);
	assert.equal(profile.avatarId, 'amber-fox');
	assert.equal(profile.displayName, 'Amber Fox');
	assert.equal(profile.source, 'browser-local');
	assert.equal(manager.getStoredAvatar().id, 'amber-fox');
	assert.equal(JSON.stringify(profile).includes('.png'), false);
});

test('legacy Keylink avatar ID migrates after catalog validation', async () => {
	const storage = storageMock({ [Avatar.LEGACY_KEY]: 'ocean-wave' });
	const manager = Avatar.createAvatarManager({ storage, crypto, manifestUrl: Avatar.MANIFEST_URL });
	await manager.loadManifest(manifest);
	const profile = manager.getStoredProfile();
	assert.equal(profile.avatarId, 'ocean-wave');
	assert.equal(profile.source, 'keylink-legacy');
});

test('search and secure random suggestions stay within the manifest', async () => {
	const manager = Avatar.createAvatarManager({ storage: storageMock(), crypto, manifestUrl: Avatar.MANIFEST_URL });
	await manager.loadManifest(manifest);
	assert.ok(manager.search('orange').some((entry) => entry.id === 'amber-fox'));
	const suggestions = manager.suggestions(6);
	assert.equal(suggestions.length, 6);
	assert.equal(new Set(suggestions.map((entry) => entry.id)).size, 6);
	assert.ok(suggestions.every((entry) => manager.getAvatarById(entry.id)));
	assert.throws(() => manager.select('not-a-real-avatar'), /valid Avatar by Noverel/);
});

test('Sweetwallet surfaces Avatar by Noverel without treating it as authentication', () => {
	const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
	const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');
	assert.match(html, /id="loginAvatarWrap"/);
	assert.match(html, /id="loginAvatarWrap"[\s\S]*?login-avatar-preview/);
	assert.doesNotMatch(html, /id="lockedAvatarWrap"/);
	assert.match(html, /id="headerAvatarButton"/);
	assert.match(html, /id="menuChooseAvatar"/);
	assert.match(html, /id="avatarPickerModal"/);
	assert.match(html, /not identity verification, tracking, or KYC/);
	assert.match(html, /<\/main>[\s\S]*?<footer class="about-footer"/);
	assert.match(html, /Made with[\s\S]*?data-lucide="heart"[\s\S]*?href="https:\/\/noverel\.net\/"[\s\S]*?>Noverel<\/a>/);
	assert.match(client, /offerAvatarSetup\(false\)/);
	assert.match(client, /method === 'GET' && data && data\.error/);
	assert.match(client, /function requestHistoryPage\(address, offset\)/);
	assert.doesNotMatch(client, /removeItem\(['"]noverel_avatar_v1/);
});

test('automatic activity loading does not expose raw backend errors after login', () => {
	const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');
	assert.match(client, /function loadActivity\(reset, showErrors\)/);
	assert.match(client, /if \(showErrors\) \{[\s\S]*?Activity is temporarily unavailable\./);
	assert.doesNotMatch(client, /showToast\(error\.message \|\| 'Activity load failed\.'/);
	assert.match(client, /#refreshActivity'[\s\S]*?loadActivity\(true, true\)/);
});

test('automatic balance loading does not expose raw backend errors after login', () => {
	const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');
	assert.match(client, /function refreshBalance\(showSuccess\)/);
	assert.match(client, /if \(showSuccess\) \{[\s\S]*?Balance is temporarily unavailable\./);
	assert.doesNotMatch(client, /showToast\(error\.message \|\| 'Balance refresh failed\.'/);
});

test('top bar removes two of eight balance decimals and shows its avatar only when unlocked', () => {
	const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
	const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');
	assert.match(html, /id="refreshBalance"[\s\S]*?id="headerAvatarButton"[\s\S]*?id="menuToggle"/);
	assert.match(client, /function formatHeaderBalance\(satoshis\)[\s\S]*?minimumFractionDigits: 6,[\s\S]*?maximumFractionDigits: 6/);
	assert.match(client, /Access\.headerAvatarVisible\(state\.mode, state\.keys, entry\)/);
	assert.match(client, /Access\.loginAvatarVisible\(state\.mode, entry\)/);
	assert.match(client, /panel\.classList\.toggle\('active', panel\.dataset\.panel === name\);[\s\S]*?renderAvatarSurfaces\(\)/);
});

test('saved-wallet unlock uses compact identity copy and keyboard-aware PIN layout', () => {
	const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
	const css = fs.readFileSync(path.join(root, 'sweetwallet.css'), 'utf8');
	const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');
	assert.doesNotMatch(html, /Saved wallet:/);
	assert.match(html, /class="wallet-unlock-summary[^"]*"[\s\S]*?Unlock saved wallet[\s\S]*?id="savedWalletAddress"/);
	assert.doesNotMatch(html, /lockedSavedWalletAddress|lockedUnlockForm/);
	assert.match(css, /\.login-avatar-preview\s*\{[\s\S]*?width: 114px;[\s\S]*?height: 92px;[\s\S]*?border-radius: 24px/);
	assert.match(css, /\.noverel-avatar-button\s*\{[\s\S]*?width: 60px;[\s\S]*?height: 46px;[\s\S]*?border-radius: 16px/);
	assert.match(css, /body\.pin-focused[\s\S]*?#pinEntryWrap[\s\S]*?\.pin-entry/);
	assert.match(client, /window\.visualViewport\.addEventListener\('resize', syncPinViewportState/);
	assert.match(client, /scrollIntoView\(\{ block: 'nearest', inline: 'nearest', behavior: 'auto' \}\)/);
});

test('avatar artwork is contained and new-wallet action is an accessible icon control', () => {
	const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
	const css = fs.readFileSync(path.join(root, 'sweetwallet.css'), 'utf8');
	assert.match(html, /id="createWallet"[^>]*aria-label="Create new wallet"[^>]*title="Create new wallet"/);
	assert.match(html, /id="createWallet"[\s\S]*?data-lucide="plus"/);
	assert.doesNotMatch(html, /id="createWallet"[\s\S]*?<span>New<\/span>/);
	assert.match(css, /\.login-avatar-preview img\s*\{[\s\S]*?object-fit: contain/);
	assert.match(css, /\.new-wallet-button\s*\{[\s\S]*?width: 42px;[\s\S]*?height: 42px/);
});

test('new-wallet reminder is friendly and only revealed after creating a wallet', () => {
	const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
	const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');
	assert.match(html, /id="newWalletNotice" class="notice new-wallet-notice hidden"/);
	assert.match(html, /This new wallet is only available for now\. To keep it on this device, save it with a password in the Security menu\./);
	assert.match(client, /\$\('#createWallet'\)[\s\S]*?\$\('#newWalletNotice'\)\.classList\.remove\('hidden'\)/);
	assert.match(client, /function closeWallet[\s\S]*?\$\('#newWalletNotice'\)\.classList\.add\('hidden'\)/);
});

test('locked startup refreshes the live balance using the saved public address', () => {
	const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');
	assert.match(client, /balanceAddress = state\.address \|\| \(state\.savedVault && state\.savedVault\.address\) \|\| ''/);
	assert.match(client, /requestBalance\(balanceAddress\)/);
	assert.match(client, /if \(state\.savedVault\) \{[\s\S]*?state\.mode = 'locked';[\s\S]*?state\.loginMode = Access\.initialLoginMode\(state\.savedVault\);[\s\S]*?refreshBalance\(false\);[\s\S]*?startBalanceLoop\(\)/);
});

test('balance loading falls back to Esplora totals and spendable outputs', () => {
	const client = fs.readFileSync(path.join(root, 'sweetwallet.js'), 'utf8');
	assert.match(client, /function requestBalance\(address\)/);
	assert.match(client, /requestApi\('\/balance\/' \+ encodedAddress\)/);
	assert.match(client, /requestApi\('\/esplora\/address\/' \+ encodedAddress\)/);
	assert.match(client, /chain\.funded_txo_sum[\s\S]*?chain\.spent_txo_sum/);
	assert.match(client, /mempool\.funded_txo_sum[\s\S]*?mempool\.spent_txo_sum/);
	assert.match(client, /requestApi\('\/unspent\/' \+ encodedAddress \+ '\?amount=0'\)/);
	assert.match(client, /outputs\.reduce\(function \(total, output\)/);
});
