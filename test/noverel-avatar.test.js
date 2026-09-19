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
	assert.match(html, /id="loginAvatarWrap"[\s\S]*?<span>Welcome back<\/span>/);
	assert.match(html, /id="lockedAvatarWrap"/);
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
