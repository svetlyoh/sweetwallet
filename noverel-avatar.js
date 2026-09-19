(function (root, factory) {
	var api = factory(root);
	if (typeof module === 'object' && module.exports) { module.exports = api; }
	if (root) { root.NoverelAvatar = api; }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
	'use strict';

	var STORAGE_KEY = 'noverel_avatar_v1';
	var LEGACY_KEY = 'keylink_security_avatar_v1';
	var MANIFEST_URL = '/avatars/avatar-manifest.json';
	var CATALOG_VERSION = '2026-09-18';
	var ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

	function normalizeManifest(value, manifestUrl) {
		var envelope = Array.isArray(value) ? { avatars: value, catalogVersion: CATALOG_VERSION } : value;
		if (!envelope || !Array.isArray(envelope.avatars) || !envelope.avatars.length) {
			throw new Error('Avatar by Noverel catalog is unavailable.');
		}
		var ids = Object.create(null);
		var names = Object.create(null);
		var base = manifestUrl || MANIFEST_URL;
		var catalogVersion = String(envelope.catalogVersion || CATALOG_VERSION);
		var avatars = envelope.avatars.map(function (entry) {
			var id = String(entry && entry.id || '').trim();
			var displayName = String(entry && entry.displayName || '').trim();
			var image = String(entry && entry.image || '').trim();
			var keywords = entry && Array.isArray(entry.keywords) ? entry.keywords.map(function (keyword) {
				return String(keyword || '').trim();
			}).filter(Boolean) : [];
			var filename = image.split('/').pop();
			if (!ID_PATTERN.test(id) || !displayName || !image || !keywords.length || ids[id] || names[filename]) {
				throw new Error('Avatar by Noverel catalog is invalid.');
			}
			ids[id] = true;
			names[filename] = true;
			return Object.freeze({
				id: id,
				displayName: displayName,
				image: image,
				imageUrl: new URL(image, new URL(base, root && root.location ? root.location.href : 'http://localhost/')).href,
				keywords: Object.freeze(keywords)
			});
		});
		return { avatars: avatars, catalogVersion: catalogVersion };
	}

	function secureIndex(cryptoObject, length) {
		if (!cryptoObject || typeof cryptoObject.getRandomValues !== 'function') {
			throw new Error('Secure random avatar selection is unavailable.');
		}
		if (!Number.isSafeInteger(length) || length < 1 || length > 0x100000000) {
			throw new Error('Avatar by Noverel catalog is invalid.');
		}
		var range = 0x100000000;
		var limit = Math.floor(range / length) * length;
		var value = new Uint32Array(1);
		do { cryptoObject.getRandomValues(value); } while (value[0] >= limit);
		return value[0] % length;
	}

	function validMirror(value) {
		return !!(value && value.schemaVersion === 1 && ID_PATTERN.test(String(value.avatarId || '')));
	}

	function createAvatarManager(options) {
		options = options || {};
		var storage = options.storage || (root && root.localStorage);
		var cryptoObject = options.crypto || (root && root.crypto);
		var fetchImpl = options.fetch || (root && root.fetch && root.fetch.bind(root));
		var manifestUrl = options.manifestUrl || MANIFEST_URL;
		var catalog = [];
		var catalogVersion = CATALOG_VERSION;
		var catalogPromise = null;

		function readJson(key) {
			try {
				var raw = storage && storage.getItem(key);
				return raw ? JSON.parse(raw) : null;
			} catch (error) { return null; }
		}

		function getStoredProfile() {
			var profile = readJson(STORAGE_KEY);
			return validMirror(profile) ? profile : null;
		}

		function writeProfile(entry, source) {
			if (!storage) { throw new Error('Browser preferences are unavailable.'); }
			var profile = {
				schemaVersion: 1,
				avatarId: entry.id,
				displayName: entry.displayName,
				catalogVersion: catalogVersion,
				updatedAt: new Date().toISOString(),
				source: source || 'browser-local'
			};
			storage.setItem(STORAGE_KEY, JSON.stringify(profile));
			return profile;
		}

		function migrateLegacySelection() {
			if (getStoredProfile() || !storage) { return null; }
			var legacyId = '';
			try { legacyId = String(storage.getItem(LEGACY_KEY) || '').trim(); }
			catch (error) { return null; }
			var entry = getAvatarById(legacyId);
			return entry ? writeProfile(entry, 'keylink-legacy') : null;
		}

		function setCatalog(value) {
			var normalized = normalizeManifest(value, manifestUrl);
			catalog = normalized.avatars;
			catalogVersion = normalized.catalogVersion;
			migrateLegacySelection();
			return catalog.slice();
		}

		function loadManifest(value) {
			if (value) { return Promise.resolve(setCatalog(value)); }
			if (catalog.length) { return Promise.resolve(catalog.slice()); }
			if (catalogPromise) { return catalogPromise; }
			if (!fetchImpl) { return Promise.reject(new Error('Avatar by Noverel catalog is unavailable.')); }
			catalogPromise = fetchImpl(manifestUrl, {
				headers: { accept: 'application/json' },
				credentials: 'same-origin'
			}).then(function (response) {
				if (!response || !response.ok) { throw new Error('Avatar by Noverel catalog is unavailable.'); }
				return response.json();
			}).then(setCatalog).catch(function (error) {
				catalogPromise = null;
				throw error;
			});
			return catalogPromise;
		}

		function getAvatarById(id) {
			var wanted = String(id || '');
			return catalog.find(function (entry) { return entry.id === wanted; }) || null;
		}

		function getStoredAvatar() {
			var profile = getStoredProfile();
			return profile ? getAvatarById(profile.avatarId) : null;
		}

		function search(query) {
			var normalized = String(query || '').trim().toLowerCase();
			if (!normalized) { return catalog.slice(); }
			return catalog.filter(function (entry) {
				return [entry.displayName, entry.id].concat(entry.keywords).join(' ').toLowerCase().includes(normalized);
			});
		}

		function randomAvatar() {
			if (!catalog.length) { throw new Error('Avatar by Noverel catalog is unavailable.'); }
			return catalog[secureIndex(cryptoObject, catalog.length)];
		}

		function suggestions(count) {
			var pool = catalog.slice();
			var wanted = Math.max(0, Math.min(pool.length, Number.isFinite(Number(count)) ? Math.floor(Number(count)) : 6));
			var result = [];
			while (result.length < wanted) {
				result.push(pool.splice(secureIndex(cryptoObject, pool.length), 1)[0]);
			}
			return result;
		}

		function select(id, source) {
			var entry = getAvatarById(id);
			if (!entry) { throw new Error('Choose a valid Avatar by Noverel.'); }
			writeProfile(entry, source);
			return entry;
		}

		return Object.freeze({
			loadManifest: loadManifest,
			getAvatarById: getAvatarById,
			getStoredProfile: getStoredProfile,
			getStoredAvatar: getStoredAvatar,
			search: search,
			randomAvatar: randomAvatar,
			suggestions: suggestions,
			select: select,
			getCatalog: function () { return catalog.slice(); },
			getCatalogVersion: function () { return catalogVersion; }
		});
	}

	return Object.freeze({
		STORAGE_KEY: STORAGE_KEY,
		LEGACY_KEY: LEGACY_KEY,
		MANIFEST_URL: MANIFEST_URL,
		ID_PATTERN: ID_PATTERN,
		createAvatarManager: createAvatarManager
	});
}));
