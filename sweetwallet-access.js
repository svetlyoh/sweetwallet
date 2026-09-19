(function (root, factory) {
	var api = factory();
	if (typeof module === 'object' && module.exports) { module.exports = api; }
	if (root) { root.SweetWalletAccess = api; }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
	'use strict';

	function hasQuickPin(record) {
		return !!(record && record.quickUnlock && record.quickUnlock.enabled);
	}

	function accessRequired(mode) {
		return mode === 'closed' || mode === 'locked';
	}

	function walletScreenVisible(mode) {
		return mode === 'session' || mode === 'saved' || mode === 'watch';
	}

	function initialLoginMode(savedVault) {
		if (hasQuickPin(savedVault)) { return 'pin'; }
		return 'password';
	}

	function accessExperience(mode, savedVault, requestedView) {
		if (walletScreenVisible(mode)) { return 'wallet'; }
		if (requestedView === 'import' && !savedVault) { return 'import'; }
		if (savedVault && accessRequired(mode)) { return 'unlock'; }
		return 'welcome';
	}

	function loginModeAvailability(mode, savedVault) {
		if (mode === 'password') {
			return savedVault ? { available: true, message: '' } : {
				available: false,
				message: 'No saved wallet is available on this browser.'
			};
		}
		if (mode === 'pin') {
			if (hasQuickPin(savedVault)) { return { available: true, message: '' }; }
			return savedVault ? {
				available: false,
				message: 'No quick-unlock PIN is saved on this browser. Use Password.'
			} : {
				available: false,
				message: 'No quick-unlock PIN is saved on this browser. Use Password.'
			};
		}
		return { available: false, message: 'Choose a login method.' };
	}

	function loginPresentation(mode, savedVault) {
		var availability = loginModeAvailability(mode, savedVault);
		if (!availability.available) {
			return Object.freeze({
				availability: availability,
				pinVisible: false,
				secretVisible: false,
				submitVisible: false
			});
		}
		return Object.freeze({
			availability: availability,
			pinVisible: mode === 'pin',
			secretVisible: mode === 'password',
			submitVisible: mode !== 'pin'
		});
	}

	function loginAvatarVisible(mode, avatarExists) {
		return !!avatarExists && accessRequired(mode);
	}

	function headerAvatarVisible(mode, hasKeys, avatarExists) {
		return !!avatarExists && !!hasKeys && (mode === 'saved' || mode === 'session');
	}

	function applyScreenVisibility(documentObject, mode) {
		var loginVisible = accessRequired(mode);
		var walletVisible = walletScreenVisible(mode);
		if (loginVisible === walletVisible) {
			throw new Error('SweetWallet access state must display exactly one top-level screen.');
		}
		var loginScreen = documentObject && documentObject.getElementById('loginScreen');
		var walletScreen = documentObject && documentObject.getElementById('walletScreen');
		if (loginScreen) { loginScreen.classList.toggle('active', loginVisible); }
		if (walletScreen) { walletScreen.classList.toggle('active', walletVisible); }
		return Object.freeze({ loginVisible: loginVisible, walletVisible: walletVisible });
	}

	return Object.freeze({
		accessRequired: accessRequired,
		walletScreenVisible: walletScreenVisible,
		initialLoginMode: initialLoginMode,
		accessExperience: accessExperience,
		loginModeAvailability: loginModeAvailability,
		loginPresentation: loginPresentation,
		loginAvatarVisible: loginAvatarVisible,
		headerAvatarVisible: headerAvatarVisible,
		applyScreenVisibility: applyScreenVisibility
	});
}));
