'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const css = fs.readFileSync(path.join(__dirname, '..', 'sweetwallet.css'), 'utf8');

test('PIN entry matches KeyLink square-cell proportions and typing treatment', () => {
	assert.match(css, /\.pin-entry\s*\{[\s\S]*?position:\s*relative;[\s\S]*?grid-template-columns:\s*repeat\(6, minmax\(0, 1fr\)\);[\s\S]*?gap:\s*7px;[\s\S]*?width:\s*min\(100%, 360px\);/);
	assert.match(css, /\.pin-entry\[data-length="4"\]\s*\{[\s\S]*?gap:\s*9px;[\s\S]*?width:\s*min\(100%, 286px\);/);
	assert.match(css, /\.pin-box\s*\{[\s\S]*?aspect-ratio:\s*1;[\s\S]*?border-radius:\s*16px;/);
	assert.match(css, /\.pin-box\.filled::after\s*\{[\s\S]*?width:\s*9px;[\s\S]*?height:\s*9px;[\s\S]*?box-shadow:\s*0 0 0 5px rgba\(223, 249, 231, 0\.07\);/);
	assert.match(css, /\.pin-entry:focus-within \.pin-box,[\s\S]*?border-color:\s*#39d77f;/);
});
