/**
 * typedoc plugin that lets typedoc run on minimatch 11, the first line with
 * the GHSA-g3hv-75wg-m249 fix. minimatch 11 made Minimatch#matchOne private,
 * and typedoc (through 0.28.20) still calls it, once: its glob() keeps a
 * directory when `mini.set.some((row) => mini.matchOne(dir, row, true))`.
 * That asks whether any row can match, so the public match() answers it. The
 * comparison with negate undoes the pattern's `!`, which matchOne ignored.
 * Delete this file, and its entries in typedoc.json and docs:markdown, once
 * typedoc stops calling matchOne.
 */
'use strict';

/* eslint-disable @typescript-eslint/no-var-requires */
const path = require('path');

const { Minimatch } = require(require.resolve('minimatch', {
	paths: [path.dirname(require.resolve('typedoc'))]
}));

exports.load = function load() {
	if (typeof Minimatch.prototype.matchOne === 'function') return;
	Minimatch.prototype.matchOne = function matchOne(file, _row, partial) {
		return this.match(file.join('/'), partial) !== this.negate;
	};
};
