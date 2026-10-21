/**
 * The first release on each supported Node.js line that carries the fixes
 * from the October 21, 2026 Node.js security release (issue #1773). The lines
 * missing here (18, 20, 21, 23, 25) are end of life and have no patched
 * release at all, so any version on them counts as unpatched.
 */
export const PATCHED_NODE_RELEASES: ReadonlyArray<string> = [
	'22.23.4',
	'24.22.1',
	'26.12.1'
];

const parseVersion = (version: string): number[] | undefined => {
	const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version.trim());
	return match ? match.slice(1, 4).map(Number) : undefined;
};

/**
 * Whether a Node.js version (`process.versions.node`, with or without a
 * leading `v`) has the October 21, 2026 security fixes. A major line newer
 * than the newest patched one passes; a version that does not parse fails.
 *
 * @param {string} version
 * @returns {boolean}
 */
export const isPatchedNodeVersion = (version: string): boolean => {
	const parsed = parseVersion(version);
	if (!parsed) return false;
	const [major, minor, patch] = parsed;
	const floors = PATCHED_NODE_RELEASES.map((r) => parseVersion(r) as number[]);
	const newestMajor = Math.max(...floors.map(([m]) => m));
	if (major > newestMajor) return true;
	const floor = floors.find(([m]) => m === major);
	if (!floor) return false;
	if (minor !== floor[1]) return minor > floor[1];
	return patch >= floor[2];
};

/**
 * The startup warning for a Node.js version without the October 21, 2026
 * security fixes, or undefined when the version has them. The daemon logs it
 * and keeps running.
 *
 * @param {string} version
 * @returns {string | undefined}
 */
export const unpatchedNodeWarning = (version: string): string | undefined => {
	if (isPatchedNodeVersion(version)) return undefined;
	const shown = version.startsWith('v') ? version : `v${version}`;
	return (
		`Node.js ${shown} does not have the fixes from the October 21, 2026 ` +
		'Node.js security release (TLS host name checks, Brotli decoding, ' +
		'dns.resolve); run Node.js ' +
		`${PATCHED_NODE_RELEASES.join(', ')} or later on the same line`
	);
};
