/**
 * Node 22.18+ and 24 strip TypeScript types natively, so mocha's import() of a
 * test file no longer fails over to require() and ts-node for every file: one
 * that imports only Node built-ins loads as native ESM instead, where
 * __dirname, type-only named imports and constructor parameter properties
 * break (issue #1773). Turning native stripping off sends every test file
 * through ts-node, as on Node 20.
 *
 * Node 24 and 26 call the switch --no-strip-types and Node 22 only knows the
 * experimental name, so take whichever this Node accepts. Node 20 has neither
 * and needs none.
 */
const flag = ['--no-strip-types', '--no-experimental-strip-types'].find(
	(name) => process.allowedNodeEnvironmentFlags.has(name)
);

module.exports = flag ? { 'node-option': [flag.slice(2)] } : {};
