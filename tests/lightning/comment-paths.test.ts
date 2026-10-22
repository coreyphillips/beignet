/**
 * Issue #1688: a comment that cites a document or source file names one that
 * is in the repository, so a spec citation on a fund-critical invariant can
 * be followed. CI runs the same check as `npm run docs:paths`.
 */
import { expect } from 'chai';
import {
	citationsIn,
	commentsOf,
	danglingCitations,
	IRepositoryIndex,
	resolves
} from '../../scripts/comment-paths';

const INDEX: IRepositoryIndex = {
	files: new Set([
		'docs/specs/ffor-offline-receive.md',
		'docs/RECOVERY-PROTOCOL.md',
		'src/lightning/channel/channel.ts',
		'tests/lightning/conformance/helpers.ts',
		'tests/lightning/conformance/vectors/SOURCE.md'
	]),
	dirs: new Set([
		'docs',
		'docs/specs',
		'src',
		'src/lightning',
		'src/lightning/channel',
		'tests',
		'tests/lightning',
		'tests/lightning/conformance',
		'tests/lightning/conformance/vectors'
	]),
	topDirs: new Set(['docs', 'src', 'tests', 'docker']),
	markdownNames: new Set([
		'ffor-offline-receive.md',
		'RECOVERY-PROTOCOL.md',
		'SOURCE.md'
	]),
	isIgnored: (file) =>
		['docker/docker-compose.override.yml', 'docker/NOTES.md'].includes(file)
};

const FROM = 'src/lightning/channel/channel.ts';

function dangling(comment: string, from = FROM): string[] {
	return citationsIn(comment, INDEX)
		.map(({ cited }) => cited)
		.filter((cited) => !resolves(cited, from, INDEX));
}

describe('Comment citations resolve (issue #1688)', function () {
	this.timeout(60_000);

	it('no comment in the repository cites a file that is not in it (npm run docs:paths)', () => {
		expect(danglingCitations()).to.deep.equal([]);
	});

	it('a spec cited at a path that does not exist is dangling, even when a file of that name exists elsewhere', () => {
		expect(
			dangling('// see specs/ffor-offline-receive.md section 7.5.5')
		).to.deep.equal(['specs/ffor-offline-receive.md']);
		expect(
			dangling('// (docs/specs/ffor-offline-receive.md section 7.5.5)')
		).to.deep.equal([]);
		expect(
			dangling('// docs/specs/CONCURRENT-RECEIVE.md section 4')
		).to.deep.equal(['docs/specs/CONCURRENT-RECEIVE.md']);
	});

	it('a bare document name resolves anywhere in the tree, and an absent one is dangling', () => {
		expect(
			dangling('// RECOVERY-PROTOCOL.md 5.1, see SOURCE.md')
		).to.deep.equal([]);
		expect(dangling('// CONCURRENT-RECEIVE.md section 3.1')).to.deep.equal([
			'CONCURRENT-RECEIVE.md'
		]);
	});

	it('a path relative to the citing file resolves', () => {
		expect(
			dangling('// vectors/SOURCE.md', 'tests/lightning/conformance/helpers.ts')
		).to.deep.equal([]);
	});

	it('a repository path resolves to a file or a directory, and reports the missing one', () => {
		expect(
			dangling('// src/lightning/channel/channel.ts:5707 and src/lightning/')
		).to.deep.equal([]);
		expect(
			dangling('// tests/cli/agent-production-hardening.ts:')
		).to.deep.equal(['tests/cli/agent-production-hardening.ts']);
	});

	it('an ignored local file may be cited, an ignored document may not', () => {
		expect(
			dangling('// whatever docker/docker-compose.override.yml publishes')
		).to.deep.equal([]);
		expect(dangling('// docker/NOTES.md')).to.deep.equal(['docker/NOTES.md']);
	});

	it('URLs, globs, prose and paths outside a top-level directory are not citations', () => {
		for (const comment of [
			'// https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md',
			'// tests/lightning/recovery-phase7-*.test.ts',
			'// Injectable for tests/custom sinks.',
			'// BOLT 4 vector bolt04/onion-test.json, rn-electrum-client/helpers/index.js',
			'// ~/.beignet/config.json and <dataDir>/requests.json'
		]) {
			expect(citationsIn(comment, INDEX), comment).to.deep.equal([]);
		}
	});

	it('reads comments only, including one in an empty block, and not strings', () => {
		const source = [
			"const a = 'docs/MISSING-1.md';",
			'const b = `${a} // docs/MISSING-2.md`;',
			'const c = /\\/\\/ docs\\/MISSING-3.md/;',
			'try {',
			'\tvoid c;',
			'} catch {',
			'\t// docs/specs/ffor-offline-receive.md',
			'}',
			'/**',
			' * docs/RECOVERY-PROTOCOL.md',
			' */',
			'export const d = b; // trailing SOURCE.md'
		].join('\n');
		expect(commentsOf('x.ts', source)).to.deep.equal([
			{ line: 7, text: '// docs/specs/ffor-offline-receive.md' },
			{ line: 9, text: '/**\n * docs/RECOVERY-PROTOCOL.md\n */' },
			{ line: 12, text: '// trailing SOURCE.md' }
		]);
	});
});
