/**
 * Issue #1695: lint fails on a cycle among the modules src/ loads at runtime,
 * which type-only imports do not join. Pure graph checks, offline.
 */

import { expect } from 'chai';
import * as ts from 'typescript';

import { findCycles, valueImportSpecifiers } from '../scripts/import-cycles';

const specifiers = (lines: string[]): string[] =>
	valueImportSpecifiers(
		ts.createSourceFile('x.ts', lines.join('\n'), ts.ScriptTarget.Latest)
	);

describe('Import cycle check (#1695)', () => {
	it('counts value imports and re-exports, not type-only or lazy ones', () => {
		expect(
			specifiers([
				"import { a } from './a';",
				"import type { B } from './b';",
				"import './c';",
				"export * from './d';",
				"export { e } from './e';",
				"export type { F } from './f';",
				"import g = require('./g');",
				"const h = (): unknown => require('./h');",
				"const i = (): unknown => import('./i');"
			])
		).to.deep.equal(['./a', './c', './d', './e', './g']);
	});

	it('reports each cycle, including a self-import, and nothing acyclic', () => {
		const graph = new Map([
			['a', ['b']],
			['b', ['c']],
			['c', ['a', 'd']],
			['d', []],
			['e', ['e']],
			['f', ['d', 'a']]
		]);
		expect(
			findCycles(graph).map((component) => [...component].sort())
		).to.have.deep.members([['a', 'b', 'c'], ['e']]);
	});

	it('reports nothing for a chain', () => {
		const graph = new Map([
			['a', ['b']],
			['b', ['c']],
			['c', []]
		]);
		expect(findCycles(graph)).to.deep.equal([]);
	});
});
