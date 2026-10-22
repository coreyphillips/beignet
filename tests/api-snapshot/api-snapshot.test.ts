/**
 * Issue #1713: the exported API of every entry point is recorded in this
 * directory, so a change to the public surface arrives as a reviewed diff of
 * these files (npm run api:snapshot regenerates them), and deprecated.txt is
 * the removal list for the next major release.
 */
import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';

import {
	DEPRECATED_FILE,
	SNAPSHOT_DIR,
	apiLines,
	declarationProgram,
	renderSnapshots
} from '../../scripts/api-snapshot';
import type { IApiLine } from '../../scripts/api-snapshot';

/** The lines of `a` that `b` lacks. */
function linesMissing(a: string, b: string): string[] {
	const present = new Set(b.split('\n'));
	return a.split('\n').filter((line) => !present.has(line));
}

function expectCommitted(name: string, expected: string): void {
	const file = path.join(SNAPSHOT_DIR, name);
	const committed = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
	if (committed === expected) return;
	const show = (sign: string, lines: string[]): string[] => [
		...lines.slice(0, 20).map((line) => `${sign} ${line}`),
		...(lines.length > 20 ? [`${sign} ... ${lines.length - 20} more`] : [])
	];
	expect.fail(
		[
			`tests/api-snapshot/${name} is stale: run npm run api:snapshot and review the diff`,
			...show('-', linesMissing(committed, expected)),
			...show('+', linesMissing(expected, committed))
		].join('\n')
	);
}

describe('Exported API snapshot (issue #1713)', function () {
	this.timeout(120_000);

	let snapshots: Map<string, string>;
	before(() => {
		snapshots = renderSnapshots();
	});

	it('every entry point matches its committed snapshot', () => {
		for (const [name, text] of snapshots) {
			if (name !== DEPRECATED_FILE) expectCommitted(name, text);
		}
	});

	it('deprecated.txt lists every declaration tagged @deprecated', () => {
		expectCommitted(DEPRECATED_FILE, snapshots.get(DEPRECATED_FILE)!);
	});

	it('no snapshot is left for an entry point package.json no longer exports', () => {
		const orphans = fs
			.readdirSync(SNAPSHOT_DIR)
			.filter((name) => name.endsWith('.txt') && !snapshots.has(name));
		expect(orphans).to.deep.equal([]);
	});
});

describe('API snapshot lines (issue #1713)', () => {
	// Not on disk, so every declaration comes from the fixture. A fixture
	// that declares something it does not export ends in `export {}`, as tsc
	// emits it, or the declaration is exported implicitly.
	const DIR = path.resolve('/api-snapshot-fixture');

	function lines(files: Record<string, string>): IApiLine[] {
		const entry = path.join(DIR, 'index.d.ts');
		const program = declarationProgram(
			new Map(
				Object.entries(files).map(([name, text]) => [
					path.join(DIR, name),
					text
				])
			),
			DIR,
			[entry],
			{ types: [] }
		);
		return apiLines(program, [{ specifier: 'fixture', types: entry }])[0];
	}

	const texts = (files: Record<string, string>): string[] =>
		lines(files).map((line) => line.text);

	it('gives each export, public member and unexported declaration in use a line, keeping overload order', () => {
		expect(
			texts({
				'index.d.ts': [
					'declare class Base {',
					'    on(event: string): void;',
					'}',
					'export declare class Store<T> extends Base {',
					'    private secret;',
					'    #private;',
					'    protected guard(): void;',
					'    static open(path: string): Store<string>;',
					'    readonly size: number;',
					'    static readonly VERSION = 19;',
					'    constructor(path: string);',
					'    get(key: string, fallback: T): T;',
					'    get(key: string): T | undefined;',
					'}',
					'export declare class Pool {',
					'    private constructor();',
					'}',
					"export declare function open(path: string, mode?: 'r' | 'w'): Promise<void>;",
					'declare const brand: unique symbol;',
					'export type Verified = string[] & { readonly [brand]: true };',
					'export {};'
				].join('\n')
			})
		).to.deep.equal([
			'unexported class Base',
			'method Base.on(event: string): void',
			'class Pool',
			'private constructor Pool()',
			'class Store<T> extends Base',
			'constructor Store(path: string)',
			'static readonly property Store.VERSION = 19',
			'method Store.get(key: string, fallback: T): T',
			'method Store.get(key: string): T | undefined',
			'protected method Store.guard(): void',
			'static method Store.open(path: string): Store<string>',
			'readonly property Store.size: number',
			'type Verified = string[] & { readonly [brand]: true; }',
			'unexported const brand: unique symbol',
			"function open(path: string, mode?: 'r' | 'w'): Promise<void>"
		]);
	});

	it('prints a reference as its export name, or with its file when an unexported declaration shares that name', () => {
		expect(
			texts({
				'index.d.ts': [
					"export * as invoice from './invoice';",
					"export * as offer from './offer';",
					"export * from './entry';",
					"export * from './store';"
				].join('\n'),
				'invoice.d.ts': 'export interface Fallback {\n    hash: Uint8Array;\n}',
				'offer.d.ts': [
					'export interface Fallback {',
					'    program: Uint8Array;',
					'}',
					'export interface Invoice {',
					'    mine: Fallback;',
					'    theirs: import("./invoice").Fallback;',
					'}'
				].join('\n'),
				'entry.d.ts': 'export interface Entry {\n    id: string;\n}',
				'store.d.ts': [
					'interface Entry {',
					'    key: string;',
					'}',
					'export declare function list(): Entry[];',
					'export {};'
				].join('\n')
			})
		).to.deep.equal([
			'unexported interface ./store#Entry',
			'property ./store#Entry.key: string',
			'interface Entry',
			'property Entry.id: string',
			'namespace invoice',
			'interface invoice.Fallback',
			'property invoice.Fallback.hash: Uint8Array',
			'function list(): ./store#Entry[]',
			'namespace offer',
			'interface offer.Fallback',
			'property offer.Fallback.program: Uint8Array',
			'interface offer.Invoice',
			'property offer.Invoice.mine: offer.Fallback',
			'property offer.Invoice.theirs: invoice.Fallback'
		]);
	});

	it('names a dependency type by its package and declaration, whatever the import calls it', () => {
		expect(
			texts({
				'index.d.ts': [
					"import type { Transaction as Psbt } from 'pkg';",
					'export interface Input {',
					'    psbt: Psbt;',
					'    other: import("pkg").Psbt;',
					'}'
				].join('\n'),
				'node_modules/pkg/index.d.ts':
					"export * from './src/tx';\nexport declare class Psbt {\n}",
				'node_modules/pkg/src/tx.d.ts': 'export declare class Transaction {\n}'
			})
		).to.deep.equal([
			'interface Input',
			'property Input.other: pkg#Psbt',
			'property Input.psbt: pkg#Transaction'
		]);
	});

	it('qualifies namespace members, keeps literal spacing and drops module paths from import() types', () => {
		expect(
			texts({
				'index.d.ts':
					"export * as wire from './wire';\nexport * from './util';",
				'util.d.ts': 'export interface Message {\n    type: number;\n}',
				'wire.d.ts': [
					'export declare const SEP = "a  b";',
					'export declare const CODE = \'import("./util").Message\';',
					'export declare const VERSION = 2;',
					'export declare function encode(m: import("./util").Message): Uint8Array;'
				].join('\n')
			})
		).to.deep.equal([
			'interface Message',
			'property Message.type: number',
			'namespace wire',
			`const wire.CODE = 'import("./util").Message'`,
			'const wire.SEP = "a  b"',
			'const wire.VERSION = 2',
			'function wire.encode(m: Message): Uint8Array'
		]);
	});

	it('flags @deprecated declarations, overloads and aliases one by one, and marks type-only exports', () => {
		const result = lines({
			'util.d.ts': 'export declare function start(): void;',
			'index.d.ts': [
				"export { /** @deprecated Use start. */ start as begin, start } from './util';",
				'declare class Engine {',
				'    start(): void;',
				'}',
				'export type { Engine };',
				'declare namespace tools {',
				'    function go(): void;',
				'}',
				'export type { tools };',
				'export type Server = {',
				'    /** @deprecated Use url. */',
				'    host: string;',
				'    url: string;',
				'};',
				'/** @deprecated Pass an options object. */',
				'export declare function run(fast: boolean): void;',
				'export declare function run(opts?: { fast?: boolean }): void;',
				'export interface Options {',
				'    /** @deprecated Use timeoutMs. */',
				'    timeout?: number;',
				'    timeoutMs?: number;',
				'}',
				'export {};'
			].join('\n')
		});
		expect(result.map((line) => line.text)).to.include.members([
			'type-only class Engine',
			'method Engine.start(): void',
			'type-only namespace tools'
		]);
		expect(
			result.filter((line) => line.deprecated).map((line) => line.text)
		).to.deep.equal([
			'property Options.timeout?: number',
			'property Server.host: string',
			'function begin(): void',
			'function run(fast: boolean): void'
		]);
	});
});
