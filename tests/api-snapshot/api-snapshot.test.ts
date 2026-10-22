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
		return apiLines(program, [entry])[0];
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
					"export declare function open(path: string, mode?: 'r' | 'w'): Promise<void>;",
					'export {};'
				].join('\n')
			})
		).to.deep.equal([
			'unexported class Base',
			'method Base.on(event: string): void',
			'class Store<T> extends Base',
			'constructor Store(path: string)',
			'static readonly property Store.VERSION = 19',
			'method Store.get(key: string, fallback: T): T',
			'method Store.get(key: string): T | undefined',
			'protected method Store.guard(): void',
			'static method Store.open(path: string): Store<string>',
			'readonly property Store.size: number',
			"function open(path: string, mode?: 'r' | 'w'): Promise<void>"
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
					'export declare const VERSION = 2;',
					'export declare function encode(m: import("./util").Message): Uint8Array;'
				].join('\n')
			})
		).to.deep.equal([
			'interface Message',
			'property Message.type: number',
			'namespace wire',
			'const wire.SEP = "a  b"',
			'const wire.VERSION = 2',
			'function wire.encode(m: Message): Uint8Array'
		]);
	});

	it('flags @deprecated declarations, overloads one by one, and marks type-only exports', () => {
		const result = lines({
			'index.d.ts': [
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
			'function run(fast: boolean): void'
		]);
	});
});
