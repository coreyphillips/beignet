/**
 * Issue #1687: the event and option tables in the READMEs are generated from
 * the typed maps and option interfaces, so they cannot drift from the code,
 * the Lightning README lists every namespace beignet/lightning exports, and
 * docs/README.md links every document in the repository.
 */
import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import { DOC_TABLES, renderTable, withTable } from '../../scripts/doc-tables';
import { getRelayedEvents } from '../../src/cli/daemon';

const ROOT = path.join(__dirname, '../..');

function read(file: string): string {
	return fs.readFileSync(path.join(ROOT, file), 'utf8');
}

function rendered(name: string): string {
	const table = DOC_TABLES.find((t) => t.name === name);
	if (!table) throw new Error(`no ${name} table`);
	return renderTable(table);
}

/** The body rows of a rendered table, split into trimmed cells. */
function rows(table: string): string[][] {
	return table
		.split('\n')
		.slice(2)
		.map((row) =>
			row
				.slice(1, -1)
				.split(/(?<!\\)\|/)
				.map((cell) => cell.trim())
		);
}

describe('Generated README tables (issue #1687)', function () {
	this.timeout(60_000);

	it('every README table matches its interface (npm run docs:tables)', () => {
		for (const table of DOC_TABLES) {
			const readme = read(table.readme);
			expect(
				withTable(readme, table, renderTable(table)),
				`${table.readme} is stale: run npm run docs:tables`
			).to.equal(readme);
		}
	});

	it('every row has a description, so a new event or option needs a doc comment', () => {
		for (const table of DOC_TABLES) {
			for (const cells of rows(renderTable(table))) {
				expect(
					cells[cells.length - 1],
					`${table.name} ${cells[0]} has no doc comment`
				).to.not.equal('');
			}
		}
	});

	it('lists all BeignetNodeEvents, and the SSE column follows getRelayedEvents', () => {
		const events = rows(rendered('BeignetNodeEvents'));
		const always = new Set<string>(getRelayedEvents(false));
		const withHtlc = new Set<string>(getRelayedEvents(true));
		expect(events.length).to.be.greaterThan(90);
		for (const [event, , sse] of events) {
			const name = event.replace(/`/g, '');
			const expected = always.has(name)
				? 'yes'
				: withHtlc.has(name)
				? '`htlcEvents`'
				: 'no';
			expect(sse, name).to.equal(expected);
		}
		const listed = new Set(events.map(([event]) => event.replace(/`/g, '')));
		for (const event of withHtlc)
			expect(listed.has(event), event).to.equal(true);
	});

	it('lists inherited and nested BeignetNodeOptions', () => {
		const options = new Set(
			rows(rendered('BeignetNodeOptions')).map(([option]) =>
				option.replace(/`/g, '')
			)
		);
		for (const option of [
			'network?',
			'dataDir?',
			'electrumTlsVerify?',
			'iroh?',
			'swaps.minSat?',
			'swaps.submarine?',
			'fforSettle.enabled',
			'autoTuneFees.ceilPpm?'
		]) {
			expect(options.has(option), option).to.equal(true);
		}
		expect(options.size).to.be.greaterThan(100);
	});

	it('the Lightning README names every beignet/lightning namespace, and only those', () => {
		const barrel = read('src/lightning/index.ts');
		const modules = [
			...barrel.matchAll(/^export \* as \w+ from '\.\/([a-z0-9-]+)';$/gm)
		].map((match) => match[1]);
		// Every export line of the barrel parsed, none skipped.
		expect(modules).to.have.length(barrel.match(/^export /gm)?.length ?? 0);
		const readme = read('src/lightning/README.md');
		const reference = readme.slice(
			readme.indexOf('## Module Reference'),
			readme.indexOf('## Testing')
		);
		const tableModules = [...reference.matchAll(/^\| `([a-z0-9-]+)` \|/gm)].map(
			(match) => match[1]
		);
		expect([...tableModules].sort()).to.deep.equal([...modules].sort());
		const tree = readme.slice(
			readme.indexOf('```\nsrc/lightning/'),
			readme.indexOf('### Data Flow')
		);
		const treeModules = [...tree.matchAll(/── ([a-z0-9-]+)\/ /g)].map(
			(match) => match[1]
		);
		expect([...treeModules].sort()).to.deep.equal([...modules].sort());
	});

	it('docs/README.md links every markdown document, and each link resolves', () => {
		const skip = new Set(['node_modules', 'dist', 'api-docs', '.git']);
		const found: string[] = [];
		const walk = (dir: string): void => {
			for (const entry of fs.readdirSync(path.join(ROOT, dir), {
				withFileTypes: true
			})) {
				const rel = path.posix.join(dir, entry.name);
				if (entry.isDirectory()) {
					if (!skip.has(entry.name)) walk(rel);
				} else if (entry.name.endsWith('.md') && rel !== 'docs/README.md') {
					found.push(rel);
				}
			}
		};
		for (const dir of ['docs', 'src', 'example', 'scripts', 'tests']) walk(dir);
		// Named rather than walked: the root also holds untracked scratch notes.
		found.push('README.md', 'SECURITY.md', 'CONTRIBUTING.md');
		const linked = [
			...read('docs/README.md').matchAll(/\]\(([^)#]+)(?:#[^)]*)?\)/g)
		].map((match) => path.posix.normalize(path.posix.join('docs', match[1])));
		for (const link of linked) {
			expect(fs.existsSync(path.join(ROOT, link)), link).to.equal(true);
		}
		const missing = found.filter((file) => !linked.includes(file));
		expect(missing, 'add these to docs/README.md').to.deep.equal([]);
	});

	it('README.md links the security policy and the contributing guide (issue #1712)', () => {
		const readme = read('README.md');
		for (const file of ['SECURITY.md', 'CONTRIBUTING.md']) {
			expect(readme, file).to.include(`](${file})`);
		}
	});
});
