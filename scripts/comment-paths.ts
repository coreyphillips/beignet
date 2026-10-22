/**
 * Fails when a code comment cites a file that is not in the repository, so a
 * "see docs/RECOVERY-PROTOCOL.md 5.1" always leads somewhere. Usage:
 *   npm run docs:paths   exit 1 and list each dangling citation
 *
 * Reads every comment in the .ts, .js, .cjs and .mjs files git knows of. Two
 * kinds of token count as citations, and each must name a file git tracks or
 * would track (not ignored), since a document in an ignored directory exists
 * on one machine only:
 * - a markdown file, at that path from the repository root or from the citing
 *   file's directory, or, for a bare name, anywhere in the tree;
 * - a file or directory (trailing slash) under a top-level directory of the
 *   repository (`src/`, `tests/`, `docs/` and so on). An ignored path passes
 *   here: that is how a local file such as docker/docker-compose.override.yml
 *   is cited.
 * URLs are not checked, so a file in another repository is cited by its URL.
 */
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

const ROOT = path.resolve(__dirname, '..');

export interface IDanglingCitation {
	file: string;
	line: number;
	cited: string;
}

/** What a citation is checked against. */
export interface IRepositoryIndex {
	/** Tracked and untracked, unignored files, from the repository root. */
	files: Set<string>;
	/** Every directory holding one of those files. */
	dirs: Set<string>;
	/** The top-level directories, which mark a path as this repository's. */
	topDirs: Set<string>;
	/** Basenames of the markdown files. */
	markdownNames: Set<string>;
	/** Whether .gitignore deliberately leaves the path out. */
	isIgnored: (file: string) => boolean;
}

/** Every comment in a source file, with the line it starts on. */
export function commentsOf(
	fileName: string,
	text: string
): { line: number; text: string }[] {
	const source = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest);
	const seen = new Map<number, number>();
	// Comments sit in the trivia before each token, so every token's full
	// start is visited, punctuation included: the comment in an empty catch
	// block belongs to its closing brace, which no node starts at.
	const visit = (node: ts.Node): void => {
		if (
			node.kind >= ts.SyntaxKind.FirstJSDocNode &&
			node.kind <= ts.SyntaxKind.LastJSDocNode
		) {
			return;
		}
		for (const range of [
			...(ts.getLeadingCommentRanges(text, node.pos) ?? []),
			...(ts.getTrailingCommentRanges(text, node.pos) ?? [])
		]) {
			seen.set(range.pos, range.end);
		}
		for (const child of node.getChildren(source)) visit(child);
	};
	visit(source);
	return [...seen]
		.sort(([a], [b]) => a - b)
		.map(([pos, end]) => ({
			line: source.getLineAndCharacterOfPosition(pos).line + 1,
			text: text.slice(pos, end)
		}));
}

const PATH_TOKEN = /(?<![\w@.\/-])(?:\.{1,2}\/)*[\w@.-]+(?:\/[\w@.-]+)*\/?/g;

/**
 * The tokens of a comment that cite a file of this repository, with their
 * offsets in the comment.
 */
export function citationsIn(
	comment: string,
	index: IRepositoryIndex
): { cited: string; offset: number }[] {
	// Blanked to the same length so offsets still point into the comment.
	const text = comment.replace(/\S+:\/\/\S*/g, (url) => ' '.repeat(url.length));
	const found: { cited: string; offset: number }[] = [];
	for (const match of text.matchAll(PATH_TOKEN)) {
		const offset = match.index ?? 0;
		const after = text[offset + match[0].length] ?? '';
		// A glob or brace pattern names files, not a file.
		if (after === '*' || after === '{') continue;
		const cited = match[0].replace(/\.+$/, '');
		const rooted =
			index.topDirs.has(cited.split('/')[0]) &&
			// "tests/custom sinks" is prose; a file has an extension.
			/\/(?:[^/]*\.\w+|)$/.test(cited);
		if (cited.endsWith('.md') || rooted) found.push({ cited, offset });
	}
	return found;
}

/** Whether a citation from `file` resolves. */
export function resolves(
	cited: string,
	file: string,
	index: IRepositoryIndex
): boolean {
	const candidates = [
		path.posix.normalize(cited),
		path.posix.normalize(path.posix.join(path.posix.dirname(file), cited))
	].map((candidate) => candidate.replace(/\/$/, ''));
	if (
		candidates.some(
			(candidate) => index.files.has(candidate) || index.dirs.has(candidate)
		)
	) {
		return true;
	}
	if (cited.endsWith('.md')) {
		return !cited.includes('/') && index.markdownNames.has(cited);
	}
	return index.isIgnored(candidates[0]);
}

function git(args: string[], root: string): string {
	return execFileSync('git', args, { cwd: root, encoding: 'utf8' });
}

export function repositoryIndex(root = ROOT): IRepositoryIndex {
	// Untracked files count so a new document passes before it is staged; CI
	// checks out only what was committed. A deletion not yet staged is gone.
	const files = new Set(
		git(['ls-files', '-z', '--cached', '--others', '--exclude-standard'], root)
			.split('\0')
			.filter((file) => file && fs.existsSync(path.join(root, file)))
	);
	const dirs = new Set<string>();
	for (const file of files) {
		for (let dir = path.posix.dirname(file); dir !== '.'; ) {
			dirs.add(dir);
			dir = path.posix.dirname(dir);
		}
	}
	return {
		files,
		dirs,
		topDirs: new Set([...dirs].filter((dir) => !dir.includes('/'))),
		markdownNames: new Set(
			[...files]
				.filter((file) => file.endsWith('.md'))
				.map((file) => path.posix.basename(file))
		),
		isIgnored: (file): boolean => {
			try {
				git(['check-ignore', '-q', file], root);
				return true;
			} catch {
				return false;
			}
		}
	};
}

export function danglingCitations(root = ROOT): IDanglingCitation[] {
	const index = repositoryIndex(root);
	const dangling: IDanglingCitation[] = [];
	for (const file of [...index.files].filter((f) => /\.[cm]?[jt]s$/.test(f))) {
		const text = fs.readFileSync(path.join(root, file), 'utf8');
		for (const comment of commentsOf(file, text)) {
			for (const { cited, offset } of citationsIn(comment.text, index)) {
				if (resolves(cited, file, index)) continue;
				const lines = comment.text.slice(0, offset).split('\n').length - 1;
				dangling.push({ file, line: comment.line + lines, cited });
			}
		}
	}
	return dangling;
}

if (require.main === module) {
	const dangling = danglingCitations();
	for (const { file, line, cited } of dangling) {
		console.error(
			`${file}:${line}: cites ${cited}, which is not in the repository`
		);
	}
	if (dangling.length) process.exit(1);
}
