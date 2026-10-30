/** Build a self-contained SDK from the shared protocol implementation. */
import * as fs from 'fs';
import * as path from 'path';
import { builtinModules } from 'module';
import * as ts from 'typescript';

const ROOT = path.resolve(__dirname, '..');
export const DIRECT_FUNDING_PACKAGE = path.join(
	ROOT,
	'packages/direct-funding'
);
const SOURCE_ROOT = path.join(ROOT, 'src') + path.sep;

interface IPackageManifest {
	dependencies: Record<string, string>;
}

/** Collect imports, re-exports, import types, and literal require calls. */
function moduleSpecifiers(source: ts.SourceFile): string[] {
	const specifiers: string[] = [];
	const visit = (node: ts.Node): void => {
		if (
			(ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
			node.moduleSpecifier &&
			ts.isStringLiteral(node.moduleSpecifier)
		) {
			specifiers.push(node.moduleSpecifier.text);
		} else if (
			ts.isImportTypeNode(node) &&
			ts.isLiteralTypeNode(node.argument) &&
			ts.isStringLiteral(node.argument.literal)
		) {
			specifiers.push(node.argument.literal.text);
		} else if (
			ts.isCallExpression(node) &&
			((ts.isIdentifier(node.expression) &&
				node.expression.text === 'require') ||
				node.expression.kind === ts.SyntaxKind.ImportKeyword) &&
			node.arguments.length === 1 &&
			ts.isStringLiteral(node.arguments[0])
		) {
			specifiers.push(node.arguments[0].text);
		}
		ts.forEachChild(node, visit);
	};
	visit(source);
	return specifiers;
}

/**
 * Emit only the entry points' dependency graph. The output directory can be
 * replaced by tests so package qualification never changes the working build.
 */
export function buildDirectFundingPackage(
	outDir = path.join(DIRECT_FUNDING_PACKAGE, 'dist')
): string[] {
	const configFile = path.join(DIRECT_FUNDING_PACKAGE, 'tsconfig.json');
	const loaded = ts.readConfigFile(configFile, ts.sys.readFile);
	if (loaded.error)
		throw new Error(
			ts.flattenDiagnosticMessageText(loaded.error.messageText, '\n')
		);
	const parsed = ts.parseJsonConfigFileContent(
		loaded.config,
		ts.sys,
		DIRECT_FUNDING_PACKAGE,
		{ outDir, declarationDir: outDir },
		configFile
	);
	const program = ts.createProgram(parsed.fileNames, parsed.options);
	const diagnostics = [...parsed.errors, ...ts.getPreEmitDiagnostics(program)];
	if (diagnostics.length) {
		throw new Error(
			ts.formatDiagnosticsWithColorAndContext(diagnostics, {
				getCanonicalFileName: (file) => file,
				getCurrentDirectory: () => ROOT,
				getNewLine: () => '\n'
			})
		);
	}

	const manifest: IPackageManifest = JSON.parse(
		fs.readFileSync(path.join(DIRECT_FUNDING_PACKAGE, 'package.json'), 'utf8')
	);
	const builtins = new Set(
		builtinModules.map((name) => name.replace(/^node:/, ''))
	);
	for (const source of program.getSourceFiles()) {
		if (!source.fileName.startsWith(SOURCE_ROOT)) continue;
		for (const specifier of moduleSpecifiers(source)) {
			if (
				specifier.startsWith('.') ||
				builtins.has(specifier.replace(/^node:/, ''))
			)
				continue;
			const name = specifier
				.split('/')
				.slice(0, specifier.startsWith('@') ? 2 : 1)
				.join('/');
			if (!manifest.dependencies[name]) {
				throw new Error(
					`SDK dependency ${name} from ${source.fileName} is absent from its manifest`
				);
			}
		}
	}

	const outputs = new Map<string, string>();
	const result = program.emit(undefined, (file, text) =>
		outputs.set(file, text)
	);
	if (result.emitSkipped)
		throw new Error('Direct-funding SDK compilation did not emit files');
	fs.rmSync(outDir, { recursive: true, force: true });
	for (const [file, text] of outputs) {
		fs.mkdirSync(path.dirname(file), { recursive: true });
		fs.writeFileSync(file, text);
	}
	return [...outputs.keys()].map((file) => path.relative(outDir, file)).sort();
}

if (require.main === module) {
	console.log(
		`Built direct-funding SDK: ${buildDirectFundingPackage().length} files`
	);
}
