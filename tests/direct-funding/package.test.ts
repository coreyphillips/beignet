import { expect } from 'chai';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as ts from 'typescript';
import {
	buildDirectFundingPackage,
	DIRECT_FUNDING_PACKAGE
} from '../../scripts/build-direct-funding';

describe('Standalone direct-funding package', function () {
	this.timeout(120_000);

	it('packs and loads runtime and types without installing the Beignet package', () => {
		const work = fs.mkdtempSync(
			path.join(os.tmpdir(), 'direct-funding-package-')
		);
		try {
			const staging = path.join(work, 'staging');
			fs.mkdirSync(staging);
			const files = buildDirectFundingPackage(path.join(staging, 'dist'));
			expect(files).to.include('direct-funding/index.js');
			expect(files).to.include('direct-funding/index.d.ts');
			expect(files).to.include('direct-funding/node.js');
			expect(
				files.filter(
					(file) =>
						file.startsWith('lightning/channel/') ||
						file.startsWith('lightning/direct-funding/receiver/') ||
						file === 'lightning/node.js' ||
						(file.startsWith('lightning/node/') &&
							!/^lightning\/node\/rate-limiter\.(?:js|d\.ts)$/.test(file)) ||
						file.startsWith('cli/')
				)
			).to.deep.equal([]);
			for (const file of ['package.json', 'LICENSE', 'README.md']) {
				const source = path.join(DIRECT_FUNDING_PACKAGE, file);
				if (fs.existsSync(source))
					fs.copyFileSync(source, path.join(staging, file));
			}
			const packed: Array<{ filename: string }> = JSON.parse(
				execFileSync('npm', ['pack', '--json', '--ignore-scripts'], {
					cwd: staging,
					env: { ...process.env, npm_config_cache: path.join(work, 'cache') },
					encoding: 'utf8'
				})
			);
			const modules = path.join(work, 'node_modules');
			const installed = path.join(modules, '@beignet/direct-funding');
			fs.mkdirSync(installed, { recursive: true });
			execFileSync('tar', [
				'-xzf',
				path.join(staging, packed[0].filename),
				'-C',
				installed,
				'--strip-components=1'
			]);

			// Only the package's declared production dependencies are visible to
			// its code. Each dependency retains access to its own dependencies.
			const manifest = JSON.parse(
				fs.readFileSync(path.join(installed, 'package.json'), 'utf8')
			);
			expect(manifest.dependencies).not.to.have.property('beignet');
			for (const dependency of Object.keys(manifest.dependencies)) {
				const target = path.join(modules, dependency);
				fs.mkdirSync(path.dirname(target), { recursive: true });
				fs.symlinkSync(
					path.resolve(
						DIRECT_FUNDING_PACKAGE,
						'../../node_modules',
						dependency
					),
					target,
					'dir'
				);
			}
			const loaded = JSON.parse(
				execFileSync(
					process.execPath,
					[
						'-e',
						`
				const sdk = require('@beignet/direct-funding');
				const node = require('@beignet/direct-funding/node');
				console.log(JSON.stringify({
					parameter: sdk.DF_BIP21_PARAM,
					signer: typeof sdk.createPsbtCoinSigner,
					wallet: typeof sdk.BitcoinCoreWalletAdapter,
					peer: typeof node.NodePeerMessaging,
					nodeExports: Object.keys(node).length
				}));
			`
					],
					{
						cwd: work,
						env: { ...process.env, NODE_PATH: '' },
						encoding: 'utf8'
					}
				)
			);
			expect(loaded.parameter).to.equal('bgnq');
			expect(loaded.signer).to.equal('function');
			expect(loaded.wallet).to.equal('function');
			expect(loaded.peer).to.equal('function');
			expect(loaded.nodeExports).to.be.greaterThan(0);

			const consumer = path.join(work, 'consumer.ts');
			fs.writeFileSync(
				consumer,
				[
					"import * as sdk from '@beignet/direct-funding';",
					"import * as node from '@beignet/direct-funding/node';",
					'export const parameter: string = sdk.DF_BIP21_PARAM;',
					'export const signer = sdk.createPsbtCoinSigner;',
					'export const wallet = sdk.BitcoinCoreWalletAdapter;',
					'export const nodeExports = node;'
				].join('\n')
			);
			const program = ts.createProgram([consumer], {
				target: ts.ScriptTarget.ES2020,
				lib: ['lib.es2020.d.ts'],
				module: ts.ModuleKind.Node16,
				moduleResolution: ts.ModuleResolutionKind.Node16,
				strict: true,
				noEmit: true,
				types: ['node'],
				typeRoots: [path.join(modules, '@types')]
			});
			const errors = ts
				.getPreEmitDiagnostics(program)
				.map((diagnostic) =>
					ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n')
				);
			expect(errors).to.deep.equal([]);
		} finally {
			fs.rmSync(work, { recursive: true, force: true });
		}
	});
});
