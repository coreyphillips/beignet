import { expect } from 'chai';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// Runs the CLI with http.request stubbed and returns the JSON body it sent.
async function captureRequestBody(cliArgs: string[]): Promise<unknown> {
	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-psbt-cli-'));
	const capturePath = path.join(tempDir, 'request.json');
	const preloadPath = path.join(tempDir, 'capture-http.js');
	fs.writeFileSync(
		preloadPath,
		`const http = require('http');
const fs = require('fs');
const { EventEmitter } = require('events');
http.request = (_options, callback) => {
	const request = new EventEmitter();
	const chunks = [];
	request.write = (chunk) => chunks.push(Buffer.from(chunk));
	request.end = () => {
		fs.writeFileSync(process.env.BEIGNET_CAPTURE_PATH, Buffer.concat(chunks));
		const response = new EventEmitter();
		process.nextTick(() => {
			callback(response);
			response.emit('data', Buffer.from('{"ok":true,"result":{}}'));
			response.emit('end');
		});
	};
	return request;
};
`
	);

	try {
		const code = await new Promise<number | null>((resolve, reject) => {
			const child = spawn(
				process.execPath,
				[
					'-r',
					preloadPath,
					'-r',
					'ts-node/register',
					path.join('src', 'cli', 'cli.ts'),
					...cliArgs
				],
				{
					cwd: REPO_ROOT,
					env: {
						...process.env,
						HOME: tempDir,
						BEIGNET_CAPTURE_PATH: capturePath
					},
					stdio: ['ignore', 'ignore', 'pipe']
				}
			);
			child.stderr.resume();
			child.on('error', reject);
			child.on('close', resolve);
		});

		expect(code).to.equal(0);
		return JSON.parse(fs.readFileSync(capturePath, 'utf8'));
	} finally {
		fs.rmSync(tempDir, { recursive: true, force: true });
	}
}

describe('CLI PSBT commands with trailing global flags', function () {
	this.timeout(120_000);

	it('does not send an auth flag as the omitted unsigned PSBT', async () => {
		const body = await captureRequestBody([
			'psbt',
			'import-signed',
			'signed-value',
			'--api-key',
			'secret'
		]);
		expect(body).to.deep.equal({ psbtBase64: 'signed-value' });
	});

	it('does not send an auth flag or its value as a PSBT to combine', async () => {
		const body = await captureRequestBody([
			'psbt',
			'combine',
			'a',
			'b',
			'--api-key',
			'k'
		]);
		expect(body).to.deep.equal({ psbts: ['a', 'b'] });
	});
});
