import { expect } from 'chai';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

describe('CLI PSBT import with trailing global flags', function () {
	this.timeout(120_000);

	it('does not send an auth flag as the omitted unsigned PSBT', async () => {
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
						'psbt',
						'import-signed',
						'signed-value',
						'--api-key',
						'secret'
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
			expect(JSON.parse(fs.readFileSync(capturePath, 'utf8'))).to.deep.equal({
				psbtBase64: 'signed-value'
			});
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});
});
