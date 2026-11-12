/**
 * `beignet porch-relay`: the command's flags (porchRelayCommand) and the real
 * binary, started, used as a relay and signalled. The relay's own behaviour
 * has its tests in porch-relay.test.ts.
 */

import { expect } from 'chai';
import { ChildProcess, spawn } from 'child_process';
import net from 'net';
import {
	DEFAULT_PORCH_RELAY_LIMITS,
	DEFAULT_PORCH_RELAY_PORT,
	porchRelayCommand
} from '../../src/cli/porch-relay';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IPorchChallenge,
	createPorchRegister,
	decodePorchControl,
	encodePorchControl,
	parsePorchRelayUrl,
	porchRouteId
} from '../../src/lightning/transport/porch';
import { NodeWebSocket } from '../../src/lightning/transport/websocket-node-client';
import { assertDistCliFresh, DIST_CLI } from './helpers/dist-cli';

const NO_PROXY_WARNING = /^no --trusted-proxy: /;

describe('porch-relay command flags', function () {
	const files: Record<string, string> = {
		'cert.pem': 'CERT',
		'key.pem': 'KEY',
		token: 'open sesame\n',
		blank: ' \n'
	};
	const read = (path: string): Buffer => {
		if (!(path in files)) throw new Error(`ENOENT: ${path}`);
		return Buffer.from(files[path]);
	};
	const command = (
		args: string[],
		env: Record<string, string | undefined> = {}
	): ReturnType<typeof porchRelayCommand> => porchRelayCommand(args, env, read);

	it('needs only the public URL', function () {
		const c = command(['--url', 'wss://Relay.Example:443/']);
		expect(c.warnings).to.have.length(1);
		expect(c.warnings[0]).to.match(NO_PROXY_WARNING);
		expect({ ...c, warnings: [] }).to.deep.equal({
			port: DEFAULT_PORCH_RELAY_PORT,
			host: '127.0.0.1',
			urls: ['wss://relay.example'],
			warnings: [],
			options: { authorities: ['relay.example'] }
		});
		expect(DEFAULT_PORCH_RELAY_PORT).to.equal(2114);
	});

	it('reads every flag', function () {
		const c = command([
			'--url',
			'wss://relay.example:8443',
			'--url',
			'ws://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion',
			'--port',
			'8443',
			'--host',
			'0.0.0.0',
			'--tls-cert',
			'cert.pem',
			'--tls-key',
			'key.pem',
			'--token-file',
			'token',
			'--trusted-proxy',
			'127.0.0.1',
			'--trusted-proxy',
			'::1',
			'--limit',
			'connections=2048',
			'--limit',
			'pairWaitMs=500',
			'--stats',
			'60'
		]);
		expect(c).to.deep.equal({
			port: 8443,
			host: '0.0.0.0',
			urls: [
				'wss://relay.example:8443',
				'ws://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion'
			],
			statsSeconds: 60,
			// Serving TLS, and one of its names is ws://.
			warnings: [c.warnings[0]],
			options: {
				authorities: [
					'relay.example:8443',
					'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion'
				],
				token: 'open sesame',
				tls: { cert: Buffer.from('CERT'), key: Buffer.from('KEY') },
				trustedProxies: ['127.0.0.1', '::1'],
				limits: { connections: 2048, pairWaitMs: 500 }
			}
		});
		expect(c.warnings[0]).to.match(/^serving TLS, but a --url is ws:\/\//);
	});

	it('names the relay exactly as a node that dials the URL will', function () {
		for (const url of [
			'wss://relay.example',
			'wss://RELAY.example:443',
			'wss://relay.example:8443',
			'ws://relay.example:80',
			'ws://relay.example:8080',
			'wss://[2001:db8::1]:8443'
		]) {
			const c = command(['--url', url]);
			expect(c.options.authorities, url).to.deep.equal([
				parsePorchRelayUrl(url).authority
			]);
			expect(c.urls, url).to.deep.equal([parsePorchRelayUrl(url).origin]);
		}
		// One name given twice is one name.
		expect(
			command([
				'--url',
				'wss://relay.example',
				'--url',
				'wss://relay.example:443'
			]).options.authorities
		).to.deep.equal(['relay.example']);
	});

	it('takes the token from the file, else from the environment', function () {
		const url = ['--url', 'wss://relay.example'];
		expect(command(url).options).to.not.have.property('token');
		expect(
			command(url, { BEIGNET_PORCH_RELAY_TOKEN: 'from env' }).options.token
		).to.equal('from env');
		expect(
			command([...url, '--token-file', 'token'], {
				BEIGNET_PORCH_RELAY_TOKEN: 'from env'
			}).options.token
		).to.equal('open sesame');
	});

	it('warns about what an operator would otherwise find out later', function () {
		const warnings = (args: string[]): string[] => command(args).warnings;
		expect(warnings(['--url', 'wss://relay.example'])[0]).to.match(
			NO_PROXY_WARNING
		);
		expect(
			warnings(['--url', 'wss://relay.example', '--trusted-proxy', '10.0.0.1'])
		).to.deep.equal([]);
		// Serving TLS itself: there is no proxy to speak of.
		expect(
			warnings([
				'--url',
				'wss://relay.example',
				'--tls-cert',
				'cert.pem',
				'--tls-key',
				'key.pem'
			])
		).to.deep.equal([]);
		const plain = warnings([
			'--url',
			'ws://relay.example',
			'--trusted-proxy',
			'10.0.0.1'
		]);
		expect(plain).to.have.length(1);
		expect(plain[0]).to.match(
			/^ws:\/\/relay\.example is not encrypted to the relay/
		);
		// An onion service is encrypted by Tor.
		expect(
			warnings([
				'--url',
				'ws://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion',
				'--trusted-proxy',
				'10.0.0.1'
			])
		).to.deep.equal([]);
	});

	const refused: Array<[string, string[], RegExp, Record<string, string>?]> = [
		['no URL', [], /needs --url/],
		[
			'a URL with a path',
			['--url', 'wss://relay.example/v1'],
			/scheme, host and port/
		],
		[
			'a URL that is not a WebSocket one',
			['--url', 'https://relay.example'],
			/ws:\/\/ or wss:\/\//
		],
		[
			'an unknown flag',
			['--url', 'wss://r.example', '--verbose', '1'],
			/Unknown porch-relay option: --verbose/
		],
		[
			'a stray word',
			['wss://r.example'],
			/Unknown porch-relay option: wss:\/\/r\.example/
		],
		[
			'a flag with no value',
			['--url', 'wss://r.example', '--port'],
			/--port needs a value/
		],
		[
			'a flag followed by a flag',
			['--url', '--port', '1'],
			/--url needs a value/
		],
		[
			'a port out of range',
			['--url', 'wss://r.example', '--port', '65536'],
			/--port must be a whole number from 0 to 65535/
		],
		[
			'a port that is not a number',
			['--url', 'wss://r.example', '--port', '8e3'],
			/--port must be a whole number/
		],
		[
			'a port given twice',
			['--url', 'wss://r.example', '--port', '1', '--port', '2'],
			/--port was given more than once/
		],
		[
			'a certificate without its key',
			['--url', 'wss://r.example', '--tls-cert', 'cert.pem'],
			/go together/
		],
		[
			'a key without its certificate',
			['--url', 'wss://r.example', '--tls-key', 'key.pem'],
			/go together/
		],
		[
			'a certificate file that is not there',
			[
				'--url',
				'wss://r.example',
				'--tls-cert',
				'nope',
				'--tls-key',
				'key.pem'
			],
			/ENOENT: nope/
		],
		[
			'a blank token file',
			['--url', 'wss://r.example', '--token-file', 'blank'],
			/token is empty/
		],
		[
			'an empty token in the environment',
			['--url', 'wss://r.example'],
			/token is empty/,
			{ BEIGNET_PORCH_RELAY_TOKEN: '' }
		],
		[
			'a token over the protocol limit',
			['--url', 'wss://r.example'],
			/longer than 256 bytes/,
			{ BEIGNET_PORCH_RELAY_TOKEN: 'x'.repeat(257) }
		],
		[
			'a proxy named by host',
			['--url', 'wss://r.example', '--trusted-proxy', 'localhost'],
			/takes an IP address, not localhost/
		],
		[
			'a limit the relay does not have',
			['--url', 'wss://r.example', '--limit', 'conections=5'],
			/one of: standbysPerHost, /
		],
		[
			'a limit without a value',
			['--url', 'wss://r.example', '--limit', 'connections'],
			/takes <name>=<n>/
		],
		[
			'a limit of zero',
			['--url', 'wss://r.example', '--limit', 'connections=0'],
			/--limit connections must be a whole number from 1/
		],
		[
			'a limit that is not a number',
			['--url', 'wss://r.example', '--limit', 'connections=many'],
			/--limit connections must be a whole number/
		],
		[
			'a limit given twice',
			['--url', 'wss://r.example', '--limit', 'hosts=1', '--limit', 'hosts=2'],
			/--limit hosts was given twice/
		],
		[
			'a stats interval of zero',
			['--url', 'wss://r.example', '--stats', '0'],
			/--stats must be a whole number from 1/
		]
	];
	for (const [name, args, message, env] of refused) {
		it(`refuses ${name}`, function () {
			expect(() => command(args, env)).to.throw(message);
		});
	}

	it('accepts every limit the relay has, by name', function () {
		const names = Object.keys(DEFAULT_PORCH_RELAY_LIMITS);
		const c = command([
			'--url',
			'wss://relay.example',
			...names.flatMap((name) => ['--limit', `${name}=77`])
		]);
		expect(c.options.limits).to.deep.equal(
			Object.fromEntries(names.map((name) => [name, 77]))
		);
	});
});

describe('beignet porch-relay', function () {
	this.timeout(120_000);

	before(assertDistCliFresh);

	const children: ChildProcess[] = [];
	afterEach(function () {
		for (const child of children.splice(0)) child.kill('SIGKILL');
	});

	function run(args: string[]): {
		child: ChildProcess;
		line: Promise<Record<string, unknown>>;
		exit: Promise<number | null>;
		stderr: () => string;
	} {
		const child = spawn(process.execPath, [DIST_CLI, 'porch-relay', ...args], {
			stdio: ['ignore', 'pipe', 'pipe'],
			env: { ...process.env, BEIGNET_PORCH_RELAY_TOKEN: undefined }
		});
		children.push(child);
		let stdout = '';
		let stderr = '';
		child.stderr?.on('data', (chunk: Buffer) => (stderr += chunk));
		const line = new Promise<Record<string, unknown>>((resolve, reject) => {
			child.stdout?.on('data', (chunk: Buffer) => {
				stdout += chunk;
				const end = stdout.indexOf('\n');
				if (end >= 0) resolve(JSON.parse(stdout.slice(0, end)));
			});
			child.once('close', () =>
				reject(new Error(`exited without a line. stderr: ${stderr}`))
			);
		});
		const exit = new Promise<number | null>((resolve) =>
			child.once('close', (code) => resolve(code))
		);
		return { child, line, exit, stderr: () => stderr };
	}

	it('starts, relays a connection and stops on a signal', async function () {
		const relay = run([
			'--url',
			'ws://relay.test',
			'--port',
			'0',
			'--limit',
			'pairWaitMs=500'
		]);
		const started = await relay.line;
		expect(started.ok).to.equal(true);
		const result = started.result as Record<string, unknown>;
		expect(result).to.include({
			message: 'Porch relay started',
			host: '127.0.0.1',
			tls: false,
			private: false,
			pid: relay.child.pid
		});
		expect(result.urls).to.deep.equal(['ws://relay.test']);
		const port = result.port as number;
		expect(port).to.be.greaterThan(0);
		// Its two warnings, and nothing else, on stderr.
		expect(relay.stderr()).to.match(/warning: no --trusted-proxy/);
		expect(relay.stderr()).to.match(
			/warning: ws:\/\/relay\.test is not encrypted/
		);

		const dial = (path: string): NodeWebSocket =>
			new NodeWebSocket(`ws://relay.test${path}`, {
				connect: (): net.Socket => net.createConnection(port, '127.0.0.1')
			});
		const secret = Buffer.alloc(32, 9);
		const tag = Buffer.alloc(16, 3);
		const routeId = porchRouteId(getPublicKey(secret), tag);

		const host = dial('/v1/host');
		const hostTexts: string[] = [];
		const hostBytes: Buffer[] = [];
		const paired = new Promise<void>((resolve, reject) => {
			host.onerror = (e): void => reject(e as Error);
			host.onmessage = (ev): void => {
				if (typeof ev.data !== 'string') {
					hostBytes.push(Buffer.from(ev.data as ArrayBuffer));
					host.send(Buffer.from('pong from the host'));
					return;
				}
				hostTexts.push(ev.data);
				const message = decodePorchControl(ev.data);
				if (message?.t === 'challenge') {
					const challenge = message as IPorchChallenge;
					host.send(
						encodePorchControl(
							createPorchRegister({
								hostSecret: secret,
								nonce: Buffer.from(challenge.nonce, 'hex'),
								authority: challenge.authority,
								tags: [tag]
							})
						)
					);
				} else if (message?.t === 'ready') {
					const visitor = dial(`/v1/p/${routeId}`);
					visitor.onopen = (): void =>
						visitor.send(Buffer.from('ping from the visitor'));
					visitor.onmessage = (answer): void => {
						expect(Buffer.from(answer.data as ArrayBuffer).toString()).to.equal(
							'pong from the host'
						);
						resolve();
					};
					visitor.onerror = (e): void => reject(e as Error);
				}
			};
		});
		await paired;
		expect(Buffer.concat(hostBytes).toString()).to.equal(
			'ping from the visitor'
		);
		expect(hostTexts.map((t) => decodePorchControl(t)?.t)).to.deep.equal([
			'challenge',
			'ready',
			'paired'
		]);

		relay.child.kill('SIGTERM');
		expect(await relay.exit).to.equal(0);
	});

	it('exits with the reason when its flags are wrong', async function () {
		const relay = run([
			'--url',
			'wss://relay.example',
			'--limit',
			'conections=5'
		]);
		const line = await relay.line;
		expect(line.ok).to.equal(false);
		expect(line.error).to.include({ code: 'PORCH_RELAY_FAILED' });
		expect((line.error as { message: string }).message).to.match(
			/--limit takes <name>=<n>/
		);
		expect(await relay.exit).to.equal(1);
	});

	it('exits with the reason when it cannot listen', async function () {
		const taken = net.createServer();
		await new Promise<void>((resolve) =>
			taken.listen(0, '127.0.0.1', () => resolve())
		);
		try {
			const relay = run([
				'--url',
				'wss://relay.example',
				'--port',
				String((taken.address() as net.AddressInfo).port)
			]);
			const line = await relay.line;
			expect(line.ok).to.equal(false);
			expect((line.error as { message: string }).message).to.match(
				/EADDRINUSE/
			);
			expect(await relay.exit).to.equal(1);
		} finally {
			taken.close();
		}
	});
});
