/**
 * Relay-only Iroh: the node's link can be handed out because no peer is
 * ever offered, or reached over, an IP address of the node.
 */
import { expect } from 'chai';
import crypto from 'crypto';
import { createNodeIrohEndpoint } from '../../src/lightning/transport/iroh-node';
import {
	IIrohAddress,
	IIrohEndpoint,
	IIrohEndpointOptions,
	IrohEndpointFactory,
	IrohRelayOnlyError,
	IrohRelayOnlyMode,
	isLoopbackSocketAddress,
	routableSocketAddresses
} from '../../src/lightning/transport/iroh';
import { PeerManager } from '../../src/lightning/transport/peer-manager';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IFakeIrohBinding, fakeIrohBinding } from './helpers/fake-iroh';
const sinon = require('sinon');

const SECRET = Buffer.alloc(32, 1);
const PUBLIC_ADDRESS = '203.0.113.9:4433';

describe('isLoopbackSocketAddress', () => {
	it('accepts loopback in every form Iroh prints', () => {
		for (const address of [
			'127.0.0.1:52148',
			'127.5.6.7:1',
			'[::1]:52557',
			'[::ffff:127.0.0.1]:9'
		])
			expect(isLoopbackSocketAddress(address), address).to.equal(true);
	});

	it('rejects private, wildcard, public and unparseable addresses', () => {
		for (const address of [
			'192.168.1.5:9',
			'10.0.0.2:9',
			'0.0.0.0:5',
			'[::]:61557',
			'[fe80::1]:5',
			'[2001:db8::1]:5',
			PUBLIC_ADDRESS,
			'1270.0.0.1:5',
			'::1',
			'localhost:5',
			''
		])
			expect(isLoopbackSocketAddress(address), address).to.equal(false);
	});

	it('keeps only the addresses a peer could route to', () => {
		expect(
			routableSocketAddresses(['127.0.0.1:1', PUBLIC_ADDRESS, '[::1]:2'])
		).to.deep.equal([PUBLIC_ADDRESS]);
	});
});

describe('Iroh relay-only: Node backend', () => {
	let fake: IFakeIrohBinding | undefined;
	let clock: { tickAsync(ms: number): Promise<void>; restore(): void };
	const opened: IIrohEndpoint[] = [];

	before(function () {
		try {
			require('@number0/iroh/index.js');
		} catch {
			this.skip();
		}
	});
	beforeEach(() => {
		clock = sinon.useFakeTimers({
			toFake: [
				'setTimeout',
				'clearTimeout',
				'setInterval',
				'clearInterval',
				'Date'
			]
		});
	});
	afterEach(async () => {
		for (const endpoint of opened.splice(0)) await endpoint.close();
		clock.restore();
		fake?.restore();
		fake = undefined;
	});

	/** Bind, and report whether the factory has resolved or rejected yet. */
	function bind(options: Partial<IIrohEndpointOptions> = {}): {
		state: { endpoint?: IIrohEndpoint; error?: Error };
		done: Promise<void>;
	} {
		const state: { endpoint?: IIrohEndpoint; error?: Error } = {};
		const done = createNodeIrohEndpoint({
			secretKey: SECRET,
			relayOnly: true,
			...options
		}).then(
			(endpoint) => {
				state.endpoint = endpoint;
				opened.push(endpoint);
			},
			(error: Error) => {
				state.error = error;
			}
		);
		return { state, done };
	}

	it('leaves the binding as it was when relay-only is off', async () => {
		fake = fakeIrohBinding();
		const { state, done } = bind({ relayOnly: false });
		await done;
		expect(fake.builders).to.have.length(1);
		expect(fake.builders[0].calls).to.deep.equal([
			'applyN0',
			'secretKey',
			'alpns',
			'bind'
		]);
		expect(state.endpoint?.relayOnly).to.equal(undefined);
		// An ordinary endpoint still reports its addresses.
		fake.builders[0].endpoint.addresses = [PUBLIC_ADDRESS];
		expect(state.endpoint?.address().directAddresses).to.deep.equal([
			PUBLIC_ADDRESS
		]);
		// And nothing polls it.
		await clock.tickAsync(10_000);
		expect(fake.builders[0].endpoint.closed).to.equal(false);
	});

	it('removes the IP transport when the binding can, with no wait', async () => {
		fake = fakeIrohBinding({ native: true });
		const { state, done } = bind();
		await done;
		const [builder] = fake.builders;
		expect(fake.builders).to.have.length(1);
		expect(builder.calls).to.include('clearIpTransports');
		expect(builder.calls.indexOf('clearIpTransports')).to.be.lessThan(
			builder.calls.indexOf('bind')
		);
		expect(builder.bindAddrs).to.deep.equal([]);
		expect(state.endpoint?.relayOnly).to.equal('native');
	});

	const noop = (): void => undefined;
	/** The setAlpns calls that advertised something. */
	const advertised = (index = 0): number[][][] =>
		(fake as IFakeIrohBinding).builders[index].endpoint.alpns.filter(
			(alpns) => alpns.length > 0
		);

	it('pins both address families to loopback otherwise, and stays silent while it watches', async () => {
		fake = fakeIrohBinding();
		const { state, done } = bind();
		// Binding is not held up by the watch.
		await done;
		const endpoint = state.endpoint as IIrohEndpoint;
		expect(fake.builders).to.have.length(1);
		expect(fake.builders[0].bindAddrs).to.deep.equal([
			'127.0.0.1:0',
			'[::1]:0'
		]);
		expect(endpoint.relayOnly).to.equal('loopback-pin');

		fake.builders[0].endpoint.relayUrl = 'https://relay.example/';
		endpoint.listen(noop, noop);
		await clock.tickAsync(11_750);
		expect(advertised()).to.deep.equal([]);
		expect(endpoint.address().relayUrl).to.equal(undefined);

		await clock.tickAsync(250);
		expect(advertised()).to.have.length(1);
		expect(endpoint.address().relayUrl).to.equal('https://relay.example/');
		expect(fake.builders[0].endpoint.closed).to.equal(false);
	});

	it('holds an outbound dial until the watch is over', async () => {
		fake = fakeIrohBinding();
		const { state, done } = bind();
		await done;
		const endpoint = state.endpoint as IIrohEndpoint;
		const target = {
			endpointId:
				'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
			relayUrl: 'https://relay.example/'
		};
		const failure = (promise: Promise<unknown>): Promise<Error> =>
			promise.then(
				() => new Error('connected'),
				(error: Error) => error
			);
		const impatient = failure(endpoint.connect(target, 1_000));
		const patient = failure(endpoint.connect(target, 20_000));
		await clock.tickAsync(1_000);
		expect((await impatient).message).to.contain('timed out');
		await clock.tickAsync(10_000);
		expect(fake.builders[0].endpoint.connects).to.equal(0);
		await clock.tickAsync(1_000);
		expect((await patient).message).to.equal('no route');
		expect(fake.builders[0].endpoint.connects).to.equal(1);
	});

	it('retries with IPv4 alone on a host with no IPv6 loopback', async () => {
		fake = fakeIrohBinding({ failBind: (_builder, index) => index === 0 });
		const { state, done } = bind();
		await done;
		expect(fake.builders).to.have.length(2);
		expect(fake.builders[0].bindAddrs).to.deep.equal([
			'127.0.0.1:0',
			'[::1]:0'
		]);
		// A failed bind consumes its builder, so the retry is a fresh one.
		expect(fake.builders[1].bindAddrs).to.deep.equal(['127.0.0.1:0']);
		expect(state.endpoint?.relayOnly).to.equal('loopback-pin');
	});

	it('refuses an endpoint that bound a socket off loopback', async () => {
		fake = fakeIrohBinding({
			endpoint: () => ({ sockets: ['127.0.0.1:4433', '0.0.0.0:4433'] })
		});
		const { state, done } = bind();
		await done;
		expect(state.error).to.be.instanceOf(IrohRelayOnlyError);
		expect(state.error?.message).to.contain('off loopback');
		expect(fake.builders[0].endpoint.closed).to.equal(true);
	});

	it('refuses an endpoint whose address list is routable as it binds', async () => {
		fake = fakeIrohBinding({
			endpoint: () => ({ addresses: ['127.0.0.1:4433', PUBLIC_ADDRESS] })
		});
		const { state, done } = bind();
		await done;
		expect(state.error).to.be.instanceOf(IrohRelayOnlyError);
		expect(fake.builders[0].endpoint.closed).to.equal(true);
	});

	it('closes itself when the router maps a port during the watch, having advertised nothing', async () => {
		fake = fakeIrohBinding();
		const violations: IrohRelayOnlyError[] = [];
		const { state, done } = bind({
			onRelayOnlyViolation: (error) => violations.push(error)
		});
		await done;
		const endpoint = state.endpoint as IIrohEndpoint;
		fake.builders[0].endpoint.relayUrl = 'https://relay.example/';
		endpoint.listen(noop, noop);
		const dial = endpoint
			.connect({ endpointId: 'ab'.repeat(32) }, 20_000)
			.catch((error: Error) => error);
		await clock.tickAsync(3_000);
		expect(violations).to.deep.equal([]);

		fake.builders[0].endpoint.addresses.push(PUBLIC_ADDRESS);
		await clock.tickAsync(250);
		expect(violations).to.have.length(1);
		expect(violations[0].code).to.equal('IROH_RELAY_ONLY_VIOLATED');
		expect(violations[0].message).to.contain('port mapping');
		expect(violations[0].message).to.not.contain('203.0.113');
		expect(fake.builders[0].endpoint.closed).to.equal(true);
		expect(((await dial) as Error).message).to.contain('closed');

		// The watch ending later changes nothing: no ALPN, no relay, no dial.
		await clock.tickAsync(20_000);
		expect(advertised()).to.deep.equal([]);
		expect(endpoint.address().relayUrl).to.equal(undefined);
		expect(fake.builders[0].endpoint.connects).to.equal(0);
		expect(violations).to.have.length(1);
	});

	it('refuses a binding whose endpoint holds a routable address despite the switch', async () => {
		fake = fakeIrohBinding({
			native: true,
			endpoint: () => ({ addresses: [PUBLIC_ADDRESS] })
		});
		const { state, done } = bind();
		await done;
		expect(state.error).to.be.instanceOf(IrohRelayOnlyError);
		expect(fake.builders[0].endpoint.closed).to.equal(true);
	});

	for (const native of [false, true]) {
		it(`closes itself and reports once when a routable address appears later (${
			native ? 'native' : 'loopback-pin'
		})`, async () => {
			fake = fakeIrohBinding({ native });
			const violations: IrohRelayOnlyError[] = [];
			const { state, done } = bind({
				onRelayOnlyViolation: (error) => violations.push(error)
			});
			await done;
			const endpoint = state.endpoint as IIrohEndpoint;
			endpoint.listen(noop, noop);
			await clock.tickAsync(60_000);
			expect(advertised()).to.have.length(1);
			expect(violations).to.deep.equal([]);
			expect(fake.builders[0].endpoint.closed).to.equal(false);

			fake.builders[0].endpoint.addresses.push(PUBLIC_ADDRESS);
			await clock.tickAsync(250);
			expect(violations).to.have.length(1);
			expect(violations[0]).to.be.instanceOf(IrohRelayOnlyError);
			expect(violations[0].message).to.not.contain('203.0.113');
			expect(fake.builders[0].endpoint.closed).to.equal(true);
			// It stopped advertising, and a closed endpoint is not checked again.
			expect(fake.builders[0].endpoint.alpns.pop()).to.deep.equal([]);
			await clock.tickAsync(5_000);
			expect(violations).to.have.length(1);
			expect(() =>
				endpoint.listen(
					() => undefined,
					() => undefined
				)
			).to.throw('closed');
		});
	}

	it('refuses relay-only with relays disabled, before binding anything', async () => {
		fake = fakeIrohBinding();
		const { state, done } = bind({ relays: [] });
		await done;
		expect(state.error?.message).to.contain('needs a relay');
		expect(fake.builders).to.have.length(0);
	});

	it('hands out no direct addresses from a relay-only endpoint', async () => {
		fake = fakeIrohBinding();
		const { state, done } = bind();
		await done;
		await clock.tickAsync(12_000);
		fake.builders[0].endpoint.relayUrl = 'https://relay.example/';
		const address = state.endpoint?.address() as IIrohAddress;
		expect(address.relayUrl).to.equal('https://relay.example/');
		expect(address).to.not.have.property('directAddresses');
	});
});

/** An endpoint as a factory hands it to the peer manager. */
function stubEndpoint(relayOnly?: IrohRelayOnlyMode): IIrohEndpoint & {
	relayUrl?: string;
	closed: boolean;
} {
	const endpoint = {
		relayUrl: undefined as string | undefined,
		closed: false,
		relayOnly,
		address: (): IIrohAddress => ({
			endpointId: 'ab'.repeat(32),
			...(endpoint.relayUrl ? { relayUrl: endpoint.relayUrl } : {})
		}),
		connect: (): Promise<never> => Promise.reject(new Error('not dialed here')),
		listen: (): void => undefined,
		stopListening: (): void => undefined,
		close: async (): Promise<void> => {
			endpoint.closed = true;
		}
	};
	return endpoint;
}

describe('Iroh relay-only: PeerManager', () => {
	const managers: PeerManager[] = [];
	afterEach(() => {
		for (const pm of managers.splice(0)) pm.destroy();
	});

	function manager(
		factory: IrohEndpointFactory,
		relayOnly = true
	): PeerManager {
		const pm = new PeerManager({
			localPrivateKey: crypto.randomBytes(32),
			iroh: { factory, secretKey: SECRET, ...(relayOnly ? { relayOnly } : {}) }
		});
		managers.push(pm);
		return pm;
	}

	const rejection = (promise: Promise<unknown>): Promise<Error | null> =>
		promise.then(
			() => null,
			(error: Error) => error
		);

	it('refuses an endpoint whose factory ignored relay-only, and does not ask again', async () => {
		const made: Array<ReturnType<typeof stubEndpoint>> = [];
		const pm = manager(async () => {
			const endpoint = stubEndpoint();
			made.push(endpoint);
			return endpoint;
		});
		const first = await rejection(pm.listenIroh());
		expect(first).to.be.instanceOf(IrohRelayOnlyError);
		expect(first?.message).to.contain('did not provide it');
		expect(made).to.have.length(1);
		expect(made[0].closed).to.equal(true);
		expect(pm.getIrohConnectionString()).to.equal(undefined);
		expect(pm.getIrohRelayOnlyMode()).to.equal(undefined);

		expect(await rejection(pm.listenIroh())).to.equal(first);
		expect(made).to.have.length(1);
	});

	it('accepts an attesting endpoint and serves the link only once a relay is known', async () => {
		const endpoint = stubEndpoint('loopback-pin');
		let asked: IIrohEndpointOptions | undefined;
		const pm = manager(async (options) => {
			asked = options;
			return endpoint;
		});
		await pm.listenIroh();
		expect(asked?.relayOnly).to.equal(true);
		expect(pm.isIrohRelayOnly()).to.equal(true);
		expect(pm.getIrohRelayOnlyMode()).to.equal('loopback-pin');
		// Discovery is on, yet a relay-only link without its relay is no link.
		expect(pm.getIrohConnectionString()).to.equal(undefined);
		endpoint.relayUrl = 'https://relay.example/';
		expect(pm.getIrohConnectionString()).to.match(
			/^0[23][0-9a-f]{64}@iroh:(ab){32}\?relay=https%3A%2F%2Frelay\.example%2F$/
		);
	});

	it('stops the listener for good when the endpoint reports a violation', async () => {
		const endpoint = stubEndpoint('loopback-pin');
		endpoint.relayUrl = 'https://relay.example/';
		let asked: IIrohEndpointOptions | undefined;
		let binds = 0;
		const forwarded: Error[] = [];
		const pm = new PeerManager({
			localPrivateKey: crypto.randomBytes(32),
			iroh: {
				factory: async (options) => {
					binds++;
					asked = options;
					return endpoint;
				},
				secretKey: SECRET,
				relayOnly: true,
				onRelayOnlyViolation: (error) => forwarded.push(error)
			}
		});
		managers.push(pm);
		const seen: Error[] = [];
		pm.on('iroh:relay-only-violated', (error: Error) => seen.push(error));
		await pm.listenIroh();
		expect(pm.isListening()).to.equal(true);
		expect(pm.getIrohConnectionString()).to.be.a('string');

		const violation = new IrohRelayOnlyError('the router mapped a port');
		asked?.onRelayOnlyViolation?.(violation);
		asked?.onRelayOnlyViolation?.(violation);
		expect(seen).to.deep.equal([violation]);
		expect(forwarded).to.deep.equal([violation, violation]);
		expect(pm.isListening()).to.equal(false);
		expect(pm.getIrohConnectionString()).to.equal(undefined);
		expect(pm.getIrohRelayOnlyMode()).to.equal(undefined);
		expect(pm.getIrohRelayOnlyFailure()).to.equal(violation);

		// Neither a listen nor an outbound Iroh dial binds another endpoint.
		expect(await rejection(pm.listenIroh())).to.equal(violation);
		const dial = await rejection(
			pm.connectPeer(
				'02' + 'cd'.repeat(32),
				'ef'.repeat(32),
				0,
				{ type: 'iroh', endpointId: 'ef'.repeat(32) },
				{ reconnect: false, timeoutMs: 500 }
			)
		);
		expect(dial).to.be.instanceOf(Error);
		expect(binds).to.equal(1);
	});

	it('takes any endpoint when relay-only was not asked for', async () => {
		const endpoint = stubEndpoint();
		endpoint.relayUrl = 'https://relay.example/';
		let asked: IIrohEndpointOptions | undefined;
		const pm = manager(async (options) => {
			asked = options;
			return endpoint;
		}, false);
		await pm.listenIroh();
		expect(asked?.onRelayOnlyViolation).to.equal(undefined);
		expect(pm.isIrohRelayOnly()).to.equal(false);
		expect(pm.getIrohRelayOnlyMode()).to.equal(undefined);
		expect(pm.getIrohConnectionString()).to.be.a('string');
	});
});

describe('Iroh relay-only: LightningNode', () => {
	const nodes: LightningNode[] = [];
	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
	});

	function makeNode(relayOnly: boolean): {
		node: LightningNode;
		endpoint: ReturnType<typeof stubEndpoint>;
		violate: (error: IrohRelayOnlyError) => void;
	} {
		const endpoint = stubEndpoint(relayOnly ? 'native' : undefined);
		endpoint.relayUrl = 'https://relay.example/';
		let asked: IIrohEndpointOptions | undefined;
		const node = new LightningNode({
			nodePrivateKey: crypto.randomBytes(32),
			perCommitmentSeed: crypto.randomBytes(32),
			channelBasepoints: {
				fundingPubkey: crypto.randomBytes(33),
				revocationBasepoint: crypto.randomBytes(33),
				paymentBasepoint: crypto.randomBytes(33),
				delayedPaymentBasepoint: crypto.randomBytes(33),
				htlcBasepoint: crypto.randomBytes(33),
				firstPerCommitmentPoint: crypto.randomBytes(33)
			},
			fundingPrivkey: crypto.randomBytes(32),
			enableNetworking: true,
			// Asked for 'any': relay-only overrides it.
			learnedAddressDials: 'any',
			iroh: {
				factory: async (options) => {
					asked = options;
					return endpoint;
				},
				secretKey: SECRET,
				...(relayOnly ? { relayOnly: true } : {})
			}
		});
		nodes.push(node);
		return {
			node,
			endpoint,
			violate: (error) => asked?.onRelayOnlyViolation?.(error)
		};
	}

	const peerManager = (node: LightningNode): PeerManager =>
		(node as unknown as { peerManager: PeerManager }).peerManager;

	it('reports the mode, dials learned addresses through a proxy only, and raises a violation as node:error', async () => {
		const { node, violate } = makeNode(true);
		await node.listenIroh();
		expect(node.getIrohRelayOnlyStatus()).to.deep.equal({ mode: 'native' });
		expect(node.getIrohConnectionString()).to.contain('@iroh:');
		// No proxy is configured, so a learned public address is not dialable.
		expect(peerManager(node).canDialLearnedAddress('203.0.113.7')).to.equal(
			false
		);

		const errors: Array<{ code: string; message: string }> = [];
		node.on('node:error', (error) => errors.push(error));
		violate(new IrohRelayOnlyError('the router mapped a port'));
		expect(errors.map((error) => error.code)).to.deep.equal([
			'IROH_RELAY_ONLY_VIOLATED'
		]);
		expect(errors[0].message).to.equal('the router mapped a port');
		expect(node.getIrohRelayOnlyStatus()).to.deep.equal({
			failure: 'the router mapped a port'
		});
		expect(node.getIrohConnectionString()).to.equal(undefined);
	});

	it('has no relay-only status, and dials learned addresses as before, without the option', async () => {
		const { node } = makeNode(false);
		await node.listenIroh();
		expect(node.getIrohRelayOnlyStatus()).to.equal(undefined);
		expect(peerManager(node).canDialLearnedAddress('203.0.113.7')).to.equal(
			true
		);
	});
});
