import { expect } from 'chai';
import {
	JitReceiveManager,
	IJitManagerDeps,
	IHeldJitPart
} from '../../src/lightning/liquidity/jit-receive';

/** In-memory KV standing in for the SQLite metadata table. */
function makeKv(): {
	saveMetadata(k: string, v: string): void;
	loadMetadata(k: string): string | null;
	raw: Map<string, string>;
} {
	const raw = new Map<string, string>();
	return {
		raw,
		saveMetadata: (k, v) => void raw.set(k, v),
		loadMetadata: (k) => raw.get(k) ?? null
	};
}

function makeDeps(
	kv: ReturnType<typeof makeKv>,
	overrides: Partial<IJitManagerDeps> = {}
): IJitManagerDeps {
	return {
		openZeroConfChannelAndWait: async () => {
			throw new Error('not in this test');
		},
		forwardOnto: () => undefined,
		getBlockHeight: () => 100,
		failureCodes: { unknownNextPeer: 0x400a, temporaryChannelFailure: 0x1007 },
		storage: kv,
		...overrides
	};
}

function makePart(overrides: Partial<IHeldJitPart> = {}): IHeldJitPart {
	return {
		inChannelId: Buffer.alloc(32, 1),
		inHtlcId: 7n,
		paymentHash: Buffer.alloc(32, 2),
		forwardAmountMsat: 50_000_000n,
		forwardCltv: 200,
		incomingCltvExpiry: 300,
		nextPacket: {
			version: 0,
			ephemeralKey: Buffer.alloc(33),
			routingInfo: Buffer.alloc(1300),
			hmac: Buffer.alloc(32)
		},
		failIncoming: () => undefined,
		...overrides
	};
}

describe('JIT receive persistence', () => {
	it('persists intents and restores unexpired ones after a restart', () => {
		const kv = makeKv();
		const m1 = new JitReceiveManager(makeDeps(kv), { enabled: true });
		const scid = Buffer.alloc(8, 9);
		const ack = m1.registerIntent('02'.padEnd(66, 'a'), {
			interceptScid: scid,
			maxAmountMsat: 100_000_000n,
			expectedTotalMsat: 100_000_000n,
			targetRemainingInboundSat: 150_000n,
			expirySeconds: 3600
		});
		expect(ack.accepted).to.equal(true);
		expect(kv.raw.get('jit:intents')).to.contain(scid.toString('hex'));

		// "Restart": a fresh manager on the same storage.
		const m2 = new JitReceiveManager(makeDeps(kv), { enabled: true });
		m2.restore();
		// The restored intent still intercepts (hold succeeds).
		const held = m2.tryInterceptUnknownScid(scid.toString('hex'), makePart());
		expect(held).to.equal(true);
	});

	it('does not restore expired intents', () => {
		const kv = makeKv();
		const m1 = new JitReceiveManager(makeDeps(kv), { enabled: true });
		const scid = Buffer.alloc(8, 4);
		m1.registerIntent('02'.padEnd(66, 'b'), {
			interceptScid: scid,
			maxAmountMsat: 100_000_000n,
			targetRemainingInboundSat: 0n,
			expirySeconds: 0 // expires immediately
		});
		const m2 = new JitReceiveManager(makeDeps(kv), { enabled: true });
		m2.restore();
		expect(
			m2.tryInterceptUnknownScid(scid.toString('hex'), makePart())
		).to.equal(false);
	});

	it('persists held HTLC metadata and fails it upstream after a restart', () => {
		const kv = makeKv();
		const m1 = new JitReceiveManager(
			// No expectedTotal → funding fires immediately but the open throws,
			// which is fine: the part was persisted at hold time.
			makeDeps(kv),
			{ enabled: true }
		);
		const scid = Buffer.alloc(8, 5);
		m1.registerIntent('02'.padEnd(66, 'c'), {
			interceptScid: scid,
			maxAmountMsat: 100_000_000n,
			expectedTotalMsat: 100_000_000n, // 100k sats — part below, stays held
			targetRemainingInboundSat: 0n,
			expirySeconds: 3600
		});
		expect(
			m1.tryInterceptUnknownScid(
				scid.toString('hex'),
				makePart({ forwardAmountMsat: 40_000_000n })
			)
		).to.equal(true);
		expect(kv.raw.get('jit:held')).to.contain(
			Buffer.alloc(32, 1).toString('hex')
		);

		// "Restart": channel not reestablished yet → retried; then delivered.
		const failed: Array<{ ch: string; id: bigint }> = [];
		let channelReady = false;
		const m2 = new JitReceiveManager(
			makeDeps(kv, {
				failRestoredHtlc: (ch, id) => {
					if (!channelReady) return false;
					failed.push({ ch, id });
					return true;
				}
			}),
			{ enabled: true }
		);
		m2.restore(); // first sweep: channel not ready
		expect(failed).to.have.length(0);
		expect(kv.raw.get('jit:held')).to.contain(
			Buffer.alloc(32, 1).toString('hex')
		);

		channelReady = true;
		m2.sweep(); // block tick after reestablish
		expect(failed).to.deep.equal([
			{ ch: Buffer.alloc(32, 1).toString('hex'), id: 7n }
		]);
		// Durable state drained.
		expect(kv.raw.get('jit:held')).to.equal('[]');
	});

	it('clears held metadata when the payment completes normally', async () => {
		const kv = makeKv();
		const forwarded: Buffer[] = [];
		const m = new JitReceiveManager(
			makeDeps(kv, {
				openZeroConfChannelAndWait: async () => Buffer.alloc(32, 8),
				forwardOnto: (outChannelId) => void forwarded.push(outChannelId)
			}),
			{ enabled: true }
		);
		const scid = Buffer.alloc(8, 6);
		m.registerIntent('02'.padEnd(66, 'd'), {
			interceptScid: scid,
			maxAmountMsat: 100_000_000n,
			expectedTotalMsat: 40_000_000n,
			targetRemainingInboundSat: 0n,
			expirySeconds: 3600
		});
		m.tryInterceptUnknownScid(
			scid.toString('hex'),
			makePart({ forwardAmountMsat: 40_000_000n })
		);
		await new Promise((r) => setTimeout(r, 20)); // let fund() run
		expect(forwarded).to.have.length(1);
		expect(kv.raw.get('jit:held')).to.equal('[]');
		expect(kv.raw.get('jit:intents')).to.equal('[]');
	});
});
