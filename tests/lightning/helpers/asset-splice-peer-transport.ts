import { strict as assert } from 'assert';
import { Transaction } from 'bitcoinjs-lib';
import { AssetSpliceConfirmationCoordinator } from '../../../src/lightning/channel/asset-splice-confirmation';
import {
	AssetSpliceTransport,
	type AssetSpliceHost
} from '../../../src/lightning/channel/asset-splice-transport';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	decodeCustomMessage
} from '../../../src/lightning/message/custom';
import { signatureRoundFixture } from './asset-splice-signature-round';

export interface SplicePeerPacket {
	from: number;
	type: number;
	wire: Buffer;
}

interface SpliceTransportPair {
	f: ReturnType<typeof signatureRoundFixture>['f'];
	s: ReturnType<typeof signatureRoundFixture>['s'];
	id: string;
	walletHosts: AssetSpliceHost[];
	available: boolean[];
	connected: boolean[];
	sides: AssetSpliceTransport[];
	make(i: number): AssetSpliceTransport;
	packets: SplicePeerPacket[];
	sent: SplicePeerPacket[];
	errors: string[];
	broadcasts: { from: number; tx: Transaction }[];
	deliver(p: SplicePeerPacket): void;
	idle(): Promise<void>;
	drain(onPacket?: (p: SplicePeerPacket) => boolean): Promise<void>;
	adopt(): Promise<string>;
	start(): Promise<void>;
	close(): void;
}

/** Two original SQLite devices using the regular on-wire construction and Bitcoin signers. */
export function setupAssetSplicePeerTransport(
	dir: string,
	observingFunding?: (
		side: number,
		channelId: string,
		txid: string,
		index: number
	) => boolean
): SpliceTransportPair {
	const { f, s, hosts } = signatureRoundFixture(dir, true);
	const { layout } = s;
	const ready = f.devices.map((d) =>
		d.store.finalOpeningChannelReady(f.id, d.party.root)
	);
	f.devices.forEach((d, i) =>
		d.store.rememberFinalPeerChannelReady(f.id, ready[1 - i])
	);
	const available = [true, true],
		connected = [true, true];
	const packets: SplicePeerPacket[] = [],
		sent: SplicePeerPacket[] = [];
	const errors: string[] = [],
		broadcasts: { from: number; tx: Transaction }[] = [];
	const walletHosts: AssetSpliceHost[] = hosts.map(
		(host, i): AssetSpliceHost => ({
			...host,
			proposeSplice: async () => Buffer.from([75 + i]),
			spliceContribution: () => f.terms[i].localDelta,
			abandonSplice: async () => {},
			describeSplice: async () => ({
				inputs: layout.inputs.map((input) => ({
					serialId: input.serialId,
					txid: input.prevTxid,
					vout: input.prevOutputIndex,
					sequence: input.sequence,
					isShared: !!input.isShared,
					prevTx: input.prevTx
				})),
				outputs: layout.outputs.map((o) => ({
					serialId: o.serialId,
					kind: o.role,
					valueSats: o.amountSats,
					descriptorHash: o.descriptorHash
				})),
				movements: layout.movements,
				parentBalances: layout.parentBalances,
				feeBudgets: layout.feeBudgets,
				relativeSatoshis: [f.terms[0].localDelta, f.terms[1].localDelta],
				commitmentRecordLimits: layout.commitmentRecordLimits
			}),
			prepareSplice: async (_ctx, proposals, _bitcoin, layoutDigest) => {
				assert.deepEqual(proposals, [Buffer.from([75]), Buffer.from([76])]);
				return {
					digest: Buffer.alloc(32, 77),
					consent: async () => Buffer.alloc(64, 81 + i),
					authorize: async () => Buffer.alloc(32, 83 + i),
					finalize: async () => ({
						transaction: s.tx.toBuffer(),
						fundingRoot: f.terms[i].assetFundingRoots!.candidate,
						proofDigest: Buffer.alloc(32, 85),
						fundingProofs: Buffer.from('b0c1', 'hex'),
						layoutDigest
					})
				};
			},
			verifySpliceFunding: async () => {},
			confirmSpliceFunding: async () => {},
			retractSpliceFunding: async () => {}
		})
	);
	function make(i: number): AssetSpliceTransport {
		const { store, party } = f.devices[i];
		return new AssetSpliceTransport(
			{ storage: store, root: party.root },
			walletHosts[i],
			(peer, id) =>
				connected[i] &&
				peer === f.devices[1 - i].party.binding.nodeId &&
				id === f.id,
			() => available[i],
			() => 0,
			(peer, type, raw) => {
				assert.equal(peer, f.devices[1 - i].party.binding.nodeId);
				const p = { from: i, type, wire: Buffer.from(raw) };
				packets.push(p);
				sent.push(p);
			},
			async () => 'unspent',
			() => {},
			(raw) => {
				broadcasts.push({ from: i, tx: Transaction.fromBuffer(raw) });
			},
			(_id, reason) => {
				errors.push(reason);
			},
			observingFunding && {
				disconnect: (): void => {},
				close: (): void => {},
				observingFunding: (id, txid, index): boolean =>
					observingFunding(i, id, txid, index)
			}
		);
	}
	const sides = [make(0), make(1)];
	function deliver(packet: SplicePeerPacket): void {
		const peer = f.devices[packet.from].party.binding.nodeId;
		const to = sides[1 - packet.from];
		if (packet.type === BEIGNET_CUSTOM_MESSAGE_TYPE) {
			const { subtype, payload } = decodeCustomMessage(packet.wire);
			to.custom(peer, subtype, payload);
		} else assert(to.handle(peer, packet.type, packet.wire));
	}
	async function idle(): Promise<void> {
		for (let i = 0; i < 200; i++) {
			await new Promise<void>((resolve) => setImmediate(resolve));
			if (!sides.some((side) => side['queues'].size)) return;
		}
		assert.fail(
			'Asset splice transport did not finish processing its peer frame'
		);
	}
	async function drain(
		onPacket: (p: SplicePeerPacket) => boolean = () => true
	): Promise<void> {
		for (let i = 0; i < 200; i++) {
			await idle();
			const p = packets.shift();
			if (!p) return;
			if (onPacket(p)) deliver(p);
		}
		assert.fail('Asset splice transport did not drain');
	}
	async function adopt(): Promise<string> {
		const txid = s.tx.getId();
		assert(broadcasts.some((e) => e.tx.getId() === txid));
		const locks: { from: number; wire: Buffer }[] = [];
		const coordinators = f.devices.map(
			(d, i) =>
				new AssetSpliceConfirmationCoordinator(
					d.store,
					walletHosts[i],
					() => {},
					(_peer, wire) => {
						locks.push({ from: i, wire });
					}
				)
		);
		for (const c of coordinators) {
			c.restore(f.id);
			await c.observe(
				f.id,
				txid,
				4,
				async () => ({ txid, blockHash: 'ba'.repeat(32), confirmations: 3 }),
				() => true
			);
		}
		for (const p of locks)
			assert(
				await coordinators[1 - p.from].receive(
					f.devices[p.from].party.binding.nodeId,
					p.wire
				)
			);
		for (const d of f.devices)
			assert.equal(
				d.store.loadAdoptedAssetSpliceReceipt(f.id)?.candidate.fundingTxid,
				txid
			);
		return txid;
	}
	return {
		f,
		id: f.id,
		s,
		walletHosts,
		available,
		connected,
		sides,
		make,
		packets,
		sent,
		errors,
		broadcasts,
		deliver,
		idle,
		drain,
		adopt,
		start: () =>
			sides[0].start(f.id, {
				fundingFeeratePerkw: f.terms[0].feerate,
				minimumDepth: 3
			}),
		close(): void {
			for (const side of sides) side.destroy();
			for (const d of f.devices) d.store.close();
		}
	};
}
