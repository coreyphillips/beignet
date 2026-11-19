/**
 * Issue #2111: an asset HTLC of the peer whose carrier is under the dust
 * limit.
 *
 * No commitment of either side can hold units on an output too small to
 * exist, so such an HTLC can never be committed. The node refuses it with
 * the lighter of BOLT 2's answers: a warning, and the connection closed. The
 * channel is not failed and nothing of the add is kept, a commitment_signed
 * that covers it is not read, and after the reconnect the channel carries
 * payments as before. Units the sender does not hold still fail the channel.
 */

import { expect } from 'chai';
import { encodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { encodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { MessageType } from '../../src/lightning/message/types';
import { ChannelState } from '../../src/lightning/channel/types';
import { PaymentStatus } from '../../src/lightning/node/types';
import { amountRecord, hash } from './helpers/auxiliary-pair';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	payAssetUnits,
	reconnectHosts,
	turns,
	withAssetOpens,
	type IAssetHost
} from './helpers/auxiliary-nodes';

interface IScene {
	alice: IAssetHost;
	bob: IAssetHost;
	channelId: Buffer;
	/** The BOLT 1 errors (17) and warnings (1) Bob sent, in order. */
	sent: Array<{ type: number; text: string }>;
	/** Peers Bob asked its host to disconnect. */
	dropped: string[];
	/** What Bob's peer sends him over the channel, as Alice's next HTLC. */
	peerAdds: (amountMsat: bigint, units: bigint) => void;
}

describe('an asset HTLC of the peer with a carrier under the dust limit (issue #2111)', function () {
	this.timeout(60_000);
	withAssetOpens();
	const hosts: IAssetHost[] = [];
	afterEach(() => {
		for (const host of hosts.splice(0)) {
			try {
				host.node.destroy();
			} catch {
				// already destroyed
			}
			host.storage?.close();
		}
	});

	/**
	 * Alice opens an asset channel to Bob (9,000 units hers, 1,000 his). The
	 * adds of the peer are written straight to Bob's wire, as a peer that is
	 * not this engine sends them: Alice's own node would not offer them.
	 */
	async function scene(tag: string): Promise<IScene> {
		const alice = assetHost(tag, 1, {}, { sqlite: true });
		const bob = assetHost(
			tag,
			2,
			{ valueIncomingHtlc: (context) => context.auxiliaryAmount! * 1000n },
			{ sqlite: true }
		);
		hosts.push(alice, bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 9000n,
			acceptorUnits: 1000n
		});
		const sent: IScene['sent'] = [];
		bob.node.on(
			'message:outbound',
			(_peer: string, type: number, payload: Buffer) => {
				if (type === MessageType.ERROR || type === MessageType.WARNING) {
					sent.push({ type, text: payload.subarray(34).toString('utf8') });
				}
			}
		);
		const dropped: string[] = [];
		bob.node.on('peer:disconnect-requested', (peer: string) => {
			dropped.push(peer);
		});
		const peerAdds = (amountMsat: bigint, units: bigint): void => {
			const id = alice.node
				.getChannelManager()
				.getChannel(channelId)!
				.getFullState().localHtlcCounter;
			bob.node.handlePeerMessage(
				alice.node.getNodeId(),
				MessageType.UPDATE_ADD_HTLC,
				encodeUpdateAddHtlcMessage({
					channelId,
					id,
					amountMsat,
					paymentHash: hash(`${tag} add ${id}`),
					cltvExpiry: 500,
					onionRoutingPacket: Buffer.alloc(1366),
					customRecords: amountRecord(units)
				})
			);
		};
		return { alice, bob, channelId, sent, dropped, peerAdds };
	}

	/**
	 * The channel as it was on both sides, with no HTLC: open, or waiting
	 * for the reestablish of the connection Bob closed. Never failed.
	 */
	const both = (s: IScene, connected = true): void => {
		for (const host of [s.alice, s.bob]) {
			const info = host.node.getAuxiliaryChannelInfo(s.channelId)!;
			expect(info.state).to.be.oneOf(
				connected
					? [ChannelState.NORMAL]
					: [ChannelState.NORMAL, ChannelState.AWAITING_REESTABLISH]
			);
			expect(info.htlcs).to.deep.equal([]);
		}
	};

	it('is refused with a warning and the connection closed: the channel stays as it was, and pays again after the reconnect', async () => {
		const s = await scene('aux-dust-carrier');
		const broadcasts = s.alice.broadcasts.length + s.bob.broadcasts.length;
		// What a peer running tapd sends when its caller hands it first-hop
		// records with the units: the invoice's own amount as the carrier,
		// here 297,029 msat for 300 units.
		s.peerAdds(297_029n, 300n);
		await turns(50);

		// Warned, not failed.
		expect(s.sent).to.have.length(1);
		expect(s.sent[0].type).to.equal(MessageType.WARNING);
		expect(s.sent[0].text).to.equal(
			"update_add_htlc 0 carries asset units on 297029 msat, under the channel's dust limit: no commitment can hold it"
		);
		expect(s.dropped).to.deep.equal([s.alice.node.getNodeId()]);
		expect(
			s.bob.errors.some((error) => error.includes('under the channel'))
		).to.equal(true);
		// The channel stays as it was on both sides, and nothing went to the
		// chain.
		both(s, false);
		expect(
			s.bob.node.getAuxiliaryChannelInfo(s.channelId)!.remoteAssetBalance
		).to.equal(9000n);
		expect(s.alice.broadcasts.length + s.bob.broadcasts.length).to.equal(
			broadcasts
		);

		// After the reconnect the channel carries a payment as before.
		await reconnectHosts(s.alice, s.bob);
		const invoice = s.bob.node.createInvoice({
			amountMsat: 1_000_000n,
			description: 'after the warning'
		});
		payAssetUnits(s.alice, s.bob, s.channelId, invoice, 1_000_000n, 1000n);
		await turns(200);
		expect(s.alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		both(s);
		expect(
			s.bob.node.getAuxiliaryChannelInfo(s.channelId)!.localAssetBalance
		).to.equal(2000n);
		expect(s.sent).to.have.length(1);
	});

	it('does not read a commitment_signed of the peer that follows such an add before the connection has gone', async () => {
		const s = await scene('aux-dust-carrier-signed');
		s.peerAdds(297_029n, 300n);
		// The peer signs its next commitment of Bob's, which would hold the
		// add Bob dropped: judged, it could only fail the channel.
		s.bob.node.handlePeerMessage(
			s.alice.node.getNodeId(),
			MessageType.COMMITMENT_SIGNED,
			encodeCommitmentSignedMessage({
				channelId: s.channelId,
				signature: Buffer.alloc(64, 1),
				htlcSignatures: [Buffer.alloc(64, 2)]
			})
		);
		await turns(50);
		expect(s.sent.map((m) => m.type)).to.deep.equal([MessageType.WARNING]);
		both(s, false);

		await reconnectHosts(s.alice, s.bob);
		const invoice = s.bob.node.createInvoice({
			amountMsat: 1_000_000n,
			description: 'after the signature that was not read'
		});
		payAssetUnits(s.alice, s.bob, s.channelId, invoice, 1_000_000n, 1000n);
		await turns(200);
		expect(s.alice.node.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		both(s);
	});

	it('still fails the channel for units its sender does not hold', async () => {
		const s = await scene('aux-dust-carrier-units');
		// A carrier above dust, and more units than Alice holds.
		s.peerAdds(354_000n, 20_000n);
		await turns(50);
		expect(s.sent.map((m) => m.type)).to.deep.equal([MessageType.ERROR]);
		expect(s.sent[0].text).to.equal('Invalid asset HTLC metadata or balance');
		expect(s.bob.node.getAuxiliaryChannelInfo(s.channelId)?.state).to.not.equal(
			ChannelState.NORMAL
		);
	});
});
