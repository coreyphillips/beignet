/**
 * An asset channel is never run through the logic of an ordinary one
 * (issue #2093). Whatever has no asset handling refuses, with an error that
 * names the channel and what was asked of it, and leaves the channel as it
 * was; a channel without asset state is not asked anything.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import type { Channel } from '../../src/lightning/channel/channel';
import type { ChannelAction } from '../../src/lightning/channel/channel-actions';
import {
	ChannelActionType,
	ChannelErrorCode
} from '../../src/lightning/channel/channel-actions';
import {
	AuxiliaryChannelUnsupportedError,
	auxiliaryUnsupported,
	isAuxiliaryChannelState
} from '../../src/lightning/channel/auxiliary-guard';
import { ChannelState } from '../../src/lightning/channel/types';
import type { IAssetHost } from './helpers/auxiliary-nodes';
import {
	assetHost,
	connectHosts,
	openAssetChannel,
	withAssetOpens
} from './helpers/auxiliary-nodes';
import { openReadyChannel } from './helpers/loopback-nodes';

const SCRIPT = Buffer.concat([Buffer.from('0014', 'hex'), Buffer.alloc(20, 9)]);

describe('an asset channel refuses what it has no asset handling for (issue #2093)', function () {
	this.timeout(20_000);
	withAssetOpens();

	let alice: IAssetHost;
	let bob: IAssetHost;
	let channelId: Buffer;
	let channel: Channel;
	let hex: string;

	beforeEach(async () => {
		alice = assetHost('aux-guard', 1);
		bob = assetHost('aux-guard', 2);
		connectHosts(alice, bob);
		channelId = await openAssetChannel(alice, bob, {
			tag: 'guard',
			openerUnits: 900n,
			acceptorUnits: 100n
		});
		hex = channelId.toString('hex');
		channel = alice.node.getChannelManager().getChannel(channelId)!;
	});

	afterEach(() => {
		alice.node.destroy();
		bob.node.destroy();
	});

	/** The one action of a refusal, checked for its code and its wording. */
	function refusal(actions: ChannelAction[], operation: string): void {
		expect(actions).to.have.length(1);
		const action = actions[0] as {
			type: ChannelActionType;
			message: string;
			code?: ChannelErrorCode;
		};
		expect(action.type).to.equal(ChannelActionType.ERROR);
		expect(action.code).to.equal(ChannelErrorCode.UNSUPPORTED);
		expect(action.message).to.equal(
			`An asset channel does not support ${operation} (channel ${hex})`
		);
	}

	/** Nothing was sent, and both sides still hold the channel as it was. */
	function untouched(sentBefore: number, sent: number[]): void {
		expect(sent.length).to.equal(sentBefore);
		for (const host of [alice, bob]) {
			const info = host.node.getAuxiliaryChannelInfo(channelId)!;
			expect(info.state).to.equal(ChannelState.NORMAL);
		}
		const state = channel.getFullState();
		expect(state.auxiliaryState!.localBalance).to.equal(900n);
		expect(state.auxiliaryState!.remoteBalance).to.equal(100n);
	}

	it('names the channel and the operation in a typed error', () => {
		const error = auxiliaryUnsupported(channel.getFullState(), 'a splice')!;
		expect(error).to.be.instanceOf(AuxiliaryChannelUnsupportedError);
		expect(error.code).to.equal('ASSET_CHANNEL_UNSUPPORTED');
		expect(error.channelId).to.equal(hex);
		expect(error.operation).to.equal('a splice');
		expect(error.message).to.equal(
			`An asset channel does not support a splice (channel ${hex})`
		);
	});

	it('refuses, in the channel, a simple close, a close to an address of the caller, every force close, splice, quiescence and delegated epoch', () => {
		const sent: number[] = [];
		alice.node.on('message:outbound', (_peer: string, type: number) => {
			sent.push(type);
		});
		const signer = channel.getSigner()!;
		const never = (): never => {
			throw new Error('an asset channel was signed for as an ordinary one');
		};
		// An asset channel closes cooperatively to the script its provider
		// names (step 9), so not to one the caller chose, and never by
		// option_simple_close.
		refusal(
			channel.initiateShutdown(SCRIPT, false, true),
			'a close to an address of the caller'
		);
		refusal(channel.sendClosingComplete(500n, 0, never), 'a simple close');
		refusal(
			channel.handleClosingComplete(
				{
					channelId,
					closerScriptPubkey: SCRIPT,
					closeeScriptPubkey: SCRIPT,
					feeSatoshis: 500n,
					locktime: 0
				} as never,
				never,
				never
			),
			'a simple close'
		);
		refusal(
			channel.handleClosingSig({ channelId } as never, never),
			'a simple close'
		);
		refusal(channel.forceClose(signer), 'a force close');
		expect(channel.prepareForceClose(signer)).to.deep.equal({
			ok: false,
			error: `An asset channel does not support a force close (channel ${hex})`
		});
		refusal(channel.initiateSplice(10_000n, 253), 'a splice');
		refusal(channel.handleSplice({ channelId } as never), 'a splice');
		refusal(channel.initiateQuiescence(), 'quiescence');
		refusal(
			channel.handleStfuMessage({ channelId, initiator: true } as never),
			'quiescence'
		);
		refusal(
			channel.initiateFforEpoch({
				voucherAmountsMsat: [1000n],
				minPaymentMsat: 1n,
				settlementDeadline: 10,
				voucherExpiry: 10,
				feeBaseMsat: 0,
				feeProportionalMillionths: 0
			}),
			'a delegated settlement epoch'
		);
		refusal(
			channel.handleFforInit(Buffer.alloc(0)),
			'a delegated settlement epoch'
		);
		untouched(0, sent);
	});

	it('refuses through the node and its manager', () => {
		const sent: number[] = [];
		for (const host of [alice, bob]) {
			host.node.on('message:outbound', (_peer: string, type: number) => {
				sent.push(type);
			});
		}
		const errors: string[] = [];
		alice.node
			.getChannelManager()
			.on('error', (_id: unknown, message: unknown) => {
				errors.push(String(message));
			});
		const close = alice.node.closeChannel(channelId, SCRIPT, false, true);
		expect(close.ok).to.equal(false);
		expect(JSON.stringify(close)).to.include(
			`An asset channel does not support a close to an address of the caller (channel ${hex})`
		);
		const force = alice.node.forceCloseChannel(channelId, SCRIPT);
		expect(force.ok).to.equal(false);
		expect(force.error).to.include(
			`An asset channel does not support a force close (channel ${hex})`
		);
		const splice = alice.node
			.getChannelManager()
			.initiateSplice(channelId, 10_000n, 253);
		expect(splice.ok).to.equal(false);
		expect(splice.error).to.equal(
			`An asset channel does not support a splice (channel ${hex})`
		);
		expect(errors).to.deep.equal([
			`An asset channel does not support a close to an address of the caller (channel ${hex})`,
			`An asset channel does not support a force close (channel ${hex})`,
			`An asset channel does not support a splice (channel ${hex})`
		]);
		untouched(0, sent);
	});

	it('does not read a spend of its funding output as an ordinary commitment', () => {
		const manager = alice.node.getChannelManager();
		const errors: string[] = [];
		manager.on('error', (_id: unknown, message: unknown) => {
			errors.push(String(message));
		});
		const state = channel.getFullState();
		const spend = new bitcoin.Transaction();
		spend.version = 2;
		// A commitment carries the BOLT 3 stamp in its locktime and sequence;
		// a spend without it is a cooperative close, which the channel now
		// follows (step 9).
		spend.locktime = 0x20000001;
		spend.addInput(
			Buffer.from(state.fundingTxid!).reverse(),
			state.fundingOutputIndex!,
			0x80000001
		);
		spend.addOutput(SCRIPT, 1_000);
		expect(
			manager.handleFundingSpent(channelId, spend, 100, SCRIPT)
		).to.deep.equal([]);
		expect(errors).to.deep.equal([
			`An asset channel does not support on-chain resolution (channel ${hex})`
		]);
		expect(manager.getMonitor(channelId)).to.equal(undefined);
		expect(channel.getFullState().state).to.equal(ChannelState.NORMAL);
	});

	it('asks nothing of a channel without asset state, on a node with a provider', async () => {
		const carol = assetHost('aux-guard-plain', 3);
		const dave = assetHost('aux-guard-plain', 4);
		connectHosts(carol, dave);
		try {
			const ordinary = await openReadyChannel(carol.node, dave.node);
			const plain = carol.node.getChannelManager().getChannel(ordinary)!;
			expect(isAuxiliaryChannelState(plain.getFullState())).to.equal(false);
			for (const operation of [
				'a simple close',
				'a close to an address of the caller',
				'a force close',
				'on-chain resolution',
				'a splice',
				'quiescence',
				'a delegated settlement epoch'
			] as const) {
				expect(auxiliaryUnsupported(plain.getFullState(), operation)).to.equal(
					undefined
				);
			}
			const closing = plain.initiateShutdown(SCRIPT);
			expect(
				closing.some((action) => action.type === ChannelActionType.ERROR),
				JSON.stringify(closing.map((action) => action.type))
			).to.equal(false);
		} finally {
			carol.node.destroy();
			dave.node.destroy();
		}
	});
});
