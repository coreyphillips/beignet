import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	encodeOpenChannelMessage,
	decodeAcceptChannelMessage,
	encodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeErrorMessage,
	encodeErrorMessage
} from '../../src/lightning/message/error';
import * as bitcoin from 'bitcoinjs-lib';
import type { IFundingProvider } from '../../src/lightning/node/types';

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}

	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	// Secret behind makeBasepoints' htlcBasepoint (keys[4]) — required for the
	// signer to produce HTLC second-level signatures in commitment_signed.
	const htlcBasepointSecret = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([4]))
		.digest();
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: fundingPrivkey,
		htlcBasepointSecret
	};
}

/**
 * Create a mock loopback that routes messages from manager A to manager B
 * and vice versa via 'message:outbound' events.
 */
function connectManagers(
	managerA: ChannelManager,
	pubkeyA: string,
	managerB: ChannelManager,
	pubkeyB: string
): void {
	managerA.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyB) {
				managerB.handleMessage(pubkeyA, type, payload);
			}
		}
	);

	managerB.on(
		'message:outbound',
		(peerPubkey: string, type: number, payload: Buffer) => {
			if (peerPubkey === pubkeyA) {
				managerA.handleMessage(pubkeyB, type, payload);
			}
		}
	);
}

describe('Channel Manager', function () {
	const aliceConfig = makeConfig(1);
	const bobConfig = makeConfig(2);
	const alicePubkey = aliceConfig.localBasepoints.fundingPubkey.toString('hex');
	const bobPubkey = bobConfig.localBasepoints.fundingPubkey.toString('hex');

	function createConnectedManagers(): {
		alice: ChannelManager;
		bob: ChannelManager;
	} {
		const alice = new ChannelManager(aliceConfig);
		const bob = new ChannelManager(bobConfig);
		connectManagers(alice, alicePubkey, bob, bobPubkey);
		return { alice, bob };
	}

	/**
	 * Helper: Open a channel through managers, create funding, confirm, and reach NORMAL.
	 */
	function openAndReadyChannel(): {
		alice: ChannelManager;
		bob: ChannelManager;
		channelId: Buffer;
	} {
		const { alice, bob } = createConnectedManagers();

		// Alice opens channel (triggers open_channel → accept_channel via loopback)
		const channel = alice.openChannel(bobPubkey, 1_000_000n);

		// Alice creates funding (triggers funding_created → funding_signed via loopback)
		const fundingTxid = crypto.randomBytes(32);
		const channelId = alice.createFunding(
			channel,
			fundingTxid,
			0,
			crypto.randomBytes(64)
		)!;

		// Both confirm funding (triggers channel_ready exchange via loopback)
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);

		return { alice, bob, channelId };
	}

	describe('Channel Opening via ChannelManager', function () {
		it('should open a channel between two managers', function () {
			const { alice } = createConnectedManagers();

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			expect(channel).to.exist;

			// After loopback: open_channel → accept_channel processed
			expect(channel.getState()).to.equal(ChannelState.SENT_ACCEPT);
		});

		it('should reject open_channel for a different chain', function () {
			// Bob operates on a different chain than Alice's open_channel targets
			const bobRegtest = new ChannelManager({
				...makeConfig(2),
				chainHash: crypto.createHash('sha256').update('other-chain').digest()
			});
			const alice = new ChannelManager(makeConfig(1));
			connectManagers(alice, alicePubkey, bobRegtest, bobPubkey);

			const errors: string[] = [];
			bobRegtest.on('error', (_id: Buffer, message: string) =>
				errors.push(message)
			);

			const channel = alice.openChannel(bobPubkey, 1_000_000n);

			// Bob rejected the open: no accept_channel came back
			expect(channel.getState()).to.equal(ChannelState.SENT_OPEN);
			expect(errors.length).to.equal(1);
			expect(errors[0]).to.include('unknown chain');
		});

		it('discards a channel whose open_channel names a hostile dust limit (issue 381)', function () {
			// The acceptor state is seeded from the peer's message before
			// Channel.handleOpenChannel ever runs, so what makes the refusal safe
			// is that the ERROR action drops the temporary channel outright. If
			// it survived, buildRemoteCommitment would trim our to_remote output
			// at the peer's dust limit in every commitment we sign (FS-1).
			//
			// Alice's own dust limit is what she advertises, and it is deliberately
			// NOT bounded on the send path: the bound belongs to values we did not
			// choose.
			const alice = new ChannelManager({
				...makeConfig(1),
				localConfig: { ...DEFAULT_CHANNEL_CONFIG, dustLimitSatoshis: 3_000n }
			});
			const bob = new ChannelManager(makeConfig(2));
			connectManagers(alice, alicePubkey, bob, bobPubkey);

			const errors: string[] = [];
			bob.on('error', (_id: Buffer | null, message: string) =>
				errors.push(message)
			);
			// Bob's refusal now reaches Alice, and a ChannelManager with no 'error'
			// listener throws ERR_UNHANDLED_ERROR out of handleErrorMsg, which would
			// surface back on Bob's side as a second error.
			const aliceErrors: string[] = [];
			alice.on('error', (_id: Buffer | null, message: string) =>
				aliceErrors.push(message)
			);
			const wire: number[] = [];
			bob.on('message:outbound', (_peer: string, type: number) =>
				wire.push(type)
			);

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const tempId = channel.getTemporaryChannelId();

			expect(errors.length).to.equal(1);
			expect(errors[0]).to.include(
				'dust_limit_satoshis 3000 exceeds maximum 1062'
			);
			expect(bob.listChannels()).to.have.length(0);
			expect(bob.getTempChannel(tempId), 'acceptor dropped it').to.equal(
				undefined
			);

			// The refusal reached the OPENER (issue 381): without it Alice keeps a
			// live negotiation Bob has already forgotten, retrying an open that can
			// never be accepted.
			expect(wire, 'exactly one wire error, and nothing else').to.deep.equal([
				MessageType.ERROR
			]);
			expect(
				aliceErrors.some((m) => m.includes('exceeds maximum 1062')),
				'the opener learned why'
			).to.equal(true);
			expect(alice.getTempChannel(tempId), 'opener forgot it too').to.equal(
				undefined
			);
			// The Channel object keeps its historical state: a v1 open dropped this
			// way is deliberately not marked ERRORED. What changed is that the
			// manager no longer tracks it.
			expect(channel.getState()).to.equal(ChannelState.SENT_OPEN);
		});

		it('discards a channel whose open_channel names a hostile reserve (issue 391)', function () {
			// An opener demanding a reserve near the whole capacity leaves the
			// acceptor a channel it can receive into and never spend from. A real
			// beignet opener always computes its reserve (capped at 20%), so the
			// hostile value is injected by capturing and tampering the message.
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));

			let openPayload: Buffer | null = null;
			alice.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					if (type === MessageType.OPEN_CHANNEL) openPayload = payload;
				}
			);
			const errors: string[] = [];
			bob.on('error', (_id: Buffer | null, message: string) =>
				errors.push(message)
			);
			const wire: number[] = [];
			bob.on('message:outbound', (_peer: string, type: number) =>
				wire.push(type)
			);

			alice.openChannel(bobPubkey, 1_000_000n);
			const open = decodeOpenChannelMessage(openPayload!);
			open.channelReserveSatoshis = 800_000n;
			bob.handleMessage(
				alicePubkey,
				MessageType.OPEN_CHANNEL,
				encodeOpenChannelMessage(open)
			);

			expect(errors.length).to.equal(1);
			expect(errors[0]).to.include(
				'channel_reserve_satoshis 800000 exceeds maximum 200000'
			);
			// The refusal is wire-visible, scoped to the id the opener chose.
			expect(wire).to.deep.equal([MessageType.ERROR]);
			expect(bob.getTempChannel(open.temporaryChannelId)).to.equal(undefined);
			expect(bob.listChannels()).to.have.length(0);
		});

		it('drops an open_channel under the reserved all-zero id, silently (issue 381)', function () {
			// Every other refusal is now scoped to the id the opener chose, and
			// BOLT 1 reserves the all-zero one for every channel with the peer, so
			// answering this one would read as "fail all of them". Refused before
			// any key is derived or any state retained, and without a wire error.
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));

			// Alice is not wired to Bob: her open_channel is captured and replayed
			// under the reserved id, which no honest opener would send.
			let openPayload: Buffer | null = null;
			alice.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					if (type === MessageType.OPEN_CHANNEL) openPayload = payload;
				}
			);
			const errors: string[] = [];
			bob.on('error', (_id: Buffer | null, message: string) =>
				errors.push(message)
			);
			const wire: number[] = [];
			bob.on('message:outbound', (_peer: string, type: number) =>
				wire.push(type)
			);

			alice.openChannel(bobPubkey, 1_000_000n);
			expect(openPayload, 'captured the open_channel').to.not.equal(null);
			const open = decodeOpenChannelMessage(openPayload!);
			open.temporaryChannelId = Buffer.alloc(32, 0x00);
			bob.handleMessage(
				alicePubkey,
				MessageType.OPEN_CHANNEL,
				encodeOpenChannelMessage(open)
			);

			expect(errors.length).to.equal(1);
			expect(errors[0]).to.include('all-zero id');
			expect(wire, 'no connection-wide error goes out').to.deep.equal([]);
			expect(bob.getTempChannel(open.temporaryChannelId)).to.equal(undefined);
			expect(bob.listChannels()).to.have.length(0);
		});

		it('never widens an all-zero id refusal, whichever arm fires (issue 381)', function () {
			// The guard has to precede the chain, namespace and duplicate-id
			// refusals, not just the ones inside Channel: those three are
			// wire-visible too, and an all-zero id combined with any of them would
			// put a connection-wide error on the wire, telling the peer to fail
			// every channel it has with us. refuseInboundOpen suppresses it a
			// second time, so the v2 arms that route through it are covered as
			// well as anything added later.
			const alice = new ChannelManager(makeConfig(1));
			let openPayload: Buffer | null = null;
			alice.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					if (type === MessageType.OPEN_CHANNEL) openPayload = payload;
				}
			);
			alice.openChannel(bobPubkey, 1_000_000n);
			const open = decodeOpenChannelMessage(openPayload!);
			open.temporaryChannelId = Buffer.alloc(32, 0x00);
			let derived = 0;

			// Each of these makes a DIFFERENT refusal arm fire ahead of the one
			// inside Channel.handleOpenChannel.
			const countingKeys = (): Partial<IChannelManagerConfig> => ({
				channelKeyDeriver: (index: number) => {
					derived++;
					const seed = makeSeed(200 + index);
					return {
						basepoints: makeBasepoints(seed),
						perCommitmentSeed: seed,
						fundingPrivkey: seed,
						htlcBasepointSecret: seed
					};
				}
			});
			const arms: Array<[string, () => ChannelManager]> = [
				[
					'unknown chain',
					(): ChannelManager =>
						new ChannelManager({
							...makeConfig(2),
							...countingKeys(),
							chainHash: crypto
								.createHash('sha256')
								.update('other-chain')
								.digest()
						})
				],
				[
					'ordinary acceptor',
					(): ChannelManager =>
						new ChannelManager({ ...makeConfig(2), ...countingKeys() })
				]
			];

			for (const [label, build] of arms) {
				const bob = build();
				derived = 0;
				const wire: number[] = [];
				const errors: string[] = [];
				bob.on('message:outbound', (_peer: string, type: number) =>
					wire.push(type)
				);
				bob.on('error', (_id: Buffer | null, message: string) =>
					errors.push(message)
				);
				bob.handleMessage(
					alicePubkey,
					MessageType.OPEN_CHANNEL,
					encodeOpenChannelMessage(open)
				);
				expect(wire, `${label}: nothing on the wire`).to.deep.equal([]);
				expect(errors.length, `${label}: refused locally`).to.equal(1);
				expect(bob.listChannels(), `${label}: no channel`).to.have.length(0);
				// And the drop precedes the work: an id we can never answer under
				// must not burn a channel key index on its way to being refused.
				expect(derived, `${label}: no channel keys derived`).to.equal(0);
			}
		});

		it('should reach AWAITING_FUNDING_CONFIRMED after funding', function () {
			const { alice } = createConnectedManagers();

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const fundingTxid = crypto.randomBytes(32);
			alice.createFunding(channel, fundingTxid, 0, crypto.randomBytes(64));

			// After loopback: funding_created → funding_signed processed
			expect(channel.getState()).to.equal(
				ChannelState.AWAITING_FUNDING_CONFIRMED
			);
		});

		it('should reach NORMAL after funding confirmed and channel_ready exchange', function () {
			const { alice, channelId } = openAndReadyChannel();

			const aliceChannel = alice.getChannel(channelId)!;
			expect(aliceChannel.getState()).to.equal(ChannelState.NORMAL);
		});

		it('should emit channel:ready event', function () {
			const { alice, bob } = createConnectedManagers();

			const events: string[] = [];
			alice.on('channel:ready', () => events.push('alice-ready'));
			bob.on('channel:ready', () => events.push('bob-ready'));

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const fundingTxid = crypto.randomBytes(32);
			const channelId = alice.createFunding(
				channel,
				fundingTxid,
				0,
				crypto.randomBytes(64)
			)!;

			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);

			expect(events).to.include('alice-ready');
			expect(events).to.include('bob-ready');
		});
	});

	describe('Channel Lookup', function () {
		it('should find channel by ID after funding', function () {
			const { alice, channelId } = openAndReadyChannel();
			const found = alice.getChannel(channelId);
			expect(found).to.exist;
		});

		it('should find channels by peer', function () {
			const { alice } = openAndReadyChannel();
			const channels = alice.getChannelsByPeer(bobPubkey);
			expect(channels.length).to.be.greaterThanOrEqual(1);
		});

		it('should list all channels', function () {
			const { alice } = openAndReadyChannel();
			const channels = alice.listChannels();
			expect(channels.length).to.be.greaterThanOrEqual(1);
		});
	});

	describe('Message Dispatch', function () {
		it('should handle unknown channel_id gracefully', function () {
			const { alice } = createConnectedManagers();
			const errors: string[] = [];
			alice.on('error', (_channelId: Buffer | null, msg: string) => {
				errors.push(msg);
			});

			// Send a channel_ready for an unknown channel
			const fakePayload = Buffer.alloc(65);
			fakePayload[32] = 0x02;
			alice.handleMessage(bobPubkey, 36, fakePayload); // CHANNEL_READY=36

			expect(errors.length).to.be.greaterThanOrEqual(1);
		});

		it('should emit channel:opened event', function () {
			const { alice } = createConnectedManagers();

			const events: string[] = [];
			alice.on('channel:opened', () => events.push('opened'));

			alice.openChannel(bobPubkey, 1_000_000n);
			expect(events).to.include('opened');
		});
	});

	describe('HTLC Operations via Manager', function () {
		it('should forward HTLC from alice to bob', function () {
			const { alice, bob, channelId } = openAndReadyChannel();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 50_000_000n;

			let htlcForwarded = false;
			bob.on(
				'htlc:forwarded',
				(_cid: Buffer, _htlcId: bigint, amount: bigint) => {
					htlcForwarded = true;
					expect(amount).to.equal(amountMsat);
				}
			);

			alice.addHtlc(
				channelId,
				amountMsat,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);
			expect(htlcForwarded).to.be.true;
		});

		it('should handle HTLC fulfill across managers', function () {
			const { alice, bob, channelId } = openAndReadyChannel();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 50_000_000n;

			// Alice adds HTLC (routed to Bob via loopback)
			alice.addHtlc(
				channelId,
				amountMsat,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);

			// Bob fulfills (routed back to Alice via loopback)
			let fulfilled = false;
			alice.on('htlc:fulfilled', () => {
				fulfilled = true;
			});

			bob.fulfillHtlc(channelId, 0n, preimage);
			expect(fulfilled).to.be.true;
		});

		it('should handle HTLC fail across managers', function () {
			const { alice, bob, channelId } = openAndReadyChannel();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 50_000_000n;

			alice.addHtlc(
				channelId,
				amountMsat,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);

			let failed = false;
			alice.on('htlc:failed', () => {
				failed = true;
			});

			// Bob fails the HTLC via the channel directly (manager routes it)
			const bobChannel = bob.getChannel(channelId)!;
			const failActions = bobChannel.failHtlc(0n, Buffer.from('rejected'));
			// Process actions manually since we called Channel directly
			for (const action of failActions) {
				if (action.type === 'SEND_MESSAGE') {
					alice.handleMessage(bobPubkey, action.messageType, action.payload);
				}
			}

			expect(failed).to.be.true;
		});

		it('should track balance changes after HTLC fulfill', function () {
			const { alice, bob, channelId } = openAndReadyChannel();

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const amountMsat = 50_000_000n;

			alice.addHtlc(
				channelId,
				amountMsat,
				paymentHash,
				500000,
				crypto.randomBytes(1366)
			);
			bob.fulfillHtlc(channelId, 0n, preimage);

			const aliceChannel = alice.getChannel(channelId)!;
			const bobChannel = bob.getChannel(channelId)!;

			const aliceBal = aliceChannel.getBalances();
			const bobBal = bobChannel.getBalances();

			// Alice sent 50M msat, so her local balance decreased
			expect(aliceBal.localMsat).to.equal(1_000_000_000n - amountMsat);
			// Bob received 50M msat
			expect(bobBal.localMsat).to.equal(amountMsat);
		});
	});

	describe('Cooperative Close via Manager', function () {
		it('should handle shutdown flow', function () {
			const { alice, bob, channelId } = openAndReadyChannel();

			alice.initiateShutdown(
				channelId,
				Buffer.from('0014' + '0'.repeat(40), 'hex')
			);

			const aliceChannel = alice.getChannel(channelId)!;
			const bobChannel = bob.getChannel(channelId)!;

			// After shutdown exchange with no pending HTLCs, the opener auto-sends
			// closing_signed (BOLT 2), so the channel may complete closing immediately
			expect(aliceChannel.getState()).to.be.oneOf([
				ChannelState.SHUTTING_DOWN,
				ChannelState.NEGOTIATING_CLOSING,
				ChannelState.CLOSED
			]);
			expect(bobChannel.getState()).to.be.oneOf([
				ChannelState.SHUTTING_DOWN,
				ChannelState.NEGOTIATING_CLOSING,
				ChannelState.CLOSED
			]);
		});

		it('responds to a peer shutdown using the configured wallet destination', function () {
			const { alice, bob, channelId } = openAndReadyChannel();

			// Bob has a wallet-owned sweep/close destination configured.
			const walletScript = Buffer.from('0014' + 'ab'.repeat(20), 'hex');
			bob.setMonitorDestinationScript(walletScript);

			// Alice initiates cooperative close; Bob must respond with HIS shutdown,
			// which should use the wallet destination — not P2WPKH(funding_pubkey).
			alice.initiateShutdown(
				channelId,
				Buffer.from('0014' + '0'.repeat(40), 'hex')
			);

			const bobScript = bob
				.getChannel(channelId)!
				.getFullState().localShutdownScript;
			expect(bobScript).to.deep.equal(walletScript);
		});
	});

	describe('ChannelResult Error Visibility', function () {
		it('addHtlc should return error for unknown channel', function () {
			const { alice } = createConnectedManagers();
			alice.on('error', () => {}); // absorb
			const fakeChannelId = crypto.randomBytes(32);
			const result = alice.addHtlc(
				fakeChannelId,
				1000n,
				crypto.randomBytes(32),
				500,
				crypto.randomBytes(1366)
			);
			expect(result.ok).to.be.false;
			expect(result.actions).to.deep.equal([]);
			expect(result.error).to.include('Channel not found');
		});

		it('fulfillHtlc should return error for unknown channel', function () {
			const { alice } = createConnectedManagers();
			alice.on('error', () => {}); // absorb
			const fakeChannelId = crypto.randomBytes(32);
			const result = alice.fulfillHtlc(
				fakeChannelId,
				0n,
				crypto.randomBytes(32)
			);
			expect(result.ok).to.be.false;
			expect(result.error).to.include('Channel not found');
		});

		it('failHtlc should return error for unknown channel', function () {
			const { alice } = createConnectedManagers();
			alice.on('error', () => {}); // absorb
			const fakeChannelId = crypto.randomBytes(32);
			const result = alice.failHtlc(fakeChannelId, 0n, Buffer.alloc(290));
			expect(result.ok).to.be.false;
			expect(result.error).to.include('Channel not found');
		});

		it('signCommitment should return error for unknown channel', function () {
			const { alice } = createConnectedManagers();
			alice.on('error', () => {}); // absorb
			const fakeChannelId = crypto.randomBytes(32);
			const result = alice.signCommitment(
				fakeChannelId,
				crypto.randomBytes(64),
				[]
			);
			expect(result.ok).to.be.false;
			expect(result.error).to.include('Channel not found');
		});

		it('initiateShutdown should return error for unknown channel', function () {
			const { alice } = createConnectedManagers();
			alice.on('error', () => {}); // absorb
			const fakeChannelId = crypto.randomBytes(32);
			const result = alice.initiateShutdown(
				fakeChannelId,
				crypto.randomBytes(22)
			);
			expect(result.ok).to.be.false;
			expect(result.error).to.include('Channel not found');
		});

		it('forceClose should return error for unknown channel', function () {
			const { alice } = createConnectedManagers();
			alice.on('error', () => {}); // absorb
			const fakeChannelId = crypto.randomBytes(32);
			const result = alice.forceClose(fakeChannelId, crypto.randomBytes(22));
			expect(result.ok).to.be.false;
			expect(result.error).to.include('Channel not found');
		});

		it('should emit error event on channel-not-found', function () {
			const { alice } = createConnectedManagers();
			const errors: string[] = [];
			alice.on('error', (_channelId: Buffer | null, msg: string) =>
				errors.push(msg)
			);

			alice.addHtlc(
				crypto.randomBytes(32),
				1000n,
				crypto.randomBytes(32),
				500,
				crypto.randomBytes(1366)
			);
			expect(errors.length).to.equal(1);
			expect(errors[0]).to.include('Channel not found');
		});

		it('addHtlc should return ok: true for valid channel', function () {
			const { alice, channelId } = openAndReadyChannel();
			const result = alice.addHtlc(
				channelId,
				50_000_000n,
				crypto.randomBytes(32),
				500000,
				crypto.randomBytes(1366)
			);
			expect(result.ok).to.be.true;
			expect(result.actions.length).to.be.greaterThan(0);
		});
	});

	describe('Multiple Channels', function () {
		it('should manage multiple channels to same peer', function () {
			const { alice } = createConnectedManagers();

			const ch1 = alice.openChannel(bobPubkey, 500_000n);
			const ch2 = alice.openChannel(bobPubkey, 1_000_000n);

			expect(ch1.getFundingSatoshis()).to.equal(500_000n);
			expect(ch2.getFundingSatoshis()).to.equal(1_000_000n);
		});

		it('should manage independent channel states', function () {
			const { alice, bob } = createConnectedManagers();

			const ch1 = alice.openChannel(bobPubkey, 500_000n);
			const ch2 = alice.openChannel(bobPubkey, 1_000_000n);

			// Fund only ch1
			const cid1 = alice.createFunding(
				ch1,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			)!;
			alice.handleFundingConfirmed(cid1);
			bob.handleFundingConfirmed(cid1);

			// ch1 should be NORMAL, ch2 still in opening
			expect(ch1.getState()).to.equal(ChannelState.NORMAL);
			expect(ch2.getState()).to.equal(ChannelState.SENT_ACCEPT);
		});
	});

	describe('Reestablish edge handling', function () {
		function makeReestablishPayload(channelId: Buffer): Buffer {
			const {
				encodeChannelReestablishMessage
			} = require('../../src/lightning/message/channel-reestablish');
			return encodeChannelReestablishMessage({
				channelId,
				nextCommitmentNumber: 1n,
				nextRevocationNumber: 0n,
				yourLastPerCommitmentSecret: Buffer.alloc(32),
				myCurrentPerCommitmentPoint: getPublicKey(makeSeed(99))
			});
		}

		it('replies with error to reestablish for an unknown channel', function () {
			const alice = new ChannelManager(aliceConfig);
			const sent: Array<{ type: number; payload: Buffer }> = [];
			alice.on(
				'message:outbound',
				(_peer: string, type: number, payload: Buffer) => {
					sent.push({ type, payload });
				}
			);

			alice.handleMessage(
				bobPubkey,
				136,
				makeReestablishPayload(crypto.randomBytes(32))
			);

			expect(sent).to.have.length(1);
			expect(sent[0].type).to.equal(17); // ERROR
			expect(sent[0].payload.toString('utf8')).to.include(
				'unknown or closed channel'
			);
		});

		it('replies with error to reestablish for a force-closed channel', function () {
			const { alice, bob, channelId } = openAndReadyChannel();
			alice.on('error', () => {
				/* observed via messages */
			});
			bob.on('error', () => {
				/* loopback delivers alice's error to bob */
			});
			alice.getChannel(channelId)!.getFullState().state =
				ChannelState.FORCE_CLOSED;

			const sent: Array<{ type: number }> = [];
			alice.on('message:outbound', (_peer: string, type: number) => {
				sent.push({ type });
			});
			alice.handleMessage(bobPubkey, 136, makeReestablishPayload(channelId));

			expect(
				sent.some((m) => m.type === 17),
				'BOLT 1 error sent'
			).to.be.true;
		});

		it('retransmits channel_reestablish once when the peer reestablishes again on the same connection', function () {
			const { alice, channelId } = openAndReadyChannel();
			alice.on('error', () => {
				/* not asserted here */
			});

			// Complete the normal reestablish exchange from alice's perspective.
			alice.handlePeerDisconnected(bobPubkey);
			alice.removeAllListeners('message:outbound'); // detach the loopback
			alice.handleMessage(bobPubkey, 136, makeReestablishPayload(channelId));
			expect(alice.getChannel(channelId)!.getState()).to.equal(
				ChannelState.NORMAL
			);

			// The peer's node restarts its channel process on the same connection
			// (CLN does this after a tx_abort exchange) and reestablishes again.
			const sent: Array<{ type: number }> = [];
			alice.on('message:outbound', (_peer: string, type: number) => {
				sent.push({ type });
			});
			alice.handleMessage(bobPubkey, 136, makeReestablishPayload(channelId));

			expect(
				sent.some((m) => m.type === 136),
				'our reestablish retransmitted'
			).to.be.true;
			expect(
				sent.some((m) => m.type === 17),
				'no error for the re-reestablish'
			).to.be.false;
			expect(alice.getChannel(channelId)!.getState()).to.equal(
				ChannelState.NORMAL
			);

			// The retransmit is latched: a third reestablish gets no further copy
			// (two retransmitting peers must not ping-pong forever).
			sent.length = 0;
			alice.handleMessage(bobPubkey, 136, makeReestablishPayload(channelId));
			expect(
				sent.some((m) => m.type === 136),
				'no second retransmit'
			).to.be.false;
		});

		it('registers BOLT 1 error and warning handlers on attach', function () {
			const alice = new ChannelManager(aliceConfig);
			const registered: number[] = [];
			const fakePeerManager = {
				onMessage: (type: number, _handler: unknown) => registered.push(type)
			};
			alice.attachToPeerManager(fakePeerManager as never);
			expect(registered).to.include(17); // ERROR
			expect(registered).to.include(1); // WARNING
		});

		it('marks the channel ERRORED on a remote channel-specific error', function () {
			const { alice, channelId } = openAndReadyChannel();
			alice.on('error', () => {
				/* surfacing tested separately */
			});
			const payload = encodeErrorMessage({
				channelId,
				data: Buffer.from('it broke', 'utf8')
			});
			alice.handleMessage(bobPubkey, 17, payload);
			expect(alice.getChannel(channelId)!.getState()).to.equal(
				ChannelState.ERRORED
			);
		});

		it('surfaces a remote warning without failing the channel', function () {
			const { alice, channelId } = openAndReadyChannel();
			const warnings: string[] = [];
			alice.on('error', (_cid: Buffer | null, message: string) =>
				warnings.push(message)
			);
			alice.handleMessage(
				bobPubkey,
				1,
				encodeErrorMessage({
					channelId,
					data: Buffer.from('feerate too low', 'utf8')
				})
			);
			expect(
				warnings.some((w) => w.includes('Remote warning: feerate too low'))
			).to.be.true;
			expect(alice.getChannel(channelId)!.getState()).to.equal(
				ChannelState.NORMAL
			);
		});
	});

	describe('the rest of the v1 handshake reaches the peer (issue 393)', function () {
		// A bare ERROR action never becomes bytes, so before this each of these
		// refusals deleted our half of the negotiation while the peer stayed parked
		// on a message it would never get an answer to.

		/** Loopback that lets a test rewrite one message type in flight. */
		function connectWithTamper(
			a: ChannelManager,
			pubA: string,
			b: ChannelManager,
			pubB: string,
			tamper: (type: number, payload: Buffer) => Buffer
		): void {
			a.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer === pubB) b.handleMessage(pubA, type, tamper(type, payload));
				}
			);
			b.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer === pubA) a.handleMessage(pubB, type, tamper(type, payload));
				}
			);
		}

		function flipByte(payload: Buffer, offset: number): Buffer {
			const copy = Buffer.from(payload);
			copy[offset] ^= 0xff;
			return copy;
		}

		it('an accept_channel we cannot license is refused ON THE WIRE', function () {
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));
			const errors: Record<string, string[]> = { alice: [], bob: [] };
			alice.on('error', (_id: Buffer | null, m: string) =>
				errors.alice.push(m)
			);
			bob.on('error', (_id: Buffer | null, m: string) => errors.bob.push(m));
			const wire: Array<{ type: number; payload: Buffer }> = [];
			alice.on(
				'message:outbound',
				(_p: string, type: number, payload: Buffer) =>
					wire.push({ type, payload })
			);
			const accepted: Buffer[] = [];
			alice.on('channel:accepted', (ch: { getChannelId(): Buffer | null }) =>
				accepted.push(ch.getChannelId() ?? Buffer.alloc(0))
			);

			connectWithTamper(alice, alicePubkey, bob, bobPubkey, (type, payload) => {
				if (type !== MessageType.ACCEPT_CHANNEL) return payload;
				// BOLT 2: accept_channel MUST echo the type open_channel set.
				const msg = decodeAcceptChannelMessage(payload);
				msg.channelType = undefined;
				return encodeAcceptChannelMessage(msg);
			});

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const tempId = channel.getTemporaryChannelId();

			const sentErrors = wire.filter((w) => w.type === MessageType.ERROR);
			expect(
				sentErrors,
				'exactly one wire error to the acceptor'
			).to.have.length(1);
			const decoded = decodeErrorMessage(sentErrors[0].payload);
			expect(
				decoded.channelId.equals(tempId),
				'scoped to the temporary id, not connection-wide'
			).to.equal(true);
			expect(decoded.data.toString('ascii')).to.include('omitted channel_type');

			// Both sides forget the negotiation, and no funding is ever built.
			expect(alice.getTempChannel(tempId), 'opener dropped it').to.equal(
				undefined
			);
			expect(bob.getTempChannel(tempId), 'acceptor dropped it').to.equal(
				undefined
			);
			expect(
				accepted,
				'no channel:accepted for a refused accept'
			).to.have.length(0);
			expect(
				errors.bob.some((m) => m.includes('omitted channel_type')),
				'the acceptor learned why'
			).to.equal(true);
		});

		it('a funding_created we cannot verify is refused ON THE WIRE', function () {
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));
			const errors: string[] = [];
			alice.on('error', (_id: Buffer | null, m: string) => errors.push(m));
			bob.on('error', () => undefined);
			const wire: Array<{ type: number; payload: Buffer }> = [];
			bob.on('message:outbound', (_p: string, type: number, payload: Buffer) =>
				wire.push({ type, payload })
			);

			connectWithTamper(alice, alicePubkey, bob, bobPubkey, (type, payload) =>
				// [32 temporary_channel_id][32 txid][2 output_index][64 signature]
				type === MessageType.FUNDING_CREATED ? flipByte(payload, 70) : payload
			);

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const tempId = channel.getTemporaryChannelId();
			alice.createFunding(channel, crypto.randomBytes(32), 0, Buffer.alloc(64));

			const sentErrors = wire.filter((w) => w.type === MessageType.ERROR);
			expect(sentErrors, 'exactly one wire error to the opener').to.have.length(
				1
			);
			const decoded = decodeErrorMessage(sentErrors[0].payload);
			expect(
				decoded.channelId.equals(tempId),
				'scoped to the id the opener used'
			).to.equal(true);
			expect(decoded.data.toString('ascii')).to.include(
				'Invalid commitment signature in funding_created'
			);
			expect(
				wire.some((w) => w.type === MessageType.FUNDING_SIGNED),
				'never answered funding_signed'
			).to.equal(false);
			expect(bob.listChannels(), 'never promoted').to.have.length(0);
			expect(bob.getTempChannel(tempId), 'acceptor dropped it').to.equal(
				undefined
			);
			expect(
				errors.some((m) => m.includes('Invalid commitment signature')),
				'the opener learned why'
			).to.equal(true);
		});

		it('a REPLAYED accept_channel leaves the healthy negotiation alone', function () {
			// The state guard is local-only so a wire error cannot cancel an open the
			// peer believes is healthy. But the manager drops the temporary channel
			// for EVERY local ERROR, so without cleanup 'none' the local half deleted
			// the very negotiation the guard exists to protect.
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));
			alice.on('error', () => undefined);
			bob.on('error', () => undefined);
			let acceptPayload: Buffer | null = null;
			connectManagers(alice, alicePubkey, bob, bobPubkey);
			bob.on(
				'message:outbound',
				(_p: string, type: number, payload: Buffer) => {
					if (type === MessageType.ACCEPT_CHANNEL) acceptPayload = payload;
				}
			);

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			const tempId = channel.getTemporaryChannelId();
			expect(acceptPayload, 'captured the accept').to.not.equal(null);
			expect(alice.getTempChannel(tempId), 'tracked after the accept').to.equal(
				channel
			);

			const wire: number[] = [];
			alice.on('message:outbound', (_p: string, type: number) =>
				wire.push(type)
			);
			alice.handleMessage(
				bobPubkey,
				MessageType.ACCEPT_CHANNEL,
				acceptPayload as unknown as Buffer
			);

			expect(wire, 'nothing on the wire').to.have.length(0);
			expect(
				alice.getTempChannel(tempId),
				'the negotiation survives the replay'
			).to.equal(channel);
		});

		it('a refused funding_signed drops the PROMOTED registration too', async function () {
			// createFunding promotes the opener to its permanent id, so with QUEUED
			// delivery (a real socket) funding_signed arrives after the promotion and
			// the temporary-id drop finds nothing. Without cleanup 'lifecycle' the
			// opener stayed in this.channels in SENT_FUNDING_CREATED forever:
			// refused at the peer, immortal locally.
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));
			alice.on('error', () => undefined);
			bob.on('error', () => undefined);

			const queue: Array<() => void> = [];
			const drain = async (): Promise<void> => {
				while (queue.length) queue.shift()!();
				await new Promise((r) => setImmediate(r));
			};
			alice.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== bobPubkey) return;
					queue.push(() => bob.handleMessage(alicePubkey, type, payload));
				}
			);
			bob.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== alicePubkey) return;
					const tampered =
						type === MessageType.FUNDING_SIGNED
							? (() => {
									// [32 channel_id][64 signature]
									const copy = Buffer.from(payload);
									copy[40] ^= 0xff;
									return copy;
							  })()
							: payload;
					queue.push(() => alice.handleMessage(bobPubkey, type, tampered));
				}
			);

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			await drain();
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				Buffer.alloc(64)
			);
			expect(channelId, 'promoted before funding_signed arrived').to.not.equal(
				null
			);
			expect(
				alice.listChannels().length,
				'promoted while the reply is still queued'
			).to.equal(1);

			await drain();
			await drain();

			expect(
				alice.listChannels(),
				'no permanent SENT_FUNDING_CREATED zombie'
			).to.have.length(0);
			expect(
				alice.getTempChannel(channel.getTemporaryChannelId()),
				'and nothing under the temporary id either'
			).to.equal(undefined);
		});

		it('a refused funding_signed releases the v1 funding input pledges (issue 412)', async function () {
			// Same queued-delivery ordering as above: the refusal lands after the
			// promotion. The registration drop is covered there; this pins the
			// other half of issue 412, that the wallet pledges behind the signed
			// funding tx free immediately rather than staying frozen until some
			// future funding selection prunes them.
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));
			alice.on('error', () => undefined);
			bob.on('error', () => undefined);

			const released: Array<Array<{ txid: string; vout: number }>> = [];
			const provider: IFundingProvider = {
				buildFundingTransaction: async () => {
					throw new Error('unused');
				},
				broadcastTransaction: async () => {
					throw new Error('unused');
				},
				releaseInputPledges: async (outpoints) => {
					released.push(outpoints);
				}
			};
			alice.setFundingProvider(provider);

			const queue: Array<() => void> = [];
			const drain = async (): Promise<void> => {
				while (queue.length) queue.shift()!();
				await new Promise((r) => setImmediate(r));
			};
			alice.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== bobPubkey) return;
					queue.push(() => bob.handleMessage(alicePubkey, type, payload));
				}
			);
			bob.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== alicePubkey) return;
					const tampered =
						type === MessageType.FUNDING_SIGNED
							? (() => {
									// [32 channel_id][64 signature]
									const copy = Buffer.from(payload);
									copy[40] ^= 0xff;
									return copy;
							  })()
							: payload;
					queue.push(() => alice.handleMessage(bobPubkey, type, tampered));
				}
			);

			// The funding tx whose inputs the wallet froze at build time.
			const fundingTx = new bitcoin.Transaction();
			fundingTx.addInput(crypto.randomBytes(32), 0);
			fundingTx.addInput(crypto.randomBytes(32), 1);
			fundingTx.addOutput(
				bitcoin.script.compile([bitcoin.opcodes.OP_0, crypto.randomBytes(20)]),
				1_000_000
			);
			const expected = fundingTx.ins.map((input) => ({
				txid: Buffer.from(input.hash).reverse().toString('hex'),
				vout: input.index
			}));

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			await drain();
			const channelId = alice.createFunding(
				channel,
				fundingTx.getHash(),
				0,
				Buffer.alloc(64)
			);
			expect(channelId, 'promoted before funding_signed arrived').to.not.equal(
				null
			);
			// The node retains the signed tx on channel state right before
			// createFunding (lightning-node handleAutoFunding); mirror it.
			channel.getFullState().pendingFundingTxHex = fundingTx.toHex();

			await drain();
			await drain();

			expect(released, 'released exactly once').to.have.length(1);
			expect(released[0], 'both funding inputs freed').to.deep.equal(expected);
			expect(alice.listChannels()).to.have.length(0);
			// The release must not have failed the channel: nothing is on chain,
			// and a v1 open dropped this way keeps its historical state.
			expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
		});

		it('an UNDECODABLE funding_signed unwinds the promoted open on the wire and releases the pledges', async function () {
			// A funding_signed whose TLV suffix does not decode used to throw in
			// the codec and die in handleMessage's catch: no wire error, no
			// unwind, the promoted registration and its pledges frozen forever
			// (the issue 415 shape at this boundary). The decode guard must take
			// the exact refusal the content arms use at SENT_FUNDING_CREATED:
			// wire error scoped to the promoted id, lifecycle cleanup, pledge
			// release, and deliberately NO persisted ERRORED row.
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));
			alice.on('error', () => undefined);
			bob.on('error', () => undefined);

			const released: Array<Array<{ txid: string; vout: number }>> = [];
			let broadcastRequested = false;
			const provider: IFundingProvider = {
				buildFundingTransaction: async () => {
					throw new Error('unused');
				},
				broadcastTransaction: async () => {
					broadcastRequested = true;
					throw new Error('must never broadcast');
				},
				releaseInputPledges: async (outpoints) => {
					released.push(outpoints);
				}
			};
			alice.setFundingProvider(provider);

			const queue: Array<() => void> = [];
			const drain = async (): Promise<void> => {
				while (queue.length) queue.shift()!();
				await new Promise((r) => setImmediate(r));
			};
			const aliceWire: Array<{ type: number; payload: Buffer }> = [];
			alice.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== bobPubkey) return;
					aliceWire.push({ type, payload });
					queue.push(() => bob.handleMessage(alicePubkey, type, payload));
				}
			);
			bob.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== alicePubkey) return;
					const tampered =
						type === MessageType.FUNDING_SIGNED
							? // TLV type 2 declaring 98 bytes with only 1 present: the
							  // decoder throws before any handler content check runs.
							  Buffer.concat([payload, Buffer.from([0x02, 0x62, 0x01])])
							: payload;
					queue.push(() => alice.handleMessage(bobPubkey, type, tampered));
				}
			);

			const fundingTx = new bitcoin.Transaction();
			fundingTx.addInput(crypto.randomBytes(32), 0);
			fundingTx.addInput(crypto.randomBytes(32), 1);
			fundingTx.addOutput(
				bitcoin.script.compile([bitcoin.opcodes.OP_0, crypto.randomBytes(20)]),
				1_000_000
			);
			const expected = fundingTx.ins.map((input) => ({
				txid: Buffer.from(input.hash).reverse().toString('hex'),
				vout: input.index
			}));

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			await drain();
			const channelId = alice.createFunding(
				channel,
				fundingTx.getHash(),
				0,
				Buffer.alloc(64)
			);
			expect(channelId, 'promoted before funding_signed arrived').to.not.equal(
				null
			);
			channel.getFullState().pendingFundingTxHex = fundingTx.toHex();

			await drain();
			await drain();

			// The peer was told, scoped to the promoted channel id.
			const wireErrors = aliceWire
				.filter((m) => m.type === MessageType.ERROR)
				.map((m) => decodeErrorMessage(m.payload));
			expect(wireErrors, 'exactly one wire error').to.have.length(1);
			expect(wireErrors[0].channelId.equals(channelId!)).to.equal(true);
			expect(wireErrors[0].data.toString('ascii')).to.contain(
				'Undecodable funding_signed'
			);
			// Full lifecycle unwind, pledges freed, nothing ever broadcast.
			expect(released, 'released exactly once').to.have.length(1);
			expect(released[0], 'both funding inputs freed').to.deep.equal(expected);
			expect(alice.listChannels()).to.have.length(0);
			expect(alice.getTempChannel(channel.getTemporaryChannelId())).to.equal(
				undefined
			);
			expect(broadcastRequested, 'no broadcast authorization').to.equal(false);
			// Same no-ERRORED-row rule as the decoded refusal: nothing was ever
			// persisted in SENT_FUNDING_CREATED, so nothing may start being.
			expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
		});

		it('an error quoting the TEMPORARY id fails the promoted channel, owner only (issue 412)', async function () {
			// A refusal of funding_created quotes the temporary id (the only id
			// that message carries), but with queued transport it lands after
			// the promotion. The resolver used to drop it silently, leaving the
			// channel in SENT_FUNDING_CREATED forever with its pledges renewing
			// every block.
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));
			const carolPubkey =
				makeConfig(3).localBasepoints.fundingPubkey.toString('hex');
			alice.on('error', () => undefined);
			bob.on('error', () => undefined);

			const queue: Array<() => void> = [];
			const drain = async (): Promise<void> => {
				while (queue.length) queue.shift()!();
				await new Promise((r) => setImmediate(r));
			};
			alice.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== bobPubkey) return;
					queue.push(() => bob.handleMessage(alicePubkey, type, payload));
				}
			);
			bob.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== alicePubkey) return;
					// Withhold funding_signed: bob "refuses" with the error below.
					if (type === MessageType.FUNDING_SIGNED) return;
					queue.push(() => alice.handleMessage(bobPubkey, type, payload));
				}
			);

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			await drain();
			const channelId = alice.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				Buffer.alloc(64)
			);
			await drain();
			expect(channelId, 'promoted').to.not.equal(null);
			const tempId = channel.getTemporaryChannelId();

			// A third party quoting the temporary id must not fail it.
			alice.handleMessage(
				carolPubkey,
				17, // ERROR
				encodeErrorMessage({ channelId: tempId, data: Buffer.from('nope') })
			);
			expect(channel.getState()).to.equal(ChannelState.SENT_FUNDING_CREATED);

			// The owner's refusal must, even under the pre-promotion id.
			alice.handleMessage(
				bobPubkey,
				17, // ERROR
				encodeErrorMessage({ channelId: tempId, data: Buffer.from('nope') })
			);
			expect(channel.getState()).to.equal(ChannelState.ERRORED);
		});

		it('a disconnect retires a promoted SENT_FUNDING_CREATED opener and frees its pledges (issue 412)', async function () {
			// The promoted opener has left tempChannels, so the early-state
			// disconnect sweep never saw it, and markForReestablish does
			// nothing for SENT_FUNDING_CREATED (BOLT 2 has no reestablish
			// before funding_signed). Without the explicit arm it sat in the
			// permanent map forever with its pledges renewing every block.
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));
			alice.on('error', () => undefined);
			bob.on('error', () => undefined);

			const released: Array<Array<{ txid: string; vout: number }>> = [];
			alice.setFundingProvider({
				buildFundingTransaction: async () => {
					throw new Error('unused');
				},
				broadcastTransaction: async () => {
					throw new Error('unused');
				},
				releaseInputPledges: async (outpoints) => {
					released.push(outpoints);
				}
			});

			const queue: Array<() => void> = [];
			const drain = async (): Promise<void> => {
				while (queue.length) queue.shift()!();
				await new Promise((r) => setImmediate(r));
			};
			alice.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== bobPubkey) return;
					queue.push(() => bob.handleMessage(alicePubkey, type, payload));
				}
			);
			bob.on(
				'message:outbound',
				(peer: string, type: number, payload: Buffer) => {
					if (peer !== alicePubkey) return;
					queue.push(() => alice.handleMessage(bobPubkey, type, payload));
				}
			);

			const fundingTx = new bitcoin.Transaction();
			fundingTx.addInput(crypto.randomBytes(32), 0);
			fundingTx.addOutput(
				bitcoin.script.compile([bitcoin.opcodes.OP_0, crypto.randomBytes(20)]),
				1_000_000
			);
			const expected = fundingTx.ins.map((input) => ({
				txid: Buffer.from(input.hash).reverse().toString('hex'),
				vout: input.index
			}));

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			await drain();
			const channelId = alice.createFunding(
				channel,
				fundingTx.getHash(),
				0,
				Buffer.alloc(64)
			);
			expect(channelId, 'promoted').to.not.equal(null);
			channel.getFullState().pendingFundingTxHex = fundingTx.toHex();

			// The peer disconnects while withholding funding_signed.
			alice.handlePeerDisconnected(bobPubkey);
			await drain();

			expect(alice.listChannels()).to.have.length(0);
			expect(alice.getTempChannel(channel.getTemporaryChannelId())).to.equal(
				undefined
			);
			expect(released).to.deep.equal([expected]);
			// Historical state kept, exactly as a refused funding_signed
			// leaves it: nothing is on chain to be ERRORED about.
			expect(channel.getState()).to.equal(ChannelState.SENT_FUNDING_CREATED);
		});

		it('a funding_signed we cannot verify is refused ON THE WIRE', function () {
			const alice = new ChannelManager(makeConfig(1));
			const bob = new ChannelManager(makeConfig(2));
			const errors: string[] = [];
			alice.on('error', () => undefined);
			bob.on('error', (_id: Buffer | null, m: string) => errors.push(m));
			const wire: Array<{ type: number; payload: Buffer }> = [];
			alice.on(
				'message:outbound',
				(_p: string, type: number, payload: Buffer) =>
					wire.push({ type, payload })
			);
			const authorized: Buffer[] = [];
			alice.on('funding:authorized', (txid: Buffer) => authorized.push(txid));

			connectWithTamper(alice, alicePubkey, bob, bobPubkey, (type, payload) =>
				// [32 channel_id][64 signature]
				type === MessageType.FUNDING_SIGNED ? flipByte(payload, 40) : payload
			);

			const channel = alice.openChannel(bobPubkey, 1_000_000n);
			alice.createFunding(channel, crypto.randomBytes(32), 0, Buffer.alloc(64));
			const permanentId = channel.getChannelId()!;

			const sentErrors = wire.filter((w) => w.type === MessageType.ERROR);
			expect(
				sentErrors,
				'exactly one wire error to the acceptor'
			).to.have.length(1);
			const decoded = decodeErrorMessage(sentErrors[0].payload);
			expect(
				decoded.channelId.equals(permanentId),
				'scoped to the PERMANENT id the acceptor now keys the channel by'
			).to.equal(true);
			expect(decoded.data.toString('ascii')).to.include(
				'Invalid commitment signature in funding_signed'
			);

			// And the refusal does NOT fail the channel: nothing is on chain, so a
			// force close would be a fiction and a persisted ERRORED row immortal.
			expect(channel.getState()).to.not.equal(ChannelState.ERRORED);
			expect(
				authorized,
				'the funding broadcast was never authorized'
			).to.have.length(0);
			expect(
				errors.some((m) => m.includes('Invalid commitment signature')),
				'the acceptor learned why'
			).to.equal(true);
		});
	});
});
