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
			const {
				encodeErrorMessage
			} = require('../../src/lightning/message/error');
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
			const {
				encodeErrorMessage
			} = require('../../src/lightning/message/error');
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
});
