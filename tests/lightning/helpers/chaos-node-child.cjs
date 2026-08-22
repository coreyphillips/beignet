/**
 * Recovery Phase 7: the SIGKILL child (docs/RECOVERY-PROTOCOL.md section 9,
 * Phase 7). A production LightningNode assembly in a dedicated process:
 * real SQLite durability on a persistent file, a real TCP listener the
 * parent's peer connects to, real guardian HTTP transports when a trio is
 * configured. The parent drives scenarios over a stdin line protocol, arms
 * ONE deterministic failpoint per life, and SIGKILLs the process the
 * moment the child reports the boundary was reached.
 *
 * Authored as plain CommonJS against the COMPILED library (dist/) so a
 * spawn costs well under a second; `npm run build` is a prerequisite of
 * the sigkill suite exactly as it already is for the wallet provider
 * tests.
 *
 * Failpoint semantics: the boundary report is written SYNCHRONOUSLY
 * (fs.writeSync straight to fd 1) and then the process enters a busy
 * spin. Nothing after the boundary ever executes, which is the crash
 * shape SIGKILL itself produces, while bytes already handed to the
 * kernel (the armed send) still leave the machine. The parent's SIGKILL
 * lands milliseconds later; a watchdog SIGKILLs from inside if it does
 * not, so no armed child outlives its run.
 *
 * Environment:
 *   CHAOS_DB       path to the SQLite file (shared across lives)
 *   CHAOS_SEED     numeric identity seed (same derivation as the
 *                  in-process chaos harness, so identities are stable
 *                  across lives)
 *   CHAOS_MODE     local | async-remote | quorum
 *   CHAOS_GUARDIANS comma-separated guardian base URLs (quorum and
 *                  replicated async-remote)
 *   CHAOS_REGISTER 1 on the first life of a namespace (ensureNamespace);
 *                  respawns load the persisted writer lease instead
 *   CHAOS_ARM      optional kill label: pre-commit:N | post-commit:N |
 *                  post-send:TYPE:K
 *   CHAOS_TAPROOT  1 to prefer taproot channels
 *   CHAOS_DUAL_FUND 1 to advertise option_dual_fund and carry a funding
 *                  provider, so `openv2` can drive a durable v2 open
 *
 * Line protocol on stdout:
 *   ready:<nodeIdHex>:<port>        the node is listening
 *   evt:commit:<n>                  a recovery commit landed (rehearsal)
 *   evt:send:<type>:<k>             an outbound message left (rehearsal)
 *   reached:<label>                 the armed boundary was hit (then spin)
 *   opened:<channelIdHex>           `open` completed its funding handshake
 *   invoice:<bolt11>:<hashHex>      `invoice` result
 *   paid:<status>                   `pay` settled or failed
 *   dump:<json>                     `dump` result
 *   ok:<command>                    generic command acknowledgment
 *   err:<message>                   command failed
 */

'use strict';
/* eslint-disable @typescript-eslint/no-var-requires */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const readline = require('readline');

const DIST = path.join(__dirname, '..', '..', '..', 'dist');
const { LightningNode } = require(path.join(
	DIST,
	'lightning/node/lightning-node'
));
const { SqliteStorage } = require(path.join(
	DIST,
	'lightning/storage/sqlite-storage'
));
const { getPublicKey } = require(path.join(DIST, 'lightning/crypto/ecdh'));
const { DEFAULT_CHANNEL_CONFIG } = require(path.join(
	DIST,
	'lightning/channel/types'
));
const {
	DurabilityBarrier,
	GuardianClient,
	GuardianReplicator,
	CRASH_V1_PROFILE,
	computeGuardianSetId,
	deriveRecoveryRoot,
	loadWriterLease,
	xOnlyFromSecret
} = require(path.join(DIST, 'lightning/recovery'));

const MESSAGE_NAMES = require(path.join(DIST, 'lightning/message/types'));
const { Feature } = require(path.join(DIST, 'lightning/features/flags'));

const env = process.env;
const DB_PATH = env.CHAOS_DB;
const SEED_ID = Number(env.CHAOS_SEED || '71');
const MODE = env.CHAOS_MODE || 'local';
const ARM = env.CHAOS_ARM || null;
const TAPROOT = env.CHAOS_TAPROOT === '1';
const DUAL_FUND = env.CHAOS_DUAL_FUND === '1';

/** Same key the in-process harness encrypts its chaos databases with. */
const DB_KEY = crypto
	.createHash('sha256')
	.update('beignet-chaos-db-encryption-key')
	.digest();

function out(line) {
	process.stdout.write(line + '\n');
}

/** Report the boundary synchronously, then die where we stand. */
function freeze(label) {
	fs.writeSync(1, `reached:${label}\n`);
	// Watchdog: if the parent's SIGKILL is somehow lost, take ourselves
	// down. alarm-style via a detached timer is impossible inside the spin,
	// so hand the job to the kernel through a second process.
	try {
		require('child_process').spawn(
			process.execPath,
			[
				'-e',
				`setTimeout(()=>{try{process.kill(${process.pid},'SIGKILL')}catch(e){}},15000)`
			],
			{ detached: true, stdio: 'ignore' }
		);
	} catch (e) {
		void e;
	}
	for (;;) {
		// SIGKILL only.
	}
}

function makeSeed(id) {
	return crypto
		.createHash('sha256')
		.update(`beignet-chaos-seed-${id}`)
		.digest();
}

function makeBasepoints(seed) {
	const keys = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
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

const seed = makeSeed(SEED_ID);
const nodePrivateKey = crypto
	.createHash('sha256')
	.update(seed)
	.update(Buffer.from('node-identity'))
	.digest();

let clockNow = BigInt(Date.now()) * 1000n;
const clock = () => ++clockNow;

async function buildRecovery(storage) {
	if (MODE === 'local') return { enabled: true, durability: 'local' };
	const urls = (env.CHAOS_GUARDIANS || '')
		.split(',')
		.map((u) => u.trim())
		.filter(Boolean);
	if (urls.length === 0) {
		return { enabled: true, durability: MODE };
	}
	const secrets = [1, 2, 3].map((i) =>
		crypto.createHash('sha256').update(`p7-sigkill-guardian-${i}`).digest()
	);
	const guardianIds = secrets.map((s) => xOnlyFromSecret(s));
	const setId = computeGuardianSetId({ ...CRASH_V1_PROFILE, guardianIds });
	const context = { guardianSetId: setId, members: guardianIds };
	const guardians = urls.map((url, i) => ({
		expectedGuardianId: guardianIds[i],
		client: new GuardianClient({ url, guardianSetId: setId })
	}));
	const root = deriveRecoveryRoot(nodePrivateKey);
	const replicator = new GuardianReplicator({
		storage,
		guardians,
		context,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: root,
		clock
	});
	let lease = null;
	if (env.CHAOS_REGISTER === '1') {
		const decision = await replicator.ensureNamespace();
		if (decision.outcome !== 'registered') {
			throw new Error(`namespace not registered: ${decision.outcome}`);
		}
		lease = decision.lease;
	} else {
		const loaded = loadWriterLease(storage);
		if (loaded.state !== 'present') {
			throw new Error('no persisted writer lease on respawn');
		}
		lease = loaded.lease;
	}
	const barrier = new DurabilityBarrier({
		durability: MODE,
		replicator,
		lease: () => lease,
		timeoutMs: 20_000,
		retryDelayMs: 40
	});
	return { enabled: true, durability: MODE, barrier };
}

/**
 * A deterministic v2 funding provider: same key, same prevout, same change
 * script every life, so the recorded schedule replays byte-identically.
 * The opener funds through the splice-input surface exactly like the
 * in-process chaos wallet; v1 funding must never run for a v2 open.
 */
function makeV2FundingProvider() {
	const bitcoin = require('bitcoinjs-lib');
	const ecc = require('@bitcoinerlab/secp256k1');
	bitcoin.initEccLib(ecc);
	const tag = (label) =>
		crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from(label))
			.digest();
	const priv = tag('v2-wallet-key');
	const pub = getPublicKey(priv);
	const payment = bitcoin.payments.p2wpkh({ pubkey: pub });
	const prevTx = new bitcoin.Transaction();
	prevTx.version = 2;
	prevTx.addInput(tag('v2-wallet-prev'), 0);
	prevTx.addOutput(payment.output, 1_000_000);
	const scriptCode = bitcoin.payments.p2pkh({ pubkey: pub }).output;
	const walletInput = {
		prevTx: prevTx.toBuffer(),
		prevOutputIndex: 0,
		value: 1_000_000n,
		sequence: 0xfffffffd,
		confirmed: true,
		signWitness: (tx, inputIndex, value) => {
			const sighash = tx.hashForWitnessV0(
				inputIndex,
				scriptCode,
				Number(value),
				bitcoin.Transaction.SIGHASH_ALL
			);
			return [
				bitcoin.script.signature.encode(
					Buffer.from(ecc.sign(sighash, priv)),
					bitcoin.Transaction.SIGHASH_ALL
				),
				pub
			];
		}
	};
	const changeScript = bitcoin.payments.p2wpkh({
		hash: tag('v2-wallet-change').subarray(0, 20)
	}).output;
	return {
		buildFundingTransaction: async () => {
			throw new Error('v1 funding must not run for a v2 open');
		},
		broadcastTransaction: async (txHex) =>
			bitcoin.Transaction.fromHex(txHex).getId(),
		selectSpliceInputs: async () => ({
			inputs: [walletInput],
			changeScript
		})
	};
}

async function main() {
	const storage = new SqliteStorage(DB_PATH, undefined, {
		encryptionKey: DB_KEY
	});
	storage.open();
	const recovery = await buildRecovery(storage);
	// Over real TCP both stacks negotiate option_dual_fund and a v1 open
	// would be routed to the v2 flow. The v1 matrix drives the v1 flow, so
	// by default the victim does not advertise dual-fund; the v2 sweep sets
	// CHAOS_DUAL_FUND=1 and drives the v2 flow through `openv2` instead.
	const localFeatures = LightningNode.defaultFeatures();
	if (!DUAL_FUND) {
		// hasFeature checks the mandatory AND optional bits; clear both.
		localFeatures.clearBit(Feature.DUAL_FUND);
		localFeatures.clearBit(Feature.DUAL_FUND + 1);
	}
	const node = new LightningNode({
		nodePrivateKey,
		localFeatures,
		network: 'bcrt',
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(SEED_ID + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		storage,
		recovery,
		preferTaproot: TAPROOT,
		enableNetworking: true,
		...(DUAL_FUND ? { fundingProvider: makeV2FundingProvider() } : {})
	});
	node.on('error', () => undefined);
	node.on('node:error', (e) => out(`err:node:${(e && e.message) || e}`));
	node.getChannelManager().on('error', (_id, m) => out(`err:mgr:${m}`));
	node.on('peer:connected', (pk) => out(`evt:peer:${String(pk).slice(0, 8)}`));
	if (recovery.barrier) {
		recovery.barrier.kickReplication();
	}

	// ── Failpoints ──
	// Commit tap: the label vocabulary counts recovery commits from process
	// start; the parent replays the identical command sequence every life,
	// which is what makes the ordinals deterministic.
	let commitCount = 0;
	// Sends made from INSIDE a commit (the Recovery Capsule refresh rides
	// the commit's onCommitted hook, so a peer_storage push can leave the
	// socket before realCommit returns) happen after the transaction is
	// durable. Their schedule lines are held until the commit line is out,
	// or the rehearsal would file a durable-after boundary before
	// post-commit:N and classify its kill as an abandonment.
	let commitDepth = 0;
	const deferredSends = [];
	const rec = node.recovery;
	const realCommit = rec.commit.bind(rec);
	rec.commit = (transition) => {
		commitCount++;
		if (ARM === `pre-commit:${commitCount}`) freeze(ARM);
		commitDepth++;
		let result;
		try {
			result = realCommit(transition);
		} finally {
			commitDepth--;
		}
		if (result && result.committed !== false) {
			out(`evt:commit:${commitCount}`);
			if (ARM === `post-commit:${commitCount}`) freeze(ARM);
		}
		for (const line of deferredSends.splice(0)) out(line);
		return result;
	};

	// Send tap: with a real PeerManager the ChannelManager writes straight
	// to the socket via sendToPeer (no event fires), so the tap wraps that
	// method. The real send runs FIRST, so post-send means the bytes were
	// handed to the socket layer before the boundary fires.
	const sendCounts = new Map();
	const pm = node.peerManager;
	const realSend = pm.sendToPeer.bind(pm);
	pm.sendToPeer = (pubkey, type, payload) => {
		realSend(pubkey, type, payload);
		const name = MESSAGE_NAMES.MessageType[type] || String(type);
		const k = (sendCounts.get(name) || 0) + 1;
		sendCounts.set(name, k);
		if (commitDepth > 0) {
			deferredSends.push(`evt:send:${name}:${k}`);
		} else {
			out(`evt:send:${name}:${k}`);
		}
		if (env.CHAOS_DEBUG === '1' && name === 'ERROR') {
			out(
				`dbg:error-payload:${payload
					.toString('latin1')
					.replace(/[^ -~]/g, '.')}`
			);
		}
		if (ARM === `post-send:${name}:${k}`) freeze(ARM);
	};

	await node.listen(0, '127.0.0.1');
	const port = node.peerManager.server.address().port;
	out(`ready:${node.getNodeId()}:${port}`);

	// ── Command loop ──
	const pendingChannels = new Map();
	const rl = readline.createInterface({ input: process.stdin });
	rl.on('line', (line) => {
		void handle(line.trim()).catch((err) => {
			out(`err:${(err && err.message) || String(err)}`);
		});
	});

	async function handle(line) {
		if (!line) return;
		const [cmd, ...args] = line.split(' ');
		if (cmd === 'open') {
			const sats = BigInt(args[0]);
			const peer = args[1];
			const channel = node.openChannel(peer, sats);
			// Over real TCP the accept_channel arrives asynchronously, unlike
			// the in-process loopback. A premature createFunding is not a
			// harmless refusal (its ERROR action tears the temp channel
			// down), so wait for the state to advance out of the freshly
			// opened one before funding.
			const before = channel.getState();
			const deadline = Date.now() + 10_000;
			while (channel.getState() === before) {
				if (Date.now() > deadline) throw new Error('open never accepted');
				await new Promise((resolve) => setTimeout(resolve, 10));
			}
			const channelId = node.createFunding(
				channel,
				crypto.randomBytes(32),
				0,
				crypto.randomBytes(64)
			);
			if (!channelId) throw new Error('createFunding failed');
			pendingChannels.set(channelId.toString('hex'), channel);
			// funding_signed is asynchronous over TCP too; confirming before
			// it arrives lands in the wrong state and is dropped.
			const fundedBy = Date.now() + 10_000;
			while (channel.getState() === 'SENT_FUNDING_CREATED') {
				if (Date.now() > fundedBy) throw new Error('no funding_signed');
				await new Promise((resolve) => setTimeout(resolve, 10));
			}
			node.handleFundingConfirmed(channelId);
			out(`opened:${channelId.toString('hex')}`);
		} else if (cmd === 'openv2') {
			const sats = BigInt(args[0]);
			const peer = args[1];
			const channel = node.openChannelV2(peer, {
				fundingSatoshis: sats,
				fundingFeeratePerkw: 1000
			});
			// The interactive round, both commitment_signeds and both
			// tx_signatures all ride the wire asynchronously; completion is
			// the state leaving the signature exchange.
			const deadline = Date.now() + 30_000;
			while (channel.getState() !== 'AWAITING_FUNDING_CONFIRMED') {
				if (Date.now() > deadline) throw new Error('v2 open never completed');
				await new Promise((resolve) => setTimeout(resolve, 10));
			}
			const channelId = channel.getChannelId();
			pendingChannels.set(channelId.toString('hex'), channel);
			out(`opened:${channelId.toString('hex')}`);
		} else if (cmd === 'confirm') {
			node.handleFundingConfirmed(Buffer.from(args[0], 'hex'));
			out('ok:confirm');
		} else if (cmd === 'invoice') {
			const invoice = node.createInvoice({
				amountMsat: BigInt(args[0]),
				description: 'sigkill',
				hold: args[1] === 'hold'
			});
			out(`invoice:${invoice.bolt11}:${invoice.paymentHash.toString('hex')}`);
		} else if (cmd === 'pay') {
			const payment = node.sendPayment(args[0]);
			const deadline = Date.now() + 15_000;
			const poll = setInterval(() => {
				if (payment.status !== 'PENDING') {
					clearInterval(poll);
					out(`paid:${payment.status}`);
				} else if (Date.now() > deadline) {
					clearInterval(poll);
					out(`paid:TIMEOUT`);
				}
			}, 10);
		} else if (cmd === 'graph') {
			buildGraph(args[0], Number(args[1]));
			out('ok:graph');
		} else if (cmd === 'settlehold') {
			node.settleHeldHtlc(Buffer.from(args[0], 'hex'));
			out('ok:settlehold');
		} else if (cmd === 'cancelhold') {
			node.cancelHoldInvoice(Buffer.from(args[0], 'hex'));
			out('ok:cancelhold');
		} else if (cmd === 'dump') {
			out(`dump:${JSON.stringify(dumpState())}`);
		} else if (cmd === 'quit') {
			// Rehearsal lives end cleanly so the schedule's tail flushes;
			// kill lives never see this command.
			node.destroy();
			process.exit(0);
		} else {
			out(`err:unknown command ${cmd}`);
		}
	}

	function dumpState() {
		return {
			channels: node
				.getChannelManager()
				.listChannels()
				.map((c) => {
					const st = c.getFullState();
					return {
						id: st.channelId ? st.channelId.toString('hex') : null,
						state: st.state,
						localCN: String(st.localCommitmentNumber),
						remoteCN: String(st.remoteCommitmentNumber),
						htlcs: [...st.htlcs.entries()].map(([key, h]) => ({
							key,
							state: h.state
						})),
						splice: !!st.spliceInFlight
					};
				}),
			awaitingDurability: node.getRecoveryStatus().awaitingDurabilityCount
		};
	}

	/** Direct payer graph: one announced channel victim -> peer. */
	function buildGraph(peerPubkeyHex, scidBlock) {
		const gossip = require(path.join(DIST, 'lightning/gossip/types'));
		const channelTypes = require(path.join(DIST, 'lightning/channel/types'));
		const scid = gossip.encodeShortChannelId({
			block: scidBlock,
			txIndex: 1,
			outputIndex: 0
		});
		const me = Buffer.from(node.getNodeId(), 'hex');
		const them = Buffer.from(peerPubkeyHex, 'hex');
		const meIs1 = Buffer.compare(me, them) < 0;
		node.getGraph().addChannelAnnouncement({
			nodeSignature1: Buffer.alloc(64),
			nodeSignature2: Buffer.alloc(64),
			bitcoinSignature1: Buffer.alloc(64),
			bitcoinSignature2: Buffer.alloc(64),
			features: Buffer.alloc(0),
			chainHash: channelTypes.BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			nodeId1: meIs1 ? me : them,
			nodeId2: meIs1 ? them : me,
			bitcoinKey1: Buffer.alloc(33, 2),
			bitcoinKey2: Buffer.alloc(33, 3)
		});
		const update = {
			signature: Buffer.alloc(64),
			chainHash: channelTypes.BITCOIN_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags: 0,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		};
		node.getGraph().applyChannelUpdate(update);
		node.getGraph().applyChannelUpdate({ ...update, channelFlags: 1 });
		node.registerChannelScid(
			node.getChannelManager().listChannels()[0].getChannelId(),
			scid
		);
	}
}

main().catch((err) => {
	out(`err:fatal:${(err && err.stack) || String(err)}`);
	process.exit(1);
});
