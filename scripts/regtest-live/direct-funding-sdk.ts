/**
 * Opt-in qualification against a disposable Bitcoin Core regtest instance.
 * Run: npx ts-node scripts/regtest-live/direct-funding-sdk.ts --run
 *
 * Requires the local btcpayserver/bitcoin:26.0 Docker image. The container has
 * no network, published ports, or host mounts, and its data directory is tmpfs.
 * Wallet coins, PSBT signing, TCP/BOLT8, broadcast, mining, and recovery are real.
 * Receiver channel negotiation uses the deterministic test harness;
 * this does not qualify an actual Lightning channel or a hardware signer.
 */
import assert from 'assert/strict';
import { execFile } from 'child_process';
import { randomBytes } from 'crypto';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { promisify } from 'util';
import * as bitcoin from 'bitcoinjs-lib';
import {
	BitcoinCoreWalletAdapter,
	chainHashForNetwork,
	createPeerTransportRegistry,
	DfTransportType,
	DirectFundingClient,
	Network
} from '../../src/direct-funding';
import type { BitcoinCoreRpc } from '../../src/direct-funding';
import {
	FileDirectFundingStorage,
	NodePeerMessaging
} from '../../src/direct-funding/node';
import {
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BEIGNET_CUSTOM_PROTOCOL_VERSION,
	BeignetCustomSubtype,
	decodeCustomMessage,
	encodeCustomMessage
} from '../../src/lightning/message/custom';
import { Peer } from '../../src/lightning/transport/peer';
import {
	decodeDfOffer,
	decodeDfWitness,
	encodeDfOfferAck,
	encodeDfReceipt
} from '../../src/lightning/direct-funding/messages';
import type { IDfOffer } from '../../src/lightning/direct-funding/messages';
import {
	offerFieldProblem,
	ownershipProblem
} from '../../src/lightning/direct-funding/receiver/verify';
import {
	buildSignRequest,
	mintRequest,
	ScriptedReceiverLane
} from '../../tests/lightning/helpers/df-sender';
import type { IBuiltSignRequest } from '../../tests/lightning/helpers/df-sender';

const execute = promisify(execFile);
const IMAGE = 'btcpayserver/bitcoin:26.0';

async function docker(args: string[]): Promise<string> {
	const { stdout } = await execute('docker', args, {
		encoding: 'utf8',
		maxBuffer: 16 * 1024 * 1024,
		timeout: 60_000
	});
	return stdout.trim();
}

async function main(): Promise<void> {
	if (!process.argv.includes('--run')) {
		throw new Error(
			'Pass --run to create and remove a disposable, offline regtest container'
		);
	}
	const container = `direct-funding-sdk-${randomBytes(8).toString('hex')}`;
	const directory = fs.mkdtempSync(
		path.join(os.tmpdir(), 'direct-funding-regtest-')
	);
	let started = false;
	const servers: net.Server[] = [];
	const acceptedPeers: Peer[] = [];
	const payerPeers: NodePeerMessaging[] = [];
	let cleanupPromise: Promise<void> | undefined;
	const cleanup = (): Promise<void> => {
		if (!cleanupPromise) {
			cleanupPromise = (async (): Promise<void> => {
				try {
					for (const peers of payerPeers) peers.close();
					for (const peer of acceptedPeers) peer.disconnect();
					await Promise.all(
						servers.map(
							(server) =>
								new Promise<void>((resolve) => {
									if (!server.listening) resolve();
									else server.close(() => resolve());
								})
						)
					);
					if (started) await docker(['rm', '--force', container]);
				} finally {
					fs.rmSync(directory, { recursive: true, force: true });
				}
			})();
		}
		return cleanupPromise;
	};
	const interrupted = (): void => {
		void cleanup().finally(() => process.exit(130));
	};
	process.once('SIGINT', interrupted);
	process.once('SIGTERM', interrupted);

	const rpc =
		(wallet?: string): BitcoinCoreRpc =>
		async (method, params = []) => {
			try {
				const raw = await docker([
					'exec',
					container,
					'bitcoin-cli',
					'-datadir=/data',
					'-regtest',
					...(wallet ? [`-rpcwallet=${wallet}`] : []),
					method,
					...params.map((value) =>
						typeof value === 'string' ? value : JSON.stringify(value)
					)
				]);
				if (raw === '') return null;
				try {
					return JSON.parse(raw);
				} catch {
					return raw;
				}
			} catch (error) {
				const failure = error as Error & {
					stderr?: string;
					code?: number | string;
				};
				const code = /error code:\s*(-?\d+)/.exec(failure.stderr ?? '');
				if (code) failure.code = Number(code[1]);
				throw failure;
			}
		};

	try {
		await docker(['image', 'inspect', IMAGE]);
		await docker([
			'run',
			'--detach',
			'--rm',
			'--pull=never',
			'--network',
			'none',
			'--name',
			container,
			'--tmpfs',
			'/data:rw,nosuid,nodev,size=256m',
			IMAGE,
			'bitcoind',
			'-regtest',
			'-server',
			'-listen=0',
			'-dnsseed=0',
			'-discover=0',
			'-txindex=1',
			'-fallbackfee=0.00002',
			'-printtoconsole=0'
		]);
		started = true;
		await docker([
			'exec',
			container,
			'bitcoin-cli',
			'-datadir=/data',
			'-regtest',
			'-rpcwait',
			'-rpcwaittimeout=30',
			'getblockchaininfo'
		]);
		const root = rpc();
		const chain = (await root('getblockchaininfo')) as { chain: string };
		assert.equal(chain.chain, 'regtest');
		await root('createwallet', ['miner']);
		const miner = rpc('miner');
		const mineTo = await miner('getnewaddress');
		await miner('generatetoaddress', [101, mineTo]);

		const results: Array<Record<string, unknown>> = [];
		for (const kind of ['p2wpkh', 'p2tr'] as const) {
			await root('createwallet', [kind]);
			const rawWallet = rpc(kind);
			const address = await rawWallet('getnewaddress', [
				'',
				kind === 'p2wpkh' ? 'bech32' : 'bech32m'
			]);
			await miner('sendtoaddress', [address, 0.002]);
			await miner('generatetoaddress', [1, mineTo]);
			const storagePath = path.join(directory, kind);
			let storage = new FileDirectFundingStorage(storagePath);
			let signingCalls = 0;
			const probeTxids: string[] = [];
			const walletRpc: BitcoinCoreRpc = async (method, params = []) => {
				assert.notEqual(
					method,
					'sendrawtransaction',
					'the payer adapter must never broadcast a probe'
				);
				if (method === 'walletprocesspsbt') {
					signingCalls++;
					const psbt = bitcoin.Psbt.fromBase64(String(params[0]));
					const unsigned = bitcoin.Transaction.fromBuffer(
						psbt.data.globalMap.unsignedTx.toBuffer()
					);
					if (unsigned.ins.length === 2) {
						assert.equal(unsigned.outs.length, 1);
						assert.equal(unsigned.outs[0].value, 0);
						probeTxids.push(unsigned.getId());
					}
				}
				return rawWallet(method, params);
			};
			let wallet = await BitcoinCoreWalletAdapter.create({
				rpc: walletRpc,
				network: Network.REGTEST,
				storage
			});
			const coins = wallet.listSpendable();
			assert.equal(coins.length, 1);
			const coin = coins[0];
			assert.equal(coin.valueSat, 200_000n);
			assert.equal(coin.script.length, kind === 'p2wpkh' ? 22 : 34);
			let built: IBuiltSignRequest | undefined;
			let offer: IDfOffer | undefined;
			let broadcasts = 0;
			let rejectReceiver!: (error: unknown) => void;
			const receiverFailure = new Promise<never>((_resolve, reject) => {
				rejectReceiver = reject;
			});
			void receiverFailure.catch(() => undefined);
			const receiverKey = randomBytes(32);
			let receiverPeer: Peer | undefined;
			const server = net.createServer((socket) => {
				const peer = new Peer({
					localPrivateKey: receiverKey,
					remotePublicKey: Buffer.alloc(33),
					host: '127.0.0.1',
					port: socket.remotePort ?? 1,
					holdMessagesUntilRelease: true,
					networks: [chainHashForNetwork(Network.REGTEST)]
				});
				acceptedPeers.push(peer);
				peer.on('error', rejectReceiver);
				peer.on('message', (type: number, payload: Buffer) => {
					try {
						assert.equal(type, BEIGNET_CUSTOM_MESSAGE_TYPE);
						const message = decodeCustomMessage(payload);
						assert.equal(message.version, BEIGNET_CUSTOM_PROTOCOL_VERSION);
						lane.send(message.subtype, message.payload);
					} catch (error) {
						rejectReceiver(error);
					}
				});
				void peer
					.acceptInbound(socket)
					.then(() => {
						receiverPeer = peer;
						assert.equal(peer.releaseHeldMessages(), 'released');
					})
					.catch(rejectReceiver);
			});
			servers.push(server);
			server.on('error', rejectReceiver);
			await new Promise<void>((resolve, reject) => {
				server.once('error', reject);
				server.listen(0, '127.0.0.1', () => {
					server.removeListener('error', reject);
					resolve();
				});
			});
			const receiverPort = (server.address() as net.AddressInfo).port;
			const request = mintRequest({
				amountSat: 100_000n,
				network: Network.REGTEST,
				nodePrivkey: receiverKey,
				transports: [
					{
						type: DfTransportType.DIRECT_PEER,
						host: '127.0.0.1',
						port: receiverPort
					}
				]
			});
			const lane = new ScriptedReceiverLane(request, (reply, subtype, body) => {
				void (async (): Promise<void> => {
					if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_OFFER) {
						offer = decodeDfOffer(body);
						assert.equal(offer.txid.toString('hex'), coin.txidHex);
						assert.equal(offer.vout, coin.vout);
						assert.equal(offer.valueSat, coin.valueSat);
						assert.ok(offer.receiptHash.equals(request.receiptHash));
						assert.equal(offerFieldProblem(offer, {}), null);
						assert.equal(
							ownershipProblem(offer, coin.script, request.nodeId),
							null
						);
						assert.ok(offer.ownership.probeProof);
						built = buildSignRequest(request, offer, { feeSat: 500n });
						reply.reply(
							BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK,
							encodeDfOfferAck({ offerId: offer.offerId, accepted: true })
						);
						reply.reply(
							BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST,
							built.body
						);
					} else if (subtype === BeignetCustomSubtype.DIRECT_FUNDING_WITNESS) {
						assert.ok(built && offer);
						const witness = decodeDfWitness(body);
						assert.ok(witness.offerId.equals(offer.offerId));
						const transaction = bitcoin.Transaction.fromBuffer(
							built.tx.toBuffer()
						);
						transaction.setWitness(0, witness.witness);
						const accepted = (await root('testmempoolaccept', [
							[transaction.toHex()]
						])) as Array<{ allowed: boolean }>;
						assert.equal(accepted[0].allowed, true);
						const fundingTxid = await root('sendrawtransaction', [
							transaction.toHex()
						]);
						assert.equal(fundingTxid, transaction.getId());
						assert.ok(!probeTxids.includes(String(fundingTxid)));
						broadcasts++;
						reply.reply(
							BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT,
							encodeDfReceipt({
								offerId: offer.offerId,
								preimage: request.preimage,
								fundingTxid: Buffer.from(transaction.getId(), 'hex'),
								rawTx: transaction.toBuffer()
							})
						);
					}
				})().catch(rejectReceiver);
			});
			lane.onMessage((frame) => {
				assert.ok(receiverPeer);
				receiverPeer.sendMessage(
					BEIGNET_CUSTOM_MESSAGE_TYPE,
					encodeCustomMessage(frame.subtype, frame.payload)
				);
			});
			const messaging = new NodePeerMessaging({
				network: Network.REGTEST,
				onError: rejectReceiver
			});
			payerPeers.push(messaging);
			const registry = createPeerTransportRegistry(messaging);
			let client = new DirectFundingClient({
				wallet,
				storage,
				network: Network.REGTEST,
				registry,
				config: {
					offerResendDelaysMs: [],
					offerTimeoutMs: 30_000,
					receiptTimeoutMs: 30_000
				}
			});
			try {
				const result = await Promise.race([
					client.pay(request.encoded, { maxTotalFeeSat: 1_000n }),
					receiverFailure
				]);
				assert.ok(
					result.attested &&
						result.receiptPreimageHex === request.preimage.toString('hex')
				);
				assert.equal(signingCalls, 2);
				assert.equal(probeTxids.length, 1);
				assert.equal(broadcasts, 1);
				assert.deepEqual(await root('getrawmempool'), [result.fundingTxid]);
				await client.reconcile();
				assert.equal(client.payments()[0].status, 'MEMPOOL_SEEN');
				await miner('generatetoaddress', [1, mineTo]);
				await client.reconcile();
				assert.equal(client.payments()[0].status, 'CONFIRMED');
				assert.equal(await root('gettxout', [coin.txidHex, coin.vout]), null);
				assert.deepEqual(await rawWallet('listlockunspent'), []);

				storage.close();
				storage = new FileDirectFundingStorage(storagePath);
				wallet = await BitcoinCoreWalletAdapter.create({
					rpc: walletRpc,
					network: Network.REGTEST,
					storage
				});
				client = new DirectFundingClient({
					wallet,
					storage,
					network: Network.REGTEST,
					registry
				});
				const replay = await client.pay(request.encoded);
				assert.equal(replay.fundingTxid, result.fundingTxid);
				assert.equal(replay.status, 'CONFIRMED');
				assert.equal(signingCalls, 2, 'recovery must not sign another payment');
				assert.equal(broadcasts, 1);
				results.push({
					kind,
					status: replay.status,
					fundingTxid: result.fundingTxid,
					signingCalls,
					broadcasts,
					restartReplay: true
				});
			} finally {
				storage.close();
			}
		}
		console.log(
			JSON.stringify(
				{
					network: 'regtest',
					bitcoinImage: IMAGE,
					transport: 'loopback TCP with BOLT8 and NodePeerMessaging',
					receiver:
						'scripted channel negotiation with real protocol verification',
					results
				},
				null,
				2
			)
		);
	} finally {
		process.removeListener('SIGINT', interrupted);
		process.removeListener('SIGTERM', interrupted);
		await cleanup();
	}
}

void main().catch((error: Error) => {
	console.error(error.stack ?? error.message);
	process.exitCode = 1;
});
