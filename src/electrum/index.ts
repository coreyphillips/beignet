import { Block } from 'bitcoinjs-lib';
import * as electrum from 'rn-electrum-client/helpers';

import {
	EAddressType,
	EAvailableNetworks,
	EElectrumNetworks,
	EScanningStrategy,
	IAddress,
	IAddresses,
	IElectrumGetAddressBalanceRes,
	IGetAddressHistoryResponse,
	IGetAddressScriptHashBalances,
	IGetAddressScriptHashesHistoryResponse,
	IGetAddressTxResponse,
	IGetHeaderResponse,
	IGetTransactions,
	IGetTransactionsFromInputs,
	IGetUtxosResponse,
	IHeader,
	INewBlock,
	IPeerData,
	ISubscribeToAddress,
	ISubscribeToHeader,
	ITransaction,
	ITxHash,
	IUtxo,
	Net,
	TAddressTypeContent,
	TConnectToElectrumRes,
	TGetAddressHistory,
	TOnMessage,
	TServer,
	TSubscribedReceive,
	TTxResponse,
	TTxResult,
	TUnspentAddressScriptHashData,
	TUnspentAddressScriptHashResponse,
	Tls
} from '../types';
import {
	btcPerKbToSatPerVbyte,
	err,
	filterAddressesForGapLimit,
	filterAddressesObjForAddressesList,
	filterAddressesObjForGapLimit,
	filterAddressesObjForSingleIndex,
	filterAddressesObjForStartingIndex,
	getAddressFromScriptPubKey,
	getElectrumNetwork,
	getScriptHash,
	ok,
	Result,
	sleep,
	splitAddresses
} from '../utils';
import { Wallet } from '../wallet';
import {
	defaultElectrumPeers,
	ELECTRUM_SERVER_COOLDOWN_MS,
	onMessageKeys,
	POLLING_INTERVAL
} from '../shapes';

/** Answer of every subscribe refused because the instance has disconnected. */
const DISCONNECTED_ERROR = 'Electrum instance is disconnected.';

type TScriptHashSubscription = {
	callbacks: Set<(data: TSubscribedReceive) => void>;
	/** Address index of a UTXO tracked beyond the gap limit; that index is
	 *  rescanned before the wallet refresh on notification. */
	utxoIndex?: number;
};

type TScriptHashRouter = {
	/** Every instance that subscribed on this network, for the fallback refresh. */
	instances: Set<Electrum>;
	/** scriptHash -> per-instance subscription state. */
	subscriptions: Map<string, Map<Electrum, TScriptHashSubscription>>;
	/** The one handler every subscribeAddress call for this network is given. */
	dispatch: (data: TSubscribedReceive) => Promise<void>;
};

/**
 * Script hash routing state, shared per network across every Electrum
 * instance in the process. rn-electrum-client keeps ONE
 * 'blockchain.scripthash.subscribe' handler per network for the WHOLE process
 * (the first onReceive it is handed) and answers a repeat script hash with
 * "Already Subscribed." without wiring the new callback, so per-call closures
 * are never delivered, and even an instance-local router would strand every
 * instance but the first. Each network therefore gets one shared registry and
 * one stable dispatcher that routes by the script hash in the notification
 * payload; instances withdraw from it in disconnect().
 */
const scriptHashRouters: Map<EElectrumNetworks, TScriptHashRouter> = new Map();

type THeaderRouter = {
	/** Every instance subscribed to this network's headers. */
	handlers: Map<Electrum, (data: INewBlock[]) => Promise<void>>;
	/** The one handler every subscribeHeader call for this network is given. */
	dispatch: (data: INewBlock[]) => Promise<void>;
	/** The most recent header seen on this network, whatever reported it. The
	 *  client answers every subscribe after the first with a bare
	 *  "Already Subscribed." string, so this is the only tip an instance that
	 *  joins the network later has to reconcile its own stored one against. */
	last: IHeader | null;
	/** Bumped every time `last` is replaced. A subscribe compares it across its
	 *  own await: a notification that landed while the response was in flight is
	 *  the fresher word from the same socket, and writing the response on top of
	 *  it would lower the stored height and read the next block as a rollback. */
	seq: number;
	/** The notification payload this dispatcher last accepted, compared by
	 *  identity to swallow a duplicate registration: see the dispatch. */
	lastDispatched: unknown;
};

/**
 * Header routing state, shared per network for the same reason the script hash
 * routers are: rn-electrum-client keeps ONE
 * 'blockchain.headers.subscribe' handler per network for the WHOLE process and
 * answers every later subscribe with "Already Subscribed.", so a per-call
 * closure only ever reaches the instance that subscribed first, and a client
 * reset would hand the network's headers to whichever instance re-subscribed
 * first while silencing the rest. Instances withdraw in disconnect().
 */
const headerRouters: Map<EElectrumNetworks, THeaderRouter> = new Map();

/**
 * Per-network gate over blockchain.headers.subscribe.
 *
 * rn-electrum-client registers the notification listener on the client's
 * shared emitter BEFORE the awaited request and only sets
 * clients.subscribedHeaders[network] AFTER it returns, so two subscribes that
 * overlap that window both pass its "Already Subscribed." guard and both
 * append the router's dispatcher to the same EventEmitter. Every later
 * notification then runs the whole router queue twice for the life of that
 * client: two header writes, two wallet refreshes and two newBlock messages
 * per block, per instance. Three overlapping calls triple it. That overlap is
 * the normal case rather than an exotic one, because restoreSubscriptions
 * issues one after every successful connect while an ElectrumBackend reconnect
 * monitor (or application code) can issue another at the same moment.
 *
 * Module level for the same reason the routers are: the state being protected
 * belongs to the client, and the client is process-wide, so two different
 * Electrum instances racing on one network is exactly the case to cover.
 *
 * Serialised rather than de-duplicated. The caller behind the gate still
 * issues its OWN subscribe, so a restore that runs after a client was torn
 * down and rebuilt wires the new client instead of inheriting an answer from
 * the old one; it simply finds the network already subscribed and is answered
 * "Already Subscribed." without a second listener.
 */
const headerSubscribeGates: Map<EElectrumNetworks, Promise<void>> = new Map();

function getHeaderRouter(network: EElectrumNetworks): THeaderRouter {
	let router = headerRouters.get(network);
	if (!router) {
		const created: THeaderRouter = {
			handlers: new Map(),
			last: null,
			seq: 0,
			lastDispatched: null,
			dispatch: async (data: INewBlock[]): Promise<void> => {
				// One notification, dispatched once, however many times the
				// client holds this dispatcher.
				//
				// rn-electrum-client appends it to the client's emitter once
				// per subscribe that gets past its "Already Subscribed." guard,
				// and it sets that guard only AFTER the awaited request: two
				// subscribes that overlap the window both register, and a
				// subscribe that FAILS leaves its registration behind with the
				// network still marked unsubscribed, so the next one registers
				// on top of it. Serialising the requests (see
				// headerSubscribeGates) closes the overlap but not the retry.
				//
				// The emitter hands every listener the identical payload object
				// for one notification, while a genuine second notification is
				// always a freshly parsed one, so identity is what tells a
				// duplicate registration apart from a repeated block.
				if (created.lastDispatched === data) return;
				created.lastDispatched = data;
				// The instances are snapshotted so a handler may withdraw itself
				// or a sibling mid-dispatch, but each handler is read at the
				// moment it is called rather than taken from that snapshot: an
				// instance that disconnects while this dispatch is in flight
				// must not be refreshed by a header it is merely still
				// registered for.
				//
				// Dispatched concurrently rather than one wallet at a time. The
				// handler awaits caller-supplied storage and a whole wallet
				// refresh, neither of which this library can bound, and a
				// wallet whose updateHeader never settles used to park every
				// instance behind it in the map, for that block and for every
				// block after it: the catch below only ever covered a
				// rejection, never a promise that does not settle. The client
				// emits notifications without awaiting this handler, so
				// per-instance handling could already overlap across blocks and
				// nothing here relied on the order.
				await Promise.all(
					[...created.handlers.keys()].map(async (instance) => {
						const handler = created.handlers.get(instance);
						if (!handler) return;
						try {
							await handler(data);
						} catch {
							// One instance must not starve the rest. Kept inside
							// the callback, so a rejection neither short-circuits
							// Promise.all nor escapes it unhandled.
						}
					})
				);
			}
		};
		router = created;
		headerRouters.set(network, created);
	}
	return router;
}

function getScriptHashRouter(network: EElectrumNetworks): TScriptHashRouter {
	let router = scriptHashRouters.get(network);
	if (!router) {
		const created: TScriptHashRouter = {
			instances: new Set(),
			subscriptions: new Map(),
			dispatch: async (data: TSubscribedReceive): Promise<void> => {
				const scriptHash = Array.isArray(data) ? data[0] : undefined;
				const subs = scriptHash
					? created.subscriptions.get(scriptHash)
					: undefined;
				if (!subs || subs.size === 0) {
					// Nothing registered for this hash (a race with removal, or a
					// subscription that predates the registry): fall back to the
					// pre-registry behaviour and refresh every subscribed wallet.
					for (const instance of [...created.instances]) {
						void instance.wallet.refreshWallet({});
					}
					return;
				}
				for (const [instance, sub] of [...subs]) {
					// Snapshots: a callback may unregister itself or a sibling
					// mid-dispatch.
					for (const callback of [...sub.callbacks]) {
						try {
							callback(data);
						} catch {
							// One subscriber must not starve the rest or the refresh.
						}
					}
					if (sub.utxoIndex !== undefined) {
						await instance.getUtxos({
							scanningStrategy: EScanningStrategy.singleIndex,
							addressIndex: sub.utxoIndex,
							changeAddressIndex: sub.utxoIndex
						});
					}
					void instance.wallet.refreshWallet({});
				}
			}
		};
		router = created;
		scriptHashRouters.set(network, created);
	}
	return router;
}

export class Electrum {
	private readonly _wallet: Wallet;
	private sendMessage: TOnMessage;
	private latestConnectionState: boolean | null = null;
	private connectionPollingInterval: NodeJS.Timeout | null;
	private net: Net;
	private tls: Tls;
	/** Shared in-flight connect, so concurrent callers don't race (see connectToElectrum). */
	private _connectInFlight: Promise<Result<TConnectToElectrumRes>> | null =
		null;
	/** Per-server failure tracking for rotation (keyed by host|protocol|port). */
	private _serverFailures: Map<
		string,
		{ failures: number; lastFailureAt: number }
	> = new Map();
	private _currentServer: TServer | null = null;
	/** Number of times the connected server changed after the first connect. */
	private _rotationCount = 0;
	/** Network whose subscription restore last failed, cleared once one
	 *  succeeds. A restore only fails on a socket that can stay healthy
	 *  indefinitely, and nothing else reconnects while it does, so the
	 *  connection poll owns the retry. */
	private _restoreOwed: EElectrumNetworks | null = null;
	/** Per-network bookkeeping for concurrent header subscribes: how many are in
	 *  flight and whether the handler must stay registered (see subscribeToHeader). */
	private readonly _headerSubscribes: Map<
		EElectrumNetworks,
		{ inFlight: number; committed: boolean }
	> = new Map();
	/** Set by disconnect(): this instance withdrew from the shared routers, so
	 *  work still in flight must not register it back into them. Cleared when a
	 *  new connect is explicitly requested. */
	private _disconnected = false;
	/** A drop in this wallet's stored height that has not been reconciled yet.
	 *  The header write that revealed the rollback also replaced the only
	 *  evidence of it, so a reconciliation that fails is owed here and every
	 *  later header retries it until one succeeds. */
	private _reorgOwed = false;

	public servers?: TServer | TServer[];
	public network: EAvailableNetworks;
	public electrumNetwork: EElectrumNetworks;
	public connectedToElectrum: boolean;
	public onReceive?: (data: unknown) => void;
	public batchLimit: number;
	public batchDelay: number;

	constructor({
		wallet,
		network,
		net,
		tls,
		servers,
		batchLimit = 20,
		batchDelay = 50,
		onReceive
	}: {
		wallet: Wallet;
		network: EAvailableNetworks;
		net: Net;
		tls: Tls;
		servers?: TServer | TServer[];
		batchLimit?: number;
		batchDelay?: number;
		onReceive?: (data: unknown) => void;
	}) {
		this._wallet = wallet;
		this.sendMessage = wallet.sendMessage;
		this.servers = servers ?? [];
		this.network = network;
		this.electrumNetwork = getElectrumNetwork(this.network);
		this.connectedToElectrum = false;
		this.onReceive = onReceive;
		this.net = net;
		this.tls = tls;
		this.batchLimit = batchLimit;
		this.batchDelay = batchDelay;
		this.connectionPollingInterval = setInterval((): void => {
			void this.checkConnection();
		}, POLLING_INTERVAL);
	}

	public get wallet(): Wallet {
		return this._wallet;
	}

	/**
	 * Connect to the Electrum server.
	 *
	 * Concurrent callers share a single in-flight attempt. At startup several
	 * independent paths (background refreshWallet, sweep-address lookup, header
	 * subscription) can each trigger a connect at once; without this guard they
	 * race over rn-electrum-client's shared global client, clobbering the socket
	 * mid-connect so the losing attempt returns an error and logs a spurious
	 * "Unable to connect to Electrum server." De-duping collapses them into one
	 * real connect, so the others simply join its result.
	 */
	async connectToElectrum(args: {
		network?: EAvailableNetworks;
		servers?: TServer | TServer[];
		disableRegtestCheck?: boolean;
	}): Promise<Result<TConnectToElectrumRes>> {
		// An explicit connect revives an instance that had disconnected; a
		// disconnect landing mid-connect keeps the flag set, so the attempt it
		// interrupted still declines to re-register the instance.
		this._disconnected = false;
		if (this._connectInFlight) return this._connectInFlight;
		this._connectInFlight = this._doConnect(args).finally(() => {
			this._connectInFlight = null;
		});
		return this._connectInFlight;
	}

	private async _doConnect({
		network = this.network,
		servers,
		disableRegtestCheck = false // Used to ignore regtest check for certain tests.
	}: {
		network?: EAvailableNetworks;
		servers?: TServer | TServer[];
		disableRegtestCheck?: boolean;
	}): Promise<Result<TConnectToElectrumRes>> {
		let customPeers = servers
			? Array.isArray(servers)
				? servers
				: [servers]
			: [];
		// @ts-ignore
		customPeers = customPeers.length ? customPeers : this?.servers ?? [];
		const electrumNetwork = getElectrumNetwork(network);
		if (
			!disableRegtestCheck &&
			electrumNetwork === 'bitcoinRegtest' &&
			!customPeers.length
		) {
			return err('Regtest requires that you pre-specify a server.');
		}
		const candidates = this.getServerCandidates(customPeers, electrumNetwork);
		let connected = false;
		let lastError = 'No Electrum servers available.';
		/** Whether any candidate got past the teardown and reached a socket. */
		let dialledAny = false;
		/** Whether any candidate was refused because the peer would not stop. */
		let refusedAny = false;
		for (const candidate of this.orderCandidates(candidates)) {
			const startResponse = await this.attemptConnect(
				candidate,
				electrumNetwork
			);
			dialledAny = dialledAny || !startResponse.teardownRefused;
			refusedAny = refusedAny || !!startResponse.teardownRefused;
			if (startResponse.error) {
				// A candidate the teardown refused was never dialled, so it must
				// not be blamed for the failure and cooled down.
				if (!startResponse.teardownRefused) {
					this.recordServerFailure(candidate);
				}
				lastError = String(startResponse.error);
				continue;
			}
			this.recordServerSuccess(candidate);
			connected = true;
			break;
		}
		// Every candidate was refused before it was dialled, and the peer whose
		// teardown refused them is still connected: the switch was declined on
		// purpose to keep a working connection rather than build a client on
		// stale bookkeeping, so nothing about this instance's connection
		// changed. Reporting a disconnect would contradict the peer that is
		// still serving every call, and adopting the refused target would point
		// the reconnect guards and the connection poll at the same doomed
		// switch on every later call. The error still goes back to the caller,
		// and the poll remains the authority on whether the kept peer is alive.
		if (
			!connected &&
			refusedAny &&
			!dialledAny &&
			!!electrum.getConnectedPeer(electrumNetwork)?.host
		) {
			return err(lastError);
		}
		// A network switch needs the network fields updated even when the new
		// network has no reachable server, but that must never be reported as
		// success: every Electrum call gates on connectedToElectrum, and a
		// false success leaves them all believing a connection exists.
		this.network = network;
		this.electrumNetwork = electrumNetwork;
		if (customPeers.length) {
			this.servers = customPeers;
		}
		if (!connected) {
			this.publishConnectionChange(false);
			return err(lastError);
		}
		this.publishConnectionChange(true);
		// disconnect() may have landed while this attempt was in flight, and it
		// withdrew the instance from the shared routers.
		if (this._disconnected) return ok('Connected to Electrum server.');
		// Unconditional, because a connect cannot tell whether the client it now
		// holds is the one that was subscribed. Our own teardown resets it on a
		// server change, and rn-electrum-client resets it behind our back on the
		// same-server path: start() pings the live peer and, when the socket is
		// dead, disconnects (dropping subscribedAddresses/subscribedHeaders/
		// onAddressReceive for the whole process) before building a fresh client,
		// with nothing observable left for the teardown above to notice. The
		// torn down client takes every subscription in this process with it,
		// including the ones this instance never made, and the wallet's own
		// addresses have no other reconnect hook here. Restoring costs nothing
		// when nothing was lost: the client answers a known script hash with
		// "Already Subscribed." without touching the socket.
		this.restoreSubscriptionsBestEffort(electrumNetwork);
		return ok('Connected to Electrum server.');
	}

	/**
	 * Attempts a single connect to the given server. Isolated so tests can
	 * exercise rotation with a fake connection layer.
	 */
	private async attemptConnect(
		server: TServer,
		electrumNetwork: EElectrumNetworks
	): Promise<{
		error: unknown;
		teardownRefused?: boolean;
	}> {
		const teardown = await this.stopPeerIfServerChanged(
			server,
			electrumNetwork
		);
		if (teardown.error) {
			return { error: teardown.error, teardownRefused: true };
		}
		const startResponse = await electrum.start({
			clientName: 'beignet',
			protocolVersion: '1.4',
			network: electrumNetwork,
			net: this.net,
			tls: this.tls,
			customPeers: [server]
		});
		return { error: startResponse.error };
	}

	/**
	 * Disconnects the connected peer when the next connect targets a different
	 * server.
	 *
	 * rn-electrum-client builds a fresh client whenever the target
	 * host/port/protocol differ from the connected peer, but only its
	 * disconnect path clears the per-network bookkeeping (subscribedAddresses,
	 * subscribedHeaders, onAddressReceive) while the notification handlers live
	 * on the client object that is thrown away. Without this reset every
	 * subscribe after a failover answers "Already Subscribed." although nothing
	 * is subscribed on the new connection and no handler is wired to it, so the
	 * process silently stops receiving header and script hash notifications.
	 * The same-server path is left alone: the client pings the live connection
	 * and disconnects itself (resetting the same state) if the ping fails, which
	 * is why the restore after a successful connect is unconditional.
	 *
	 * The client only clears that bookkeeping when closing the socket succeeds
	 * and reports the failure as { error: true }, so a teardown that did not
	 * happen refuses the candidate instead of connecting a fresh client on top
	 * of stale state, which is the very bug this guards against. Rotation then
	 * moves on, and the still-connected server is accepted unchanged when it
	 * comes back around. When it is not among the candidates at all the connect
	 * fails without touching the connection it kept: see _doConnect.
	 */
	private async stopPeerIfServerChanged(
		server: TServer,
		electrumNetwork: EElectrumNetworks
	): Promise<{ error?: string }> {
		const peer = electrum.getConnectedPeer(electrumNetwork);
		if (!peer?.host) return {};
		const peerKey = `${peer.host}|${peer.protocol}|${peer.port}`;
		if (peerKey === this.serverKey(server)) return {};
		const stopResponse = await electrum.stop({ network: electrumNetwork });
		// The cleared peer is the observable proof that the bookkeeping went
		// with it, so it decides, and the reported error only sharpens the
		// message.
		const clientReset = !electrum.getConnectedPeer(electrumNetwork)?.host;
		if (!clientReset) {
			const reason = stopResponse?.error
				? `: ${String(stopResponse.data ?? '')}`
				: '.';
			return {
				error: `Unable to disconnect from ${peer.host} before switching Electrum servers${reason}`
			};
		}
		return {};
	}

	/**
	 * Re-issues every subscription this process holds for the network, run after
	 * every successful connect because a client may have been torn down.
	 *
	 * rn-electrum-client keeps one client, and with it one set of
	 * subscriptions and one notification handler, per network for the whole
	 * process, so a reset by any instance drops what every other instance
	 * subscribed as well. The shared script hash router is the record of that
	 * state; re-subscribing its hashes restores the handler wiring for all of
	 * them, and this instance's own wallet addresses are re-issued on top to
	 * pick up anything generated since. The header subscription is part of the
	 * same restore, so a failure to re-issue it is owed and retried like the
	 * hashes are.
	 */
	private async restoreSubscriptions(
		electrumNetwork: EElectrumNetworks
	): Promise<void> {
		if (this._disconnected) return;
		// Re-issues the shared header dispatcher, so every instance subscribed
		// to this network's headers is wired to the new client, not just this
		// one. Started before the hashes and awaited after them, so neither
		// failure defers the other, and settled the moment it is started, so a
		// rejection is never left unhandled when the hashes fail first.
		// The internal form, because the restore is the one caller that may read
		// a failed reconciliation: it is what retries it. Every other caller
		// sees only whether the subscription itself is live.
		const headerFailed = this.subscribeToHeaderInternal().then(
			({ result, reconcileOwed }) => result.isErr() || reconcileOwed,
			() => true
		);
		const router = scriptHashRouters.get(electrumNetwork);
		if (router) {
			await Promise.all(
				[...router.subscriptions.keys()].map(async (scriptHash) => {
					const response = await electrum.subscribeAddress({
						scriptHash,
						network: electrumNetwork,
						onReceive: router.dispatch
					});
					if (response.error) {
						throw new Error('Unable to restore address subscriptions.');
					}
				})
			);
		}
		// Checked again: disconnect() can land while the hashes above are in
		// flight, and subscribeToAddresses would register this instance back
		// into the router it just withdrew from.
		if (this._disconnected) return;
		const walletSubscriptions = await this.subscribeToAddresses({});
		if (walletSubscriptions.isErr()) {
			throw walletSubscriptions.error;
		}
		// subscribeToHeader answers a protocol failure with an error value
		// rather than a rejection, so nothing outside the restore would ever
		// notice one, and the socket it failed on can stay healthy
		// indefinitely: without the debt below the wallet would receive no
		// header notification until the next reconnect. The debt also covers a
		// reconciliation the reported header revealed and could not complete,
		// which is deliberately invisible to every other caller: the
		// subscription is live, and the retry is this one's job.
		if (await headerFailed) {
			throw new Error('Unable to restore the header subscription.');
		}
	}

	/**
	 * Runs the restore without letting it fail the connect. A re-subscribe that
	 * errors leaves the debt recorded, because the socket it failed on is
	 * otherwise healthy: no reconnect is coming to restore unconditionally, so
	 * the connection poll retries it instead of leaving the hashes unwired.
	 */
	private restoreSubscriptionsBestEffort(
		electrumNetwork: EElectrumNetworks
	): void {
		this.restoreSubscriptions(electrumNetwork).then(
			() => {
				if (this._restoreOwed === electrumNetwork) {
					this._restoreOwed = null;
				}
			},
			() => {
				// A restore that failed because the instance disconnected owes
				// nothing: disconnect() cleared the debt, its retry hook is
				// stopped, and the next connect restores unconditionally.
				if (this._disconnected) return;
				this._restoreOwed = electrumNetwork;
			}
		);
	}

	/**
	 * Ordered rotation candidates: user-provided servers first, then the
	 * hardcoded fallback peers for the network (never for regtest), deduped.
	 */
	private getServerCandidates(
		customPeers: TServer[],
		electrumNetwork: EElectrumNetworks
	): TServer[] {
		const fallback =
			electrumNetwork === EElectrumNetworks.bitcoinRegtest
				? []
				: defaultElectrumPeers[electrumNetwork] ?? [];
		const candidates: TServer[] = [];
		const seen = new Set<string>();
		for (const server of [...customPeers, ...fallback]) {
			const key = this.serverKey(server);
			if (seen.has(key)) continue;
			seen.add(key);
			candidates.push(server);
		}
		return candidates;
	}

	/**
	 * Starts iteration at the currently connected server (stable across
	 * transient reconnects) and moves servers still cooling down from a recent
	 * failure to the end, so a dead server is only retried once healthier
	 * candidates have been exhausted.
	 */
	private orderCandidates(candidates: TServer[]): TServer[] {
		let ordered = candidates;
		if (this._currentServer) {
			const currentKey = this.serverKey(this._currentServer);
			const index = candidates.findIndex(
				(s) => this.serverKey(s) === currentKey
			);
			if (index > 0) {
				ordered = [...candidates.slice(index), ...candidates.slice(0, index)];
			}
		}
		const now = Date.now();
		const coolingDown = (server: TServer): boolean => {
			const failure = this._serverFailures.get(this.serverKey(server));
			if (!failure) return false;
			return now - failure.lastFailureAt < ELECTRUM_SERVER_COOLDOWN_MS;
		};
		return [
			...ordered.filter((s) => !coolingDown(s)),
			...ordered.filter(coolingDown)
		];
	}

	private serverKey(server: TServer): string {
		const port = server.protocol === 'ssl' ? server.ssl : server.tcp;
		return `${server.host}|${server.protocol}|${port}`;
	}

	private recordServerFailure(server: TServer): void {
		const key = this.serverKey(server);
		const failure = this._serverFailures.get(key);
		this._serverFailures.set(key, {
			failures: (failure?.failures ?? 0) + 1,
			lastFailureAt: Date.now()
		});
	}

	private recordServerSuccess(server: TServer): void {
		this._serverFailures.delete(this.serverKey(server));
		if (
			this._currentServer &&
			this.serverKey(this._currentServer) !== this.serverKey(server)
		) {
			this._rotationCount++;
		}
		this._currentServer = server;
	}

	/** The server of the most recent successful connect, if any. */
	public get currentServer(): TServer | null {
		return this._currentServer;
	}

	/** How many times the connected server has changed (rotation history). */
	public get rotationCount(): number {
		return this._rotationCount;
	}

	async isConnected(): Promise<boolean> {
		const { error } = await electrum.pingServer();
		return !error;
	}

	/**
	 * Returns the balance in sats for a given address.
	 * @param {string} scriptHash
	 * @return {number}
	 */
	async getAddressBalance(
		scriptHash: string
	): Promise<IElectrumGetAddressBalanceRes> {
		if (!this.connectedToElectrum)
			await this.connectToElectrum({
				network: this.network,
				servers: this.servers
			});
		const network = this.electrumNetwork;
		const response = await electrum.getAddressScriptHashBalance({
			scriptHash,
			network
		});
		if (response.error) {
			return { error: response.error, confirmed: 0, unconfirmed: 0 };
		}
		const { confirmed, unconfirmed } = response.data;
		return { error: response.error, confirmed, unconfirmed };
	}

	async getAddressScriptHashBalances(
		scriptHashes: string[]
	): Promise<IGetAddressScriptHashBalances> {
		return await electrum.getAddressScriptHashBalances({
			scriptHashes,
			network: this.electrumNetwork
		});
	}

	/**
	 * Returns the fee estimate in sat/vB for the given confirmation target via
	 * blockchain.estimatefee. Errs when the server has no estimate (-1) or
	 * returns an unusable value; results are clamped to a sane range.
	 * @param {number} blocksWillingToWait
	 * @returns {Promise<Result<number>>}
	 */
	async getFeeEstimate(blocksWillingToWait: number): Promise<Result<number>> {
		const response = await electrum.getFeeEstimate({
			blocksWillingToWait,
			network: this.electrumNetwork
		});
		if (response.error) {
			return err('Unable to get fee estimate from Electrum server.');
		}
		const satPerVbyte = btcPerKbToSatPerVbyte(Number(response.data));
		if (satPerVbyte <= 0) {
			return err('Electrum server returned an unusable fee estimate.');
		}
		return ok(satPerVbyte);
	}

	/**
	 * Returns currently connected peer.
	 * @returns {Promise<Result<IPeerData>>}
	 */
	async getConnectedPeer(): Promise<Result<IPeerData>> {
		const response = await electrum.getConnectedPeer(this.electrumNetwork);
		if (response?.host && response?.port && response?.protocol) {
			return ok(response);
		}
		return err('No peer available.');
	}

	/**
	 * Queries Electrum to return the available UTXO's and balance of the provided addresses.
	 * @param {TUnspentAddressScriptHashData} addresses
	 * @returns {Promise<Result<IGetUtxosResponse>>}
	 */
	async listUnspentAddressScriptHashes({
		addresses
	}: {
		addresses: TUnspentAddressScriptHashData;
	}): Promise<Result<IGetUtxosResponse>> {
		try {
			const addressBatches = splitAddresses(addresses, this.batchLimit);
			let balance = 0;
			const utxos: IUtxo[] = [];
			for (const batch of addressBatches) {
				const unspentAddressResult: TUnspentAddressScriptHashResponse =
					await electrum.listUnspentAddressScriptHashes({
						scriptHashes: {
							key: 'scriptHash',
							data: batch
						},
						network: this.electrumNetwork
					});

				if (unspentAddressResult.error) {
					return err(JSON.stringify(unspentAddressResult?.data ?? ''));
				}

				unspentAddressResult.data.forEach(
					({ data, result: unspentAddresses }) => {
						if (unspentAddresses?.length > 0) {
							unspentAddresses.forEach((unspentAddress) => {
								balance += unspentAddress.value;
								utxos.push({
									...data,
									...unspentAddress
								});
							});
						}
					}
				);
				await sleep(this.batchDelay);
			}

			return ok({ utxos, balance });
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns the available history for the provided address script hashes.
	 * @param {IAddress[]} [scriptHashes]
	 * @param {boolean} [scanAllAddresses]
	 * @returns {Promise<Result<IGetAddressHistoryResponse[]>>}
	 */
	async getAddressHistory({
		scriptHashes = [],
		scanAllAddresses = false
	}: {
		scriptHashes?: IAddress[];
		scanAllAddresses?: boolean;
	}): Promise<Result<IGetAddressHistoryResponse[]>> {
		try {
			if (!this.connectedToElectrum)
				await this.connectToElectrum({
					network: this.network,
					servers: this.servers
				});
			const currentWallet = this._wallet.data;
			const currentAddresses: TAddressTypeContent<IAddresses> =
				currentWallet.addresses;
			const currentChangeAddresses: TAddressTypeContent<IAddresses> =
				currentWallet.changeAddresses;

			const addressIndexes = currentWallet.addressIndex;
			const changeAddressIndexes = currentWallet.changeAddressIndex;

			if (scriptHashes.length < 1) {
				const addressTypeKeys = this._wallet.addressTypesToMonitor;
				addressTypeKeys.forEach((addressType) => {
					const addresses = currentAddresses[addressType];
					const changeAddresses = currentChangeAddresses[addressType];
					let addressValues = Object.values(addresses);
					let changeAddressValues = Object.values(changeAddresses);

					const addressIndex = addressIndexes[addressType].index;
					const changeAddressIndex = changeAddressIndexes[addressType].index;

					// Instead of scanning all addresses, adhere to the gap limit.
					if (
						!scanAllAddresses &&
						addressIndex >= 0 &&
						changeAddressIndex >= 0
					) {
						addressValues = filterAddressesForGapLimit({
							addresses: addressValues,
							index: addressIndex,
							gapLimitOptions: this._wallet.gapLimitOptions,
							change: false
						});
						changeAddressValues = filterAddressesForGapLimit({
							addresses: changeAddressValues,
							index: changeAddressIndex,
							gapLimitOptions: this._wallet.gapLimitOptions,
							change: true
						});
					}
					const utxoScriptHashes: IAddress[] = currentWallet.utxos;

					scriptHashes = [
						...utxoScriptHashes,
						...scriptHashes,
						...addressValues,
						...changeAddressValues
					];
				});
			}
			// remove items with same path
			scriptHashes = scriptHashes.filter((sh, index, arr) => {
				return index === arr.findIndex((v) => sh.path === v.path);
			});
			if (scriptHashes.length < 1) {
				return err('No scriptHashes available to check.');
			}

			const combinedResponse: TTxResponse[] = [];
			const promises: Promise<IGetAddressScriptHashesHistoryResponse>[] = [];

			// split payload in chunks of 10 addresses per-request
			for (let i = 0; i < scriptHashes.length; i += this.batchLimit) {
				const chunk = scriptHashes.slice(i, i + this.batchLimit);
				const payload = {
					key: 'scriptHash',
					data: chunk
				};
				promises.push(
					electrum.getAddressScriptHashesHistory({
						scriptHashes: payload,
						network: this.electrumNetwork
					})
				);
				await sleep(this.batchDelay);
				promises.push(
					electrum.getAddressScriptHashesMempool({
						scriptHashes: payload,
						network: this.electrumNetwork
					})
				);
				await sleep(this.batchDelay);
			}

			const responses = await Promise.all(promises);
			responses.forEach((response) => {
				if (!response.error) {
					combinedResponse.push(...response.data);
				}
			});

			const history: IGetAddressHistoryResponse[] = [];
			combinedResponse.forEach(
				({ data, result }: { data: IAddress; result: TTxResult[] }): void => {
					if (result && result?.length > 0) {
						result.forEach((item) => {
							history.push({ ...data, ...item });
						});
					}
				}
			);
			return ok(history);
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Used to retrieve scriptPubkey history for LDK.
	 * @param {string} scriptPubkey
	 * @returns {Promise<TGetAddressHistory[]>}
	 */
	async getScriptPubKeyHistory(
		scriptPubkey: string
	): Promise<TGetAddressHistory[]> {
		const history: { txid: string; height: number }[] = [];
		const address = getAddressFromScriptPubKey(scriptPubkey, this.network);
		if (!address) {
			return history;
		}
		const scriptHash = getScriptHash({
			network: this.network,
			address
		});
		if (!scriptHash) {
			return history;
		}
		const response = await electrum.getAddressScriptHashesHistory({
			scriptHashes: [scriptHash],
			network: this.electrumNetwork
		});
		if (response.error) {
			return history;
		}
		await Promise.all(
			response.data.map(({ result }: { result: TTxResult[] }): void => {
				if (result && result?.length > 0) {
					result.map((item) => {
						history.push({
							txid: item?.tx_hash ?? '',
							height: item?.height ?? 0
						});
					});
				}
			})
		);
		return history;
	}

	/**
	 * Returns an array of tx_hashes and their height for a given array of address script hashes.
	 * @param {string[]} scriptHashes
	 * @returns {Promise<Result<TTxResponse>>}
	 */
	async getAddressScriptHashesHistory(
		scriptHashes: string[] = []
	): Promise<Result<IGetAddressTxResponse>> {
		const response = await electrum.getAddressScriptHashesHistory({
			scriptHashes,
			network: this.electrumNetwork
		});
		if (response.error) {
			return err(
				response?.data ?? 'Unable to get address script hashes history.'
			);
		}
		return ok(response);
	}

	/**
	 * Returns UTXO's for a given wallet and network along with the available balance.
	 * @param {EScanningStrategy} [scanningStrategy]
	 * @param {number} addressIndex
	 * @param {number} changeAddressIndex
	 * @param {EAddressType[]} [addressTypesToCheck]
	 * @additionalAddresses {string[]} [additionalAddresses]
	 * @returns {Promise<Result<IGetUtxosResponse>>}
	 */
	async getUtxos({
		scanningStrategy = EScanningStrategy.gapLimit,
		addressIndex,
		changeAddressIndex,
		addressTypesToCheck = this._wallet.addressTypesToMonitor,
		additionalAddresses = []
	}: {
		scanningStrategy?: EScanningStrategy;
		addressIndex?: number;
		changeAddressIndex?: number;
		addressTypesToCheck?: EAddressType[];
		additionalAddresses?: string[];
	}): Promise<Result<IGetUtxosResponse>> {
		try {
			if (!this.connectedToElectrum)
				await this.connectToElectrum({
					network: this.network,
					servers: this.servers
				});
			const currentWallet = this._wallet.data;

			let addresses = {} as IAddresses;
			let changeAddresses = {} as IAddresses;
			const existingUtxos: { [key: string]: IUtxo } = {};

			for (const addressType of addressTypesToCheck) {
				// Grab all addresses and change addresses.
				const allAddresses = currentWallet.addresses[addressType] ?? {};
				const allChangeAddresses =
					currentWallet.changeAddresses[addressType] ?? {};

				// Skip a type only when NEITHER collection has been generated.
				// Two things to note here:
				//   - `continue`, not `break`: address types are independent, and a
				//     `break` dropped every LATER type from the query. Since p2tr is
				//     last in EAddressType, a wallet with no p2sh addresses returned
				//     zero UTXOs for its own p2tr addresses, indistinguishable from
				//     having no funds.
				//   - both collections are checked: getChangeAddress generates with
				//     `addressAmount: 0`, so a type can hold change addresses and no
				//     receiving addresses. Testing only the receiving side skipped
				//     those change addresses, dropping real UTXOs from the scan.
				if (
					Object.keys(allAddresses).length === 0 &&
					Object.keys(allChangeAddresses).length === 0
				) {
					continue;
				}

				if (scanningStrategy === EScanningStrategy.all) {
					addresses = { ...addresses, ...allAddresses };
					changeAddresses = { ...changeAddresses, ...allChangeAddresses };
				} else {
					// Grab the current index for address/change addresses if none were provided.
					const _addressIndex =
						addressIndex === undefined
							? currentWallet.addressIndex[addressType].index
							: addressIndex;
					const _changeAddressIndex =
						changeAddressIndex === undefined
							? currentWallet.changeAddressIndex[addressType].index
							: changeAddressIndex;

					// Use the lowest index to ensure we're not starting above our current index.
					// TODO: Consider removing this entirely or at least updating it to allow up to the max stored address/change address index.
					const lowestAddressIndex = Math.min(
						_addressIndex,
						currentWallet.addressIndex[addressType].index
					);
					const lowestChangeAddressIndex = Math.min(
						_changeAddressIndex,
						currentWallet.changeAddressIndex[addressType].index
					);

					switch (scanningStrategy) {
						case EScanningStrategy.gapLimit:
							addresses = {
								...addresses,
								...filterAddressesObjForGapLimit({
									addresses: allAddresses,
									index: lowestAddressIndex,
									gapLimitOptions: this._wallet.gapLimitOptions,
									change: false
								}),
								...filterAddressesObjForAddressesList({
									addresses: allAddresses,
									additionalAddresses
								})
							};
							changeAddresses = {
								...changeAddresses,
								...filterAddressesObjForGapLimit({
									addresses: allChangeAddresses,
									index: lowestChangeAddressIndex,
									gapLimitOptions: this._wallet.gapLimitOptions,
									change: true
								})
							};
							break;
						case EScanningStrategy.startingIndex:
							addresses = {
								...addresses,
								...filterAddressesObjForStartingIndex({
									addresses: allAddresses,
									index: lowestAddressIndex
								}),
								...filterAddressesObjForAddressesList({
									addresses: allAddresses,
									additionalAddresses
								})
							};
							changeAddresses = {
								...changeAddresses,
								...filterAddressesObjForStartingIndex({
									addresses: allChangeAddresses,
									index: lowestChangeAddressIndex
								})
							};
							break;
						case EScanningStrategy.singleIndex:
							addresses = {
								...addresses,
								...filterAddressesObjForSingleIndex({
									addresses: allAddresses,
									addressIndex: _addressIndex
								}),
								...filterAddressesObjForAddressesList({
									addresses: allAddresses,
									additionalAddresses
								})
							};
							changeAddresses = {
								...changeAddresses,
								...filterAddressesObjForSingleIndex({
									addresses: allChangeAddresses,
									addressIndex: _changeAddressIndex
								})
							};
							break;
					}
				}
			}

			// Make sure we're re-check existing utxos that may exist outside the gap limit and putting them in the necessary format.
			currentWallet.utxos.map((utxo) => {
				existingUtxos[utxo.scriptHash] = utxo;
			});

			const data: TUnspentAddressScriptHashData = {
				...addresses,
				...changeAddresses,
				...existingUtxos
			};

			return this.listUnspentAddressScriptHashes({ addresses: data });
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns available transactions from electrum based on the provided txHashes.
	 * @param {ITxHash[]} txHashes
	 * @return {Promise<Result<IGetTransactions>>}
	 */
	async getTransactions({
		txHashes = []
	}: {
		txHashes: ITxHash[];
	}): Promise<Result<IGetTransactions>> {
		try {
			if (txHashes.length < 1) {
				return ok({
					error: false,
					id: 0,
					method: 'getTransactions',
					network: this.electrumNetwork,
					data: []
				});
			}

			const result: ITransaction<IUtxo>[] = [];
			const promises: Promise<IGetTransactions>[] = [];

			// split payload in chunks of 10 transactions per-request
			for (let i = 0; i < txHashes.length; i += this.batchLimit) {
				const chunk = txHashes.slice(i, i + this.batchLimit);

				const data = {
					key: 'tx_hash',
					data: chunk
				};

				promises.push(
					electrum.getTransactions({
						txHashes: data,
						network: this.electrumNetwork
					})
				);
				await sleep(this.batchDelay);
			}
			const responses = await Promise.all(promises);
			responses.forEach((response) => {
				if (!response.error) result.push(...response.data);
			});
			return ok({
				error: false,
				id: 0,
				method: 'getTransactions',
				network: this.electrumNetwork,
				data: result
			});
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Determines whether a transaction exists based on the transaction response from electrum.
	 * @param {ITransaction<IUtxo>} txData
	 * @returns {boolean}
	 */
	public transactionExists(txData: ITransaction<IUtxo>): boolean {
		if (
			// @ts-ignore
			txData?.error &&
			// @ts-ignore
			txData?.error?.message &&
			/No such mempool or blockchain transaction|Invalid tx hash/.test(
				// @ts-ignore
				txData?.error?.message
			)
		) {
			//Transaction was removed/bumped from the mempool or potentially reorg'd out.
			return false;
		}
		return true;
	}

	/**
	 * Returns the block hex of the provided block height.
	 * @param {number} [height]
	 * @param {TAvailableNetworks} [selectedNetwork]
	 * @returns {Promise<Result<string>>}
	 */
	public async getBlockHex({
		height = 0
	}: {
		height?: number;
	}): Promise<Result<string>> {
		const response: IGetHeaderResponse = await electrum.getHeader({
			height,
			network: this.electrumNetwork
		});
		if (response.error) {
			return err(response.data);
		}
		return ok(response.data);
	}

	/**
	 * Returns the block hash given a block hex.
	 * Leaving blockHex empty will return the last known block hash from storage.
	 * @param {string} [blockHex]
	 * @param {TAvailableNetworks} [selectedNetwork]
	 * @returns {string}
	 */
	public getBlockHashFromHex({ blockHex }: { blockHex?: string }): string {
		// If empty, return the last known block hex from storage.
		if (!blockHex) {
			const { hex } = this.getBlockHeader();
			blockHex = hex;
		}
		if (!blockHex) return '';
		const block = Block.fromHex(blockHex);
		const hash = block.getId();
		return hash;
	}

	/**
	 * Returns last known block height, and it's corresponding hex from local storage.
	 * @returns {IHeader}
	 */
	public getBlockHeader(): IHeader {
		return this.wallet.data.header;
	}

	/**
	 * Block id of the PARENT recorded inside an 80 byte header hex, or '' when
	 * there is no hex or it does not parse. Every header carries its parent, so
	 * whether one block builds on another is answerable from what is already in
	 * hand, with no round trip to a server.
	 */
	private getPrevBlockHash(blockHex?: string): string {
		if (!blockHex) return '';
		try {
			const { prevHash } = Block.fromHex(blockHex);
			if (!prevHash) return '';
			// Internal byte order on the wire, display order everywhere the
			// wallet compares hashes.
			return Buffer.from(prevHash).reverse().toString('hex');
		} catch {
			return '';
		}
	}

	/**
	 * Returns transactions associated with the provided transaction hashes.
	 * @param {ITxHash[]} txHashes
	 * @return {Promise<Result<IGetTransactionsFromInputs>>}
	 */
	async getTransactionsFromInputs({
		txHashes = []
	}: {
		txHashes: ITxHash[];
	}): Promise<Result<IGetTransactionsFromInputs>> {
		try {
			const data = {
				key: 'tx_hash',
				data: txHashes
			};
			const response = await electrum.getTransactions({
				txHashes: data,
				network: this.electrumNetwork
			});
			if (response && !response.error) {
				return ok(response);
			} else {
				if (response?.error?.message) return err(response.error.message);
				return err(response ?? 'Unable to get transactions from inputs.');
			}
		} catch (e) {
			return err(e);
		}
	}

	/**
	 * Returns the merkle branch to a confirmed transaction given its hash and height.
	 * @param {string} tx_hash
	 * @param {number} height
	 * @returns {Promise<{ merkle: string[]; block_height: number; pos: number }>}
	 */
	async getTransactionMerkle({
		tx_hash,
		height
	}: {
		tx_hash: string;
		height: number;
	}): Promise<{
		merkle: string[];
		block_height: number;
		pos: number;
	}> {
		return await electrum.getTransactionMerkle({
			tx_hash,
			height,
			network: this.electrumNetwork
		});
	}

	/**
	 * Stores a header in this instance's wallet and reconciles the rollback it
	 * implies, if any.
	 *
	 * Every header write goes through here, the one a (re)subscribe answers
	 * with included: a header below the stored one is the only evidence of a
	 * rollback this instance gets, and writing it straight to storage spends
	 * that evidence. The stored height silently drops, and the next
	 * notification, higher than what was written, then reads as ordinary
	 * growth, so a chain that rolled back while this process was away, or
	 * while it was talking to a server that has since been swapped out, is
	 * never reconciled at all.
	 *
	 * The height alone does not settle it, and the hash is right there in the
	 * header. A tip REPLACED at the same height is a rollback although the
	 * chain never got shorter: the block this wallet's transactions were
	 * confirmed in is gone. A chain that rolled back and rebuilt taller while
	 * the process was away arrives ABOVE the stored tip and read as ordinary
	 * growth. And a server one block behind, which is what a failover normally
	 * lands on, read as a rollback and fired a 'reorg' message at every wallet
	 * on the network. Every header carries its parent, so the three are told
	 * apart from what is already in hand.
	 */
	private async applyHeader(header: IHeader): Promise<Result<string>> {
		const stored = this.getBlockHeader();
		// A fresh wallet's header is { height: 0, hash: '', hex: '' } and older
		// storage may carry a hex with no hash, so the hash is derived when it
		// has to be. With nothing to compare against, the height-only reading
		// this always had is kept.
		const storedHash =
			stored.hash ||
			(stored.hex ? this.getBlockHashFromHex({ blockHex: stored.hex }) : '');
		let reorgDetected = this._reorgOwed || header.height < stored.height;
		if (!this._reorgOwed && storedHash && stored.height) {
			if (header.height === stored.height) {
				// A different block at the stored height: the stored one was
				// orphaned, and writing this one on top is what spends the
				// evidence.
				reorgDetected = header.hash !== storedHash;
			} else if (header.height === stored.height + 1) {
				// The ordinary block-by-block case, and the only hot one. A
				// successor that does not build on the stored tip means the
				// stored tip is gone, however much taller the chain now is.
				reorgDetected = this.getPrevBlockHash(header.hex) !== storedHash;
			} else if (
				header.height === stored.height - 1 &&
				this.getPrevBlockHash(stored.hex) === header.hash
			) {
				// Exactly the stored tip's parent, on this very chain: the
				// server is simply a block behind, which is the common state
				// right after a failover. It holds no block at the stored
				// height and so has nothing to say about it. Not stored either:
				// lowering the tip here would spend the evidence of a rollback
				// that orphaned it, and the server's next header settles it
				// (a replacement at the stored height reads as a rollback, the
				// stored tip rebuilt reads as the header already stored).
				return ok('Header below the stored tip ignored.');
			}
			// A gap of more than one block in either direction is left with the
			// height-only reading: the wallet stores one tip, so it holds no
			// evidence about the blocks in between.
		}
		// The header this wallet already holds, with nothing owed on it: the
		// tip is re-applied on every subscribe, and the reconnect monitor makes
		// one of those a poll, so this is the common case rather than the rare
		// one. Persisting it again would buy nothing.
		if (
			!reorgDetected &&
			header.height === stored.height &&
			header.hash === storedHash
		) {
			return ok('Header already stored.');
		}
		// Owed before the WRITE, not after it, for the same reason the
		// comparison above exists: Wallet.updateHeader replaces the in-memory
		// header before it awaits storage, so a write that rejects has already
		// replaced the height the rollback was read from. The debt has to
		// outlive the write as well as the reconciliation, and be retried by
		// the next header rather than forgotten.
		if (reorgDetected) this._reorgOwed = true;
		await this._wallet.updateHeader(header);
		if (!reorgDetected) return ok('Header stored.');
		const reconciled = await this._wallet.checkUnconfirmedTransactions(true);
		if (reconciled.isErr()) return err(reconciled.error.message);
		this._reorgOwed = false;
		return ok('Header stored and reconciled.');
	}

	/**
	 * Applies a header that arrived outside the notification path, the one a
	 * (re)subscribe answers with, to every instance on the network.
	 *
	 * Only one instance ever holds that answer: the client keeps a single
	 * subscription per network for the whole process and tells every other
	 * subscriber "Already Subscribed." without a header, and an instance that
	 * is not the one reconnecting is never asked at all. Handing it to that one
	 * wallet alone would leave every other wallet's stored height above a chain
	 * that rolled back, with the notification that follows too high to reveal
	 * it, which is the same bug the reconnect one had.
	 */
	private async applyReportedHeader(header: IHeader): Promise<Result<string>> {
		const router = getHeaderRouter(this.electrumNetwork);
		router.last = header;
		router.seq++;
		let failure = '';
		for (const instance of [...router.handlers.keys()]) {
			// Re-read rather than taken from the snapshot, as the dispatch does:
			// an instance that withdrew while a wallet ahead of it was writing
			// must not have a header applied to it after all.
			if (!router.handlers.has(instance)) continue;
			const applied = await instance.applyHeader(header);
			// Reported, so the caller keeps the restore owed and retries, which
			// is what re-drives the reconciliation for every wallet here. One
			// failing wallet must not stop the rest from being reconciled.
			if (applied.isErr()) failure = applied.error.message;
		}
		return failure ? err(failure) : ok('Header applied.');
	}

	/**
	 * Applies a new block header to this instance's wallet. Handed to the
	 * shared per-network header router rather than to the client directly, so
	 * every subscribed instance is reached by the one handler the client keeps.
	 */
	private readonly _onNewBlock = async (data: INewBlock[]): Promise<void> => {
		const hex = data[0].hex;
		const hash = this.getBlockHashFromHex({ blockHex: hex });
		const header: IHeader = { ...data[0], hash };
		// Recorded for the instances this notification does not reach: one that
		// subscribes later is answered "Already Subscribed." and carries no
		// header of its own to reconcile against.
		const router = getHeaderRouter(this.electrumNetwork);
		router.last = header;
		router.seq++;
		// A failed reconciliation is owed inside applyHeader and retried by the
		// next header, so there is nothing for a notification to report.
		await this.applyHeader(header);
		// The dispatch no longer runs the instances one at a time, so the
		// withdrawal it used to honour by re-reading the map before each call
		// is honoured here instead: disconnect() may have landed while the
		// header write above was in flight, and a wallet that has stopped must
		// not be refreshed or called back into. Checked after applyHeader, so a
		// reconciliation this instance owes is still recorded in _reorgOwed.
		if (this._disconnected) return;
		await this._wallet.refreshWallet();
		this.onReceive?.(data);
		this.sendMessage(onMessageKeys.newBlock, data[0]);
	};

	/**
	 * Subscribes to the current networks headers.
	 * @return {Promise<Result<string>>}
	 */
	public async subscribeToHeader(): Promise<Result<IHeader>> {
		return (await this.subscribeToHeaderInternal()).result;
	}

	/**
	 * The subscribe itself, with the reconciliation debt reported apart from
	 * the subscription result.
	 *
	 * A reconciliation that failed is wallet data debt on a subscription that
	 * is registered, wired and answering, and only the restore may read it: it
	 * is the one caller that retries it. Reported as a subscribe failure, it
	 * told ElectrumBackend's reconnect monitor to count a ping failure, three
	 * of which fail the server over although the debt is not the server's, and
	 * told ChainWatcher.start it had no header subscription, so the watcher
	 * refused to accept work at all. It is another wallet's debt as often as
	 * this one's: applyReportedHeader reports whichever instance on the
	 * network failed.
	 */
	private async subscribeToHeaderInternal(): Promise<{
		result: Result<IHeader>;
		reconcileOwed: boolean;
	}> {
		// disconnect() withdrew this instance from the shared header router, and
		// a caller that outlived it (an ElectrumBackend reconnect monitor still
		// ticking after wallet.stop()) must not put it back: _onNewBlock would
		// then refresh a wallet that has shut down. A stopped instance owes
		// nothing either: disconnect() cleared the restore debt.
		if (this._disconnected) {
			return { result: err(DISCONNECTED_ERROR), reconcileOwed: false };
		}
		const electrumNetwork = this.electrumNetwork;
		const router = getHeaderRouter(electrumNetwork);
		// Registered before the call, and left registered on "Already
		// Subscribed.": the client wires a handler only for the first subscribe
		// on the network, so this is what makes the later instances (and the
		// ones a client reset silenced) receive headers at all.
		let state = this._headerSubscribes.get(electrumNetwork);
		if (!state) {
			state = { inFlight: 0, committed: false };
			this._headerSubscribes.set(electrumNetwork, state);
		}
		// A handler already registered predates this attempt, so a failure here
		// must not withdraw it.
		if (router.handlers.has(this)) state.committed = true;
		router.handlers.set(this, this._onNewBlock);
		// Read when the request actually goes out, not when this caller queued
		// behind another one, so the response below can be told apart from a
		// header that overtook it: see THeaderRouter.seq.
		let seenAt = router.seq;
		const run = async (): Promise<ISubscribeToHeader> => {
			seenAt = router.seq;
			return electrum.subscribeHeader({
				network: electrumNetwork,
				onReceive: router.dispatch
			});
		};
		// Queued behind whatever subscribe this network already has in flight,
		// settled or thrown: see headerSubscribeGates. A failed predecessor
		// leaves the network unsubscribed, and the caller behind it is the one
		// that re-issues the request.
		const previous = headerSubscribeGates.get(electrumNetwork);
		const attempt = previous ? previous.then(run, run) : run();
		const gate = attempt.then(
			() => undefined,
			() => undefined
		);
		headerSubscribeGates.set(electrumNetwork, gate);
		void gate.then(() => {
			if (headerSubscribeGates.get(electrumNetwork) === gate) {
				headerSubscribeGates.delete(electrumNetwork);
			}
		});
		// Counted around the wait as a whole, the queued part included, so a
		// caller still waiting its turn keeps a failing sibling from rolling
		// back the handler it is about to rely on.
		state.inFlight++;
		let subscribeResponse: ISubscribeToHeader;
		try {
			subscribeResponse = await attempt;
		} finally {
			state.inFlight--;
		}
		// Checked again: a disconnect that landed while the subscribe was in
		// flight already withdrew the handler registered above, so it stays
		// withdrawn and the header stays out of a stopped wallet.
		if (this._disconnected) {
			return { result: err(DISCONNECTED_ERROR), reconcileOwed: false };
		}
		if (subscribeResponse.error) {
			// Rolled back only when this attempt is the last word: a concurrent
			// call that already succeeded, or one still in flight, owns the
			// handler now, and deleting it would silence a live subscription.
			if (!state.committed && state.inFlight === 0) {
				router.handlers.delete(this);
			}
			// A real subscription fault, which every caller must see: this is
			// what the reconnect monitor counts and what ChainWatcher.start
			// refuses to start without.
			return {
				result: err('Unable to subscribe to headers.'),
				reconcileOwed: false
			};
		}
		state.committed = true;
		// eslint-disable-next-line @typescript-eslint/ban-ts-comment
		// @ts-ignore
		if (subscribeResponse?.data === 'Already Subscribed.') {
			// The client answers a network it already holds a subscription for
			// with that bare string and no header, so the tip the last
			// subscribe or notification reported is all there is to reconcile
			// against, and this instance may well have registered after it
			// landed. Re-applied to everyone, because this is also the call the
			// restore retries with, and a reconciliation that failed the first
			// time is owed by whichever wallets it failed for.
			if (router.last) {
				const applied = await this.applyReportedHeader(router.last);
				return {
					result: ok(this.getBlockHeader()),
					reconcileOwed: applied.isErr()
				};
			}
			return { result: ok(this.getBlockHeader()), reconcileOwed: false };
		}
		// Update local storage with current height and hex. Reconciled rather
		// than written, because a subscribe is exactly where a rollback shows
		// up: this is the first header the wallet sees after a reconnect, and
		// after a failover it comes from a server the wallet has never spoken
		// to.
		const hex = subscribeResponse.data.hex;
		const hash = this.getBlockHashFromHex({ blockHex: hex });
		const header: IHeader = { ...subscribeResponse.data, hash };
		// A header that landed while this response was in flight came from the
		// same socket and is the fresher of the two, and it has already been
		// applied and reconciled. Writing this one on top of it would lower the
		// stored height and turn the next block into a rollback that never
		// happened.
		if (router.seq !== seenAt) {
			// The notification that overtook this response applied and owes its
			// own reconciliation through _reorgOwed.
			return { result: ok(this.getBlockHeader()), reconcileOwed: false };
		}
		const applied = await this.applyReportedHeader(header);
		// The restore reads this: a wallet left holding an unreconciled
		// rollback has not been restored, whatever the subscription itself did.
		// The header is stored either way, because applyHeader writes before it
		// reconciles, so the subscription answers ok with it.
		return { result: ok(header), reconcileOwed: applied.isErr() };
	}

	/**
	 * This instance's subscription record for a script hash in the shared
	 * per-network router, created on demand. Every subscribed hash gets a
	 * record so notifications refresh exactly the wallets that subscribed it.
	 */
	private _scriptHashRecord(scriptHash: string): TScriptHashSubscription {
		const router = getScriptHashRouter(this.electrumNetwork);
		router.instances.add(this);
		let subs = router.subscriptions.get(scriptHash);
		if (!subs) {
			subs = new Map();
			router.subscriptions.set(scriptHash, subs);
		}
		let sub = subs.get(this);
		if (!sub) {
			sub = { callbacks: new Set() };
			subs.set(this, sub);
		}
		return sub;
	}

	/**
	 * Detach a callback previously handed to subscribeToAddresses (matched by
	 * function reference). Notifications for the hash stop reaching that
	 * callback; the wallet refresh on notification is unaffected.
	 */
	removeScriptHashCallback({
		scriptHash,
		onReceive
	}: {
		scriptHash: string;
		onReceive: (data: TSubscribedReceive) => void;
	}): boolean {
		const router = scriptHashRouters.get(this.electrumNetwork);
		const subs = router?.subscriptions.get(scriptHash);
		const sub = subs?.get(this);
		if (!router || !subs || !sub) {
			return false;
		}
		const removed = sub.callbacks.delete(onReceive);
		if (sub.callbacks.size === 0 && sub.utxoIndex === undefined) {
			subs.delete(this);
			if (subs.size === 0) {
				router.subscriptions.delete(scriptHash);
			}
		}
		return removed;
	}

	/**
	 * Subscribes to a number of address script hashes for receiving.
	 * @param {string[]} scriptHashes
	 * @param onReceive
	 * @return {Promise<Result<string>>}
	 */
	async subscribeToAddresses({
		scriptHashes = [],
		onReceive
	}: {
		scriptHashes?: string[];
		onReceive?: (data: TSubscribedReceive) => void;
	} = {}): Promise<Result<string>> {
		// Same guard the restore path carries: every subscribe below registers
		// this instance in the shared script hash router, where a notification
		// refreshes its wallet. A caller that outlived disconnect() must not put
		// a stopped wallet back on that path.
		if (this._disconnected) return err(DISCONNECTED_ERROR);
		const allUtxos: IUtxo[] = [];
		const currentWallet = this._wallet.data;
		const addressTypeKeys = this._wallet.addressTypesToMonitor;
		// Gather the receiving address scripthash for each address type if no scripthashes were provided.
		if (!scriptHashes.length) {
			for (const addressType of addressTypeKeys) {
				const addresses = currentWallet.addresses[addressType];
				const addressCount = Object.keys(addresses).length;

				// Check if addresses of this type have been generated. If not, skip.
				if (addressCount > 0) {
					let addressIndex = currentWallet.addressIndex[addressType]?.index;
					addressIndex = addressIndex > 0 ? addressIndex : 0;

					// Only subscribe up to the gap limit.
					const addressesInRangeToSubscribe = filterAddressesForGapLimit({
						addresses: Object.values(addresses),
						index: addressIndex,
						gapLimitOptions: this._wallet.gapLimitOptions,
						change: false
					});
					const _scriptHashes = addressesInRangeToSubscribe.map(
						(address) => address.scriptHash
					);
					scriptHashes.push(..._scriptHashes);
				}
			}
			// Keep an eye on existing UTXO's regardless of the gap limit.
			currentWallet.utxos.forEach((utxo) => {
				if (!scriptHashes.includes(utxo.scriptHash)) {
					allUtxos.push(utxo);
				}
			});
		}

		// Subscribe to all provided script hashes. Callbacks are registered
		// before the client call: the protocol subscription can deliver a
		// notification immediately, and a repeat hash resolves as "Already
		// Subscribed." without touching the client's own handler wiring. On
		// failure, only what this attempt added is rolled back, so a caller
		// retrying with a fresh closure cannot accumulate dead callbacks and a
		// concurrent subscription for the same hash keeps its own.
		const dispatch = getScriptHashRouter(this.electrumNetwork).dispatch;
		const allScriptHashesPromises = scriptHashes.map(async (scriptHash) => {
			const sub = this._scriptHashRecord(scriptHash);
			const added = onReceive ? !sub.callbacks.has(onReceive) : false;
			if (onReceive) {
				sub.callbacks.add(onReceive);
			}
			const response: ISubscribeToAddress = await electrum.subscribeAddress({
				scriptHash,
				network: this.electrumNetwork,
				onReceive: dispatch
			});
			if (response.error) {
				if (added && onReceive) {
					this.removeScriptHashCallback({ scriptHash, onReceive });
				}
				throw Error('Unable to subscribe to receiving addresses.');
			}
		});

		const allUtxosPromises = allUtxos.map(async (utxo) => {
			const sub = this._scriptHashRecord(utxo.scriptHash);
			const added = onReceive ? !sub.callbacks.has(onReceive) : false;
			if (onReceive) {
				sub.callbacks.add(onReceive);
			}
			sub.utxoIndex = utxo.index;
			const response: ISubscribeToAddress = await electrum.subscribeAddress({
				scriptHash: utxo.scriptHash,
				network: this.electrumNetwork,
				onReceive: dispatch
			});
			if (response.error) {
				if (added && onReceive) {
					this.removeScriptHashCallback({
						scriptHash: utxo.scriptHash,
						onReceive
					});
				}
				throw Error('Unable to subscribe to receiving addresses.');
			}
		});

		try {
			await Promise.all([...allScriptHashesPromises, ...allUtxosPromises]);
		} catch (e) {
			return err(e);
		}

		return ok('Successfully subscribed to addresses.');
	}

	public async broadcastTransaction({
		rawTx,
		subscribeToOutputAddress = true
	}: {
		rawTx: string;
		subscribeToOutputAddress?: boolean;
	}): Promise<Result<string>> {
		/**
		 * Subscribe to the output address and refresh the wallet when the Electrum server detects it.
		 * This prevents updating the wallet prior to the Electrum server detecting the new tx in the mempool.
		 */
		if (subscribeToOutputAddress) {
			const transaction = this._wallet.transaction.data;
			await Promise.all(
				transaction.outputs.map(async (o) => {
					const address = o?.address;
					if (address) {
						const scriptHash = getScriptHash({
							address,
							network: this.network
						});
						if (scriptHash) {
							await this.subscribeToAddresses({
								scriptHashes: [scriptHash]
							});
						}
					}
				})
			);
		}

		const broadcastResponse = await electrum.broadcastTransaction({
			rawTx,
			network: this.electrumNetwork
		});
		// TODO: This needs to be resolved in rn-electrum-client
		if (broadcastResponse.error || broadcastResponse.data.includes(' ')) {
			return err(broadcastResponse.data);
		}
		return ok(broadcastResponse.data);
	}

	/**
	 * Attempts to check the current Electrum connection.
	 * @private
	 * @returns {Promise<void>}
	 */
	private async checkConnection(): Promise<void> {
		try {
			const { error } = await electrum.pingServer();

			if (error) {
				this.wallet.logger.info(
					'Connection to Electrum Server lost, reconnecting...'
				);
				// A successful connect re-subscribes every script hash this
				// process holds and re-issues the header subscription itself, so
				// there is nothing left to re-issue here.
				const response = await this.connectToElectrum({
					network: this.network,
					servers: this.servers
				});

				if (response.isErr()) {
					this.publishConnectionChange(false);
				}
			} else {
				this.publishConnectionChange(true);
				// The socket is fine, so no reconnect will run the restore a
				// previous connect left owed. This is its only other retry hook.
				if (this._restoreOwed === this.electrumNetwork && !this._disconnected) {
					this.restoreSubscriptionsBestEffort(this.electrumNetwork);
				}
			}
		} catch (e) {
			this.wallet.logger.error('Electrum connection check failed.', e);
			this.publishConnectionChange(false);
		}
	}

	private publishConnectionChange(isConnected: boolean): void {
		const stateChanged = this.latestConnectionState !== isConnected;
		// Internal truth always tracks, including mid-switch: the reconnect
		// guards read connectedToElectrum, and a stale true would survive a
		// failed switch connect otherwise.
		this.connectedToElectrum = isConnected;
		// Externally observable transition events stay suppressed during a
		// switch. latestConnectionState is deliberately left alone then, so
		// the first check after the switch announces the final state instead
		// of assuming it was already published.
		if (this.wallet.isSwitchingNetworks || !stateChanged) return;
		this.sendMessage('connectedToElectrum', isConnected);
		this.latestConnectionState = isConnected;
	}

	public async disconnect(): Promise<void> {
		this.stopConnectionPolling();
		// Withdraw from the shared routers: a notification routed after this
		// point must not refresh or call back into a wallet that is shutting
		// down. The flag keeps work still in flight (a subscription restore
		// mid-await) from quietly registering the instance back.
		this._disconnected = true;
		// The debt goes with the instance: the next connect restores
		// unconditionally anyway, and the poll that would retry it is stopped.
		this._restoreOwed = null;
		for (const router of headerRouters.values()) {
			router.handlers.delete(this);
		}
		// The withdrawn handlers are no longer registered, so nothing a later
		// subscribe installs predates them. The entries themselves are kept, so
		// a subscribe still in flight keeps sharing state with the ones a
		// reconnect issues rather than rolling back their handler.
		for (const state of this._headerSubscribes.values()) {
			state.committed = false;
		}
		for (const router of scriptHashRouters.values()) {
			router.instances.delete(this);
			for (const [scriptHash, subs] of router.subscriptions) {
				subs.delete(this);
				if (subs.size === 0) {
					router.subscriptions.delete(scriptHash);
				}
			}
		}
		await electrum.stop();
	}

	public startConnectionPolling(): void {
		if (this.connectionPollingInterval) return;
		this.connectionPollingInterval = setInterval((): void => {
			void this.checkConnection();
		}, POLLING_INTERVAL);
	}

	public stopConnectionPolling(): void {
		if (this.connectionPollingInterval) {
			clearInterval(this.connectionPollingInterval);
			this.connectionPollingInterval = null;
		}
	}
}
