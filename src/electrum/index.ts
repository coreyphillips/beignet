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

function getHeaderRouter(network: EElectrumNetworks): THeaderRouter {
	let router = headerRouters.get(network);
	if (!router) {
		const created: THeaderRouter = {
			handlers: new Map(),
			dispatch: async (data: INewBlock[]): Promise<void> => {
				// Snapshot: a handler may disconnect its instance mid-dispatch.
				for (const handler of [...created.handlers.values()]) {
					try {
						await handler(data);
					} catch {
						// One instance must not starve the rest.
					}
				}
			}
		};
		router = created;
		headerRouters.set(network, created);
	}
	return router;
}

/**
 * Networks whose client was torn down with its subscriptions still owed.
 * Module state because the client is per network for the whole process: the
 * instance that reset it and the instance that reconnects need not be the same
 * one, so the debt belongs to the network rather than to whoever noticed it.
 * Survives failed attempts, too: a switch that resets the client and then
 * reaches no server at all still owes the restore to whichever later connect
 * succeeds.
 */
const subscriptionRestoreOwed: Set<EElectrumNetworks> = new Set();

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
	/** Set by disconnect(): this instance withdrew from the shared routers, so
	 *  work still in flight must not register it back into them. Cleared when a
	 *  new connect is explicitly requested. */
	private _disconnected = false;

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
		for (const candidate of this.orderCandidates(candidates)) {
			const startResponse = await this.attemptConnect(
				candidate,
				electrumNetwork
			);
			if (startResponse.clientReset) {
				subscriptionRestoreOwed.add(electrumNetwork);
			}
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
		if (subscriptionRestoreOwed.has(electrumNetwork)) {
			// The torn down client took every subscription in this process with
			// it, including the ones this instance never made, and the wallet's
			// own addresses have no other reconnect hook here (checkConnection
			// re-issues them only on its own reconnect path). Keyed on the reset
			// rather than on a server change: a switch that stops the peer and
			// then falls back to the server it started from resets exactly the
			// same state while leaving the current server untouched.
			this.restoreSubscriptionsBestEffort(electrumNetwork);
		}
		// Re-issues the shared header dispatcher, so every instance subscribed
		// to this network's headers is wired to the new client, not just this one.
		this.subscribeToHeader().catch(() => {
			// Best-effort: the header subscription is rebuilt on reconnect.
		});
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
		clientReset: boolean;
		teardownRefused?: boolean;
	}> {
		const teardown = await this.stopPeerIfServerChanged(
			server,
			electrumNetwork
		);
		if (teardown.error) {
			return {
				error: teardown.error,
				clientReset: teardown.clientReset,
				teardownRefused: true
			};
		}
		const startResponse = await electrum.start({
			clientName: 'beignet',
			protocolVersion: '1.4',
			network: electrumNetwork,
			net: this.net,
			tls: this.tls,
			customPeers: [server]
		});
		return { error: startResponse.error, clientReset: teardown.clientReset };
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
	 * and disconnects itself (resetting the same state) if the ping fails.
	 *
	 * The client only clears that bookkeeping when closing the socket succeeds
	 * and reports the failure as { error: true }, so a teardown that did not
	 * happen refuses the candidate instead of connecting a fresh client on top
	 * of stale state, which is the very bug this guards against. Rotation then
	 * moves on, and the still-connected server is accepted unchanged when it
	 * comes back around.
	 */
	private async stopPeerIfServerChanged(
		server: TServer,
		electrumNetwork: EElectrumNetworks
	): Promise<{ error?: string; clientReset: boolean }> {
		const peer = electrum.getConnectedPeer(electrumNetwork);
		if (!peer?.host) return { clientReset: false };
		const peerKey = `${peer.host}|${peer.protocol}|${peer.port}`;
		if (peerKey === this.serverKey(server)) return { clientReset: false };
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
				error: `Unable to disconnect from ${peer.host} before switching Electrum servers${reason}`,
				clientReset: false
			};
		}
		return { clientReset: true };
	}

	/**
	 * Re-issues every subscription this process holds for the network after the
	 * client was torn down.
	 *
	 * rn-electrum-client keeps one client, and with it one set of
	 * subscriptions and one notification handler, per network for the whole
	 * process, so a reset by any instance drops what every other instance
	 * subscribed as well. The shared script hash router is the record of that
	 * state; re-subscribing its hashes restores the handler wiring for all of
	 * them, and this instance's own wallet addresses are re-issued on top to
	 * pick up anything generated since.
	 */
	private async restoreSubscriptions(
		electrumNetwork: EElectrumNetworks
	): Promise<void> {
		if (this._disconnected) return;
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
	}

	/**
	 * Discharges the network's outstanding subscription restore, re-arming it
	 * for the next connect on this network if it does not fully succeed. Any
	 * instance may discharge it: the client, and therefore the debt, is shared.
	 */
	private restoreSubscriptionsBestEffort(
		electrumNetwork: EElectrumNetworks
	): void {
		subscriptionRestoreOwed.delete(electrumNetwork);
		this.restoreSubscriptions(electrumNetwork).catch(() => {
			subscriptionRestoreOwed.add(electrumNetwork);
		});
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
	 * Applies a new block header to this instance's wallet. Handed to the
	 * shared per-network header router rather than to the client directly, so
	 * every subscribed instance is reached by the one handler the client keeps.
	 */
	private readonly _onNewBlock = async (data: INewBlock[]): Promise<void> => {
		const hex = data[0].hex;
		const hash = this.getBlockHashFromHex({ blockHex: hex });
		const header: IHeader = { ...data[0], hash };
		const reorgDetected = header.height < this.getBlockHeader().height;
		await this._wallet.updateHeader(header);
		if (reorgDetected) {
			await this._wallet.checkUnconfirmedTransactions(reorgDetected);
		}
		await this._wallet.refreshWallet();
		this.onReceive?.(data);
		this.sendMessage(onMessageKeys.newBlock, data[0]);
	};

	/**
	 * Subscribes to the current networks headers.
	 * @return {Promise<Result<string>>}
	 */
	public async subscribeToHeader(): Promise<Result<IHeader>> {
		const router = getHeaderRouter(this.electrumNetwork);
		// Registered before the call, and left registered on "Already
		// Subscribed.": the client wires a handler only for the first subscribe
		// on the network, so this is what makes the later instances (and the
		// ones a client reset silenced) receive headers at all. Only what this
		// attempt added is rolled back on failure.
		const hadHandler = router.handlers.has(this);
		router.handlers.set(this, this._onNewBlock);
		const subscribeResponse: ISubscribeToHeader =
			await electrum.subscribeHeader({
				network: this.electrumNetwork,
				onReceive: router.dispatch
			});
		if (subscribeResponse.error) {
			if (!hadHandler) {
				router.handlers.delete(this);
			}
			return err('Unable to subscribe to headers.');
		}
		// eslint-disable-next-line @typescript-eslint/ban-ts-comment
		// @ts-ignore
		if (subscribeResponse?.data === 'Already Subscribed.') {
			return ok(this.getBlockHeader());
		}
		// Update local storage with current height and hex.
		const hex = subscribeResponse.data.hex;
		const hash = this.getBlockHashFromHex({ blockHex: hex });
		const header = { ...subscribeResponse.data, hash };
		await this._wallet.updateHeader(header);
		return ok(header);
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
				const response = await this.connectToElectrum({
					network: this.network,
					servers: this.servers
				});

				if (response.isOk()) {
					// Re-Subscribe to Addresses & Headers. A failed ping means the
					// client dropped the connection, so every instance's script
					// hashes went with it, not just this wallet's addresses.
					this.restoreSubscriptionsBestEffort(this.electrumNetwork);
					this.subscribeToHeader().catch(() => {
						/* best-effort re-subscribe on reconnect */
					});
				} else {
					this.publishConnectionChange(false);
				}
			} else {
				this.publishConnectionChange(true);
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
		for (const router of headerRouters.values()) {
			router.handlers.delete(this);
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
