import { ChildProcess, fork } from 'child_process';
import path from 'path';
import { ChannelState } from '../../../src/lightning/channel/types';
import { FforState } from '../../../src/lightning/ffor/types';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { INodeConfig, PaymentStatus } from '../../../src/lightning/node/types';

export interface IReceiverSnapshot {
	state: ChannelState;
	epochState: FforState;
	syncPending: boolean;
	outcomes?: ('fulfilled' | 'cancelled' | null)[];
	localBalanceMsat: bigint;
	vouchers: string[];
	payments: {
		status?: PaymentStatus;
		completedAt?: number;
		amountMsat?: bigint;
	}[];
	completions: number;
}

/** A production receiver with its own process and SQLite connection. */
export class FforReceiverProcess {
	private readonly child: ChildProcess;
	private nextId = 1;
	private readonly pending = new Map<
		number,
		{
			resolve: (value: unknown) => void;
			reject: (error: Error) => void;
			timer: NodeJS.Timeout;
		}
	>();
	readonly errors: string[] = [];
	readonly wireTypes: { from: 'S' | 'R'; type: number }[] = [];
	private connected = false;
	private reconnectQueue: (() => void)[] | null = null;
	private nodeId = '';
	private readonly outbound: (
		peer: string,
		type: number,
		payload: Buffer
	) => void;

	constructor(private readonly sender: LightningNode) {
		this.child = fork(path.join(__dirname, 'ffor-process-child.cjs'), [], {
			serialization: 'advanced',
			stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
			execArgv: ['-r', require.resolve('ts-node/register/transpile-only')]
		});
		this.child.stderr!.on('data', (chunk: Buffer) =>
			this.errors.push(chunk.toString())
		);
		this.child.on(
			'message',
			(message: {
				id?: number;
				value?: unknown;
				error?: string;
				event?: string;
				message?: string;
				peer?: string;
				type?: number;
				payload?: Buffer;
			}) => {
				if (message.event === 'wire') {
					this.wireTypes.push({ from: 'R', type: message.type! });
					if (this.connected && message.peer === sender.getNodeId()) {
						const deliver = (): void =>
							sender.handlePeerMessage(
								this.nodeId,
								message.type!,
								message.payload!
							);
						if (this.reconnectQueue) this.reconnectQueue.push(deliver);
						else deliver();
					}
					return;
				}
				if (message.event === 'error') {
					this.errors.push(message.message!);
					return;
				}
				const pending = this.pending.get(message.id!);
				if (!pending) return;
				this.pending.delete(message.id!);
				clearTimeout(pending.timer);
				if (message.error) pending.reject(new Error(message.error));
				else pending.resolve(message.value);
			}
		);
		this.child.on('exit', () => {
			for (const pending of this.pending.values()) {
				clearTimeout(pending.timer);
				pending.reject(new Error('receiver process exited'));
			}
			this.pending.clear();
		});
		this.outbound = (peer, type, payload): void => {
			if (peer === this.nodeId) this.wireTypes.push({ from: 'S', type });
			if (this.connected && peer === this.nodeId) {
				const deliver = (): void => {
					void this.call({
						op: 'message',
						peer: sender.getNodeId(),
						type,
						payload
					}).catch((error: Error) => this.errors.push(error.message));
				};
				if (this.reconnectQueue) this.reconnectQueue.push(deliver);
				else deliver();
			}
		};
		sender.on('message:outbound', this.outbound);
	}

	private call(request: Record<string, unknown>): Promise<unknown> {
		const id = this.nextId++;
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				reject(new Error(`receiver command timed out: ${request.op}`));
			}, 30_000);
			this.pending.set(id, { resolve, reject, timer });
			this.child.send({ ...request, id }, (error) => {
				if (!error) return;
				clearTimeout(timer);
				this.pending.delete(id);
				reject(error);
			});
		});
	}

	async start(
		config: INodeConfig,
		dbPath: string,
		height: number
	): Promise<void> {
		const { storage: _storage, ...plainConfig } = config;
		this.nodeId = (await this.call({
			op: 'init',
			config: plainConfig,
			peer: this.sender.getNodeId(),
			peerFeatures: this.sender.getLocalFeatures().toBuffer(),
			dbPath
		})) as string;
		await this.call({ op: 'block', height });
	}

	async reconnect(): Promise<void> {
		this.connected = true;
		// Both peers prepare reestablishment before either request is delivered.
		this.reconnectQueue = [];
		this.sender.getChannelManager().handlePeerReconnected(this.nodeId);
		await this.call({ op: 'reconnect', peer: this.sender.getNodeId() });
		while (this.reconnectQueue.length > 0) this.reconnectQueue.shift()!();
		this.reconnectQueue = null;
	}

	async sync(channelId: string): Promise<{ ok: boolean; error?: string }> {
		return (await this.call({ op: 'sync', channelId })) as {
			ok: boolean;
			error?: string;
		};
	}

	async inspect(channelId: string): Promise<IReceiverSnapshot> {
		return (await this.call({ op: 'inspect', channelId })) as IReceiverSnapshot;
	}

	async kill(): Promise<NodeJS.Signals | null> {
		this.connected = false;
		this.sender.removeListener('message:outbound', this.outbound);
		this.sender.getChannelManager().handlePeerDisconnected(this.nodeId);
		if (this.child.exitCode !== null || this.child.signalCode !== null)
			return this.child.signalCode;
		return new Promise((resolve) => {
			this.child.once('exit', (_code, signal) => resolve(signal));
			this.child.kill('SIGKILL');
		});
	}
}
