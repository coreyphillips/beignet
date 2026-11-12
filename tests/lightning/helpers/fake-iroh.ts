/**
 * A stand-in for the @number0/iroh Endpoint class, so the Node backend can be
 * driven without a network: which builder calls it made, what the endpoint's
 * sockets and address list read, and whether it was closed.
 */
const sinon = require('sinon');

export interface IFakeIrohEndpoint {
	/** What boundSockets() reports. */
	sockets: string[];
	/** What addr().directAddresses() reports; change it to move the list. */
	addresses: string[];
	relayUrl?: string;
	/** Every setAlpns call, in order. */
	alpns: number[][][];
	/** How many outbound connects reached the binding (each one fails). */
	connects: number;
	closed: boolean;
}

export interface IFakeIrohBuilder {
	calls: string[];
	bindAddrs: string[];
	endpoint: IFakeIrohEndpoint;
}

export interface IFakeIrohBinding {
	/** One entry per Endpoint.builder() call, in order. */
	builders: IFakeIrohBuilder[];
	restore(): void;
}

export interface IFakeIrohOptions {
	/** Expose clearIpTransports on the builder, as a newer binding would. */
	native?: boolean;
	/** Fail the bind of the builder at this index (0 is the first one). */
	failBind?: (builder: IFakeIrohBuilder, index: number) => boolean;
	/** The state of each endpoint as it binds. */
	endpoint?: (builder: IFakeIrohBuilder) => Partial<IFakeIrohEndpoint>;
}

/**
 * Replace binding.Endpoint for the life of a test. Call restore() afterwards.
 * Throws when the optional binding is not installed; callers skip on that.
 */
export function fakeIrohBinding(
	options: IFakeIrohOptions = {}
): IFakeIrohBinding {
	const binding = require('@number0/iroh/index.js');
	const builders: IFakeIrohBuilder[] = [];
	const pending = new Promise<never>(() => undefined);
	const stub = sinon.stub(binding, 'Endpoint').value({
		builder: (): unknown => {
			const record: IFakeIrohBuilder = {
				calls: [],
				bindAddrs: [],
				endpoint: {
					sockets: [],
					addresses: [],
					alpns: [],
					connects: 0,
					closed: false
				}
			};
			const index = builders.length;
			builders.push(record);
			const note = (name: string) => (): void => {
				record.calls.push(name);
			};
			return {
				applyN0: note('applyN0'),
				applyMinimal: note('applyMinimal'),
				relayMode: note('relayMode'),
				secretKey: note('secretKey'),
				alpns: note('alpns'),
				bindAddr: (address: string): void => {
					record.calls.push('bindAddr');
					record.bindAddrs.push(address);
				},
				...(options.native
					? { clearIpTransports: note('clearIpTransports') }
					: {}),
				bind: async (): Promise<unknown> => {
					record.calls.push('bind');
					if (options.failBind?.(record, index))
						throw new Error('Address family not supported');
					const state = record.endpoint;
					state.sockets = record.bindAddrs.length
						? record.bindAddrs.map((address) => address.replace(/:0$/, ':4433'))
						: options.native
						? []
						: ['0.0.0.0:4433', '[::]:4433'];
					state.addresses = state.sockets.filter(
						(address) =>
							!address.startsWith('0.0.0.0') && address !== '[::]:4433'
					);
					Object.assign(state, options.endpoint?.(record));
					return {
						boundSockets: (): string[] => state.sockets,
						addr: (): unknown => ({
							relayUrl: (): string | undefined => state.relayUrl,
							directAddresses: (): string[] => state.addresses
						}),
						id: (): unknown => ({
							toBytes: (): number[] => Array(32).fill(7)
						}),
						acceptNext: (): Promise<never> => pending,
						connect: async (): Promise<never> => {
							state.connects++;
							throw new Error('no route');
						},
						setAlpns: (alpns: number[][]): void => {
							state.alpns.push(alpns);
						},
						close: async (): Promise<void> => {
							state.closed = true;
						}
					};
				}
			};
		}
	});
	return { builders, restore: (): void => stub.restore() };
}
