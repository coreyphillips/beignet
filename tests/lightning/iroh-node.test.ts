import { expect } from 'chai';
import { createNodeIrohEndpoint } from '../../src/lightning/transport/iroh-node';
import { IDuplexTransport } from '../../src/lightning/transport/duplex-transport';
const sinon = require('sinon');

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}

describe('Iroh native stream admission', () => {
	let binding: typeof import('@number0/iroh');
	before(function () {
		try {
			binding = require('@number0/iroh/index.js');
		} catch {
			this.skip();
		}
	});

	for (const direction of ['inbound', 'outbound']) {
		for (const kind of ['bidirectional', 'unidirectional']) {
			it(`closes an ${direction} connection on an unexpected ${kind} stream`, async () => {
				const extraBi = deferred<unknown>();
				const extraUni = deferred<unknown>();
				const incoming = deferred<unknown>();
				const pending = new Promise<never>(() => undefined);
				const stream = {
					recv: { read: (): Promise<never> => pending },
					send: { writeAll: async (): Promise<void> => undefined }
				};
				const connection = {
					acceptBi: sinon.stub().returns(extraBi.promise),
					acceptUni: sinon.stub().returns(extraUni.promise),
					openBi: async (): Promise<typeof stream> => stream,
					setMaxConcurrentBiStreams: sinon.spy(),
					setMaxConcurrentUniStreams: sinon.spy(),
					remoteId: (): { toBytes: () => number[] } => ({
						toBytes: (): number[] => Array(32).fill(1)
					}),
					paths: (): [] => [],
					closed: (): Promise<never> => pending,
					close: sinon.spy()
				};
				if (direction === 'inbound')
					connection.acceptBi.onFirstCall().resolves(stream);
				const native = {
					acceptNext: sinon.stub().returns(pending),
					connect: async (): Promise<typeof connection> => connection,
					setAlpns: (): void => undefined,
					close: async (): Promise<void> => undefined
				};
				if (direction === 'inbound')
					native.acceptNext.onFirstCall().returns(incoming.promise);
				const builderOptions = {
					applyN0: (): void => undefined,
					secretKey: (): void => undefined,
					alpns: (): void => undefined,
					bind: async (): Promise<typeof native> => native
				};
				const builder = sinon.stub(binding, 'Endpoint').value({
					builder: (): typeof builderOptions => builderOptions
				});
				let socket: IDuplexTransport | undefined;
				const endpoint = await createNodeIrohEndpoint({
					secretKey: Buffer.alloc(32, 1)
				});
				try {
					if (direction === 'inbound') {
						const accepted = deferred<IDuplexTransport>();
						endpoint.listen(accepted.resolve, (error) => {
							throw error;
						});
						incoming.resolve({
							accept: async (): Promise<{
								connect: () => Promise<typeof connection>;
							}> => ({
								connect: async (): Promise<typeof connection> => connection
							})
						});
						socket = await accepted.promise;
					} else {
						socket = await endpoint.connect(
							{
								endpointId:
									'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
							},
							1000
						);
					}
					expect(
						connection.setMaxConcurrentBiStreams.firstCall.args
					).to.deep.equal([direction === 'inbound' ? 1n : 0n]);
					expect(
						connection.setMaxConcurrentUniStreams.firstCall.args
					).to.deep.equal([0n]);
					expect(connection.close.called).to.equal(false);
					(kind === 'bidirectional' ? extraBi : extraUni).resolve({});
					await new Promise((resolve) => setImmediate(resolve));
					expect(connection.close.calledOnce).to.equal(true);
					expect(connection.close.firstCall.args[0]).to.equal(1n);
				} finally {
					socket?.destroy();
					await endpoint.close();
					builder.restore();
				}
			});
		}
	}
});
