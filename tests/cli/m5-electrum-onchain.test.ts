import { expect } from 'chai';
import { BeignetNodeOptions } from '../../src/cli/beignet-node';
import { resolveConfig } from '../../src/cli/config';
import { getOpenApiSpec } from '../../src/cli/openapi';
import { encodeBip21 } from '../../src/utils/transaction';

describe('M5 Batch B: Electrum-layer improvements (CLI plumbing)', () => {
	describe('signet network option', () => {
		it('BeignetNodeOptions accepts signet', () => {
			const opts: BeignetNodeOptions = { network: 'signet' };
			expect(opts.network).to.equal('signet');
		});

		it('resolveConfig passes signet through', () => {
			const config = resolveConfig({ network: 'signet' });
			expect(config.network).to.equal('signet');
		});
	});

	describe('feeEstimationSource option', () => {
		it('BeignetNodeOptions accepts a fee estimation source', () => {
			const opts: BeignetNodeOptions = { feeEstimationSource: 'electrum' };
			expect(opts.feeEstimationSource).to.equal('electrum');
		});

		it('resolveConfig prefers the CLI flag', () => {
			const config = resolveConfig({ feeEstimationSource: 'http' });
			expect(config.feeEstimationSource).to.equal('http');
		});

		it('resolveConfig reads BEIGNET_FEE_SOURCE', () => {
			const previous = process.env.BEIGNET_FEE_SOURCE;
			process.env.BEIGNET_FEE_SOURCE = 'electrum';
			try {
				const config = resolveConfig({});
				expect(config.feeEstimationSource).to.equal('electrum');
			} finally {
				if (previous === undefined) {
					delete process.env.BEIGNET_FEE_SOURCE;
				} else {
					process.env.BEIGNET_FEE_SOURCE = previous;
				}
			}
		});
	});

	describe('BIP21 on /address/new', () => {
		it('documents the bip21 request and response fields in OpenAPI', () => {
			const spec = getOpenApiSpec() as {
				paths: Record<
					string,
					{
						post: {
							requestBody?: {
								content: {
									'application/json': {
										schema: { properties: Record<string, unknown> };
									};
								};
							};
							responses: Record<
								string,
								{
									content: {
										'application/json': {
											schema: { properties: Record<string, unknown> };
										};
									};
								}
							>;
						};
					}
				>;
			};
			const route = spec.paths['/address/new'].post;
			const bodyProps =
				route.requestBody!.content['application/json'].schema.properties;
			expect(bodyProps).to.have.property('bip21');
			expect(bodyProps).to.have.property('amountSats');
			expect(bodyProps).to.have.property('label');
			expect(bodyProps).to.have.property('message');
			const responseProps =
				route.responses['200'].content['application/json'].schema.properties;
			expect(responseProps).to.have.property('address');
			expect(responseProps).to.have.property('bip21');
		});

		it('encodeBip21 builds the URI the route returns', () => {
			const res = encodeBip21({
				address: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
				amountSats: 21000,
				label: 'test'
			});
			if (res.isErr()) throw res.error;
			expect(res.value).to.equal(
				'bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.00021&label=test'
			);
		});
	});
});
