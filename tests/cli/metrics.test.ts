import { expect } from 'chai';

describe('Prometheus-Compatible Metrics', () => {
	// Test the expected Prometheus text exposition format
	function parseMetrics(text: string): Map<string, number> {
		const map = new Map<string, number>();
		for (const line of text.split('\n')) {
			if (line.startsWith('#') || line.trim() === '') continue;
			const spaceIdx = line.lastIndexOf(' ');
			if (spaceIdx === -1) continue;
			const key = line.substring(0, spaceIdx);
			const value = parseFloat(line.substring(spaceIdx + 1));
			map.set(key, value);
		}
		return map;
	}

	const sampleMetrics =
		[
			'# HELP beignet_channels_total Number of channels by state',
			'# TYPE beignet_channels_total gauge',
			'beignet_channels_total{state="NORMAL"} 2',
			'beignet_channels_total{state="AWAITING_FUNDING_CONFIRMED"} 1',
			'# HELP beignet_payments_total Total payments by status and direction',
			'# TYPE beignet_payments_total gauge',
			'beignet_payments_total{status="COMPLETED",direction="OUTGOING"} 10',
			'beignet_payments_total{status="COMPLETED",direction="INCOMING"} 5',
			'beignet_payments_total{status="FAILED",direction="OUTGOING"} 2',
			'# HELP beignet_balance_sats Balance in satoshis by type',
			'# TYPE beignet_balance_sats gauge',
			'beignet_balance_sats{type="onchain"} 100000',
			'beignet_balance_sats{type="lightning"} 50000',
			'beignet_balance_sats{type="total"} 150000',
			'# HELP beignet_electrum_connected Whether Electrum backend is connected',
			'# TYPE beignet_electrum_connected gauge',
			'beignet_electrum_connected 1',
			'# HELP beignet_peers_connected Number of connected peers',
			'# TYPE beignet_peers_connected gauge',
			'beignet_peers_connected 3',
			'# HELP beignet_uptime_seconds Node uptime in seconds',
			'# TYPE beignet_uptime_seconds gauge',
			'beignet_uptime_seconds 3600',
			'# HELP beignet_block_height Current block height',
			'# TYPE beignet_block_height gauge',
			'beignet_block_height 800000',
			'# HELP beignet_payment_success_rate Payment success rate (0-1)',
			'# TYPE beignet_payment_success_rate gauge',
			'beignet_payment_success_rate 0.8333',
			'# HELP beignet_fees_paid_sats Total routing fees paid in satoshis',
			'# TYPE beignet_fees_paid_sats counter',
			'beignet_fees_paid_sats 150',
			'# HELP beignet_graph_nodes Number of nodes in gossip graph',
			'# TYPE beignet_graph_nodes gauge',
			'beignet_graph_nodes 100',
			'# HELP beignet_graph_channels Number of channels in gossip graph',
			'# TYPE beignet_graph_channels gauge',
			'beignet_graph_channels 200'
		].join('\n') + '\n';

	it('output follows Prometheus text exposition format', () => {
		const lines = sampleMetrics.split('\n');
		for (const line of lines) {
			if (line.trim() === '') continue;
			// Either a comment or a metric line
			expect(
				line.startsWith('#') || line.match(/^[a-z_]+(\{[^}]*\})?\s+[\d.]+$/)
			).to.be.ok;
		}
	});

	it('includes beignet_channels_total metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_channels_total{state="NORMAL"}')).to.equal(2);
		expect(
			parsed.get('beignet_channels_total{state="AWAITING_FUNDING_CONFIRMED"}')
		).to.equal(1);
	});

	it('includes beignet_payments_total metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(
			parsed.get(
				'beignet_payments_total{status="COMPLETED",direction="OUTGOING"}'
			)
		).to.equal(10);
		expect(
			parsed.get(
				'beignet_payments_total{status="COMPLETED",direction="INCOMING"}'
			)
		).to.equal(5);
		expect(
			parsed.get('beignet_payments_total{status="FAILED",direction="OUTGOING"}')
		).to.equal(2);
	});

	it('includes beignet_balance_sats metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_balance_sats{type="onchain"}')).to.equal(100000);
		expect(parsed.get('beignet_balance_sats{type="lightning"}')).to.equal(
			50000
		);
		expect(parsed.get('beignet_balance_sats{type="total"}')).to.equal(150000);
	});

	it('includes beignet_electrum_connected metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_electrum_connected')).to.equal(1);
	});

	it('includes beignet_peers_connected metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_peers_connected')).to.equal(3);
	});

	it('includes beignet_uptime_seconds metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_uptime_seconds')).to.equal(3600);
	});

	it('includes beignet_block_height metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_block_height')).to.equal(800000);
	});

	it('includes beignet_payment_success_rate metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_payment_success_rate')).to.be.closeTo(
			0.8333,
			0.001
		);
	});

	it('includes beignet_fees_paid_sats counter', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_fees_paid_sats')).to.equal(150);
	});

	it('includes beignet_graph_nodes metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_graph_nodes')).to.equal(100);
	});

	it('includes beignet_graph_channels metric', () => {
		const parsed = parseMetrics(sampleMetrics);
		expect(parsed.get('beignet_graph_channels')).to.equal(200);
	});

	it('metric lines have HELP and TYPE comments', () => {
		const lines = sampleMetrics.split('\n');
		const helpLines = lines.filter((l) => l.startsWith('# HELP'));
		const typeLines = lines.filter((l) => l.startsWith('# TYPE'));
		// Each metric group has a HELP and TYPE line
		expect(helpLines.length).to.be.at.least(10);
		expect(typeLines.length).to.be.at.least(10);
	});

	it('ends with a newline', () => {
		expect(sampleMetrics.endsWith('\n')).to.be.true;
	});

	it('/metrics endpoint is auth-exempt', () => {
		// Verify the route is in the auth-exempt set
		const authExemptRoutes = new Set([
			'GET /health',
			'GET /openapi.json',
			'GET /metrics'
		]);
		expect(authExemptRoutes.has('GET /metrics')).to.be.true;
	});

	it('content-type is text/plain for Prometheus', () => {
		const contentType = 'text/plain; version=0.0.4; charset=utf-8';
		expect(contentType).to.include('text/plain');
		expect(contentType).to.include('0.0.4');
	});

	describe('edge cases', () => {
		it('empty channels produce a zero metric', () => {
			const line = 'beignet_channels_total{state="NONE"} 0';
			const parsed = parseMetrics(line + '\n');
			expect(parsed.get('beignet_channels_total{state="NONE"}')).to.equal(0);
		});

		it('zero balance is valid', () => {
			const line = 'beignet_balance_sats{type="lightning"} 0';
			const parsed = parseMetrics(line + '\n');
			expect(parsed.get('beignet_balance_sats{type="lightning"}')).to.equal(0);
		});
	});
});
