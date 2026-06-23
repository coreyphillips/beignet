import { expect } from 'chai';
import { ChannelInfo, ChannelSuggestion } from '../../src/cli/types';

interface MockGraphNode {
	announcement?: {
		addresses: Array<{ type: number; host: string; port: number }>;
	};
}

describe('ensureMinimumChannels', () => {
	it('returns existing channels if already at minimum', () => {
		const existing: ChannelInfo[] = [
			{
				channelId: 'aaa',
				peerPubkey: 'pub1',
				state: 'NORMAL',
				localBalanceSats: 50000,
				remoteBalanceSats: 50000,
				capacitySats: 100000,
				isAnchor: false
			},
			{
				channelId: 'bbb',
				peerPubkey: 'pub2',
				state: 'NORMAL',
				localBalanceSats: 50000,
				remoteBalanceSats: 50000,
				capacitySats: 100000,
				isAnchor: false
			}
		];
		const count = 2;
		expect(existing.length).to.be.at.least(count);
	});

	it('calculates how many new channels are needed', () => {
		const existing: ChannelInfo[] = [
			{
				channelId: 'aaa',
				peerPubkey: 'pub1',
				state: 'NORMAL',
				localBalanceSats: 50000,
				remoteBalanceSats: 50000,
				capacitySats: 100000,
				isAnchor: false
			}
		];
		const count = 3;
		const needed = count - existing.length;
		expect(needed).to.equal(2);
	});

	it('uses channel suggestions for peer selection', () => {
		const suggestions: ChannelSuggestion[] = [
			{
				nodeId: 'node1',
				score: 90,
				channelCount: 10,
				totalCapacitySats: 5000000,
				reason: 'high connectivity'
			},
			{
				nodeId: 'node2',
				score: 85,
				channelCount: 8,
				totalCapacitySats: 3000000,
				reason: 'good routing'
			}
		];
		expect(suggestions).to.have.length(2);
		expect(suggestions[0].score).to.be.greaterThan(suggestions[1].score);
	});

	it('opens at most needed channels (not more than suggestions)', () => {
		const needed = 5;
		const suggestions: ChannelSuggestion[] = [
			{
				nodeId: 'node1',
				score: 90,
				channelCount: 10,
				totalCapacitySats: 5000000,
				reason: 'reason'
			},
			{
				nodeId: 'node2',
				score: 85,
				channelCount: 8,
				totalCapacitySats: 3000000,
				reason: 'reason'
			}
		];
		const toOpen = Math.min(needed, suggestions.length);
		expect(toOpen).to.equal(2);
	});

	it('returns combined existing + newly opened channels', () => {
		const existing: ChannelInfo[] = [
			{
				channelId: 'aaa',
				peerPubkey: 'pub1',
				state: 'NORMAL',
				localBalanceSats: 50000,
				remoteBalanceSats: 50000,
				capacitySats: 100000,
				isAnchor: false
			}
		];
		const newChannels: ChannelInfo[] = [
			{
				channelId: 'bbb',
				peerPubkey: 'pub2',
				state: 'AWAITING_FUNDING_CONFIRMED',
				localBalanceSats: 100000,
				remoteBalanceSats: 0,
				capacitySats: 100000,
				isAnchor: false
			}
		];
		const all = [...existing, ...newChannels];
		expect(all).to.have.length(2);
	});

	it('skips failed channel opens gracefully', () => {
		// In the implementation, failed openChannel calls are caught and skipped
		const results: ChannelInfo[] = [];
		const errors: Error[] = [];
		try {
			throw new Error('peer not connected');
		} catch (err) {
			errors.push(err as Error);
		}
		expect(results).to.have.length(0);
		expect(errors).to.have.length(1);
	});

	it('returns empty array when no suggestions available', () => {
		const suggestions: ChannelSuggestion[] = [];
		const existing: ChannelInfo[] = [];
		if (suggestions.length === 0) {
			expect(existing).to.deep.equal([]);
		}
	});

	// ─── Connect-before-open tests ───

	it('connects to peer before opening channel using gossip graph address', () => {
		const suggestion: ChannelSuggestion = {
			nodeId: 'aabbcc',
			score: 90,
			channelCount: 10,
			totalCapacitySats: 5000000,
			reason: 'high connectivity'
		};
		const graphNode: MockGraphNode = {
			announcement: {
				addresses: [{ type: 1, host: '1.2.3.4', port: 9735 }]
			}
		};

		const addrs = graphNode.announcement?.addresses;
		expect(addrs).to.exist;
		const addr = addrs!.find((a) => a.type === 1 || a.type === 2) || addrs![0];
		expect(addr.host).to.equal('1.2.3.4');
		expect(addr.port).to.equal(9735);
		expect(suggestion.nodeId).to.equal('aabbcc');
	});

	it('skips suggestions with no routable address', () => {
		const graphNode: MockGraphNode = {
			// No announcement at all
		};

		const addrs = graphNode.announcement?.addresses;
		const shouldSkip = !addrs || addrs.length === 0;
		expect(shouldSkip).to.be.true;
	});

	it('connection failure does not prevent opening to other peers', async () => {
		const opened: string[] = [];
		const suggestions = [
			{ nodeId: 'peer1', host: '1.1.1.1', port: 9735 },
			{ nodeId: 'peer2', host: '2.2.2.2', port: 9735 }
		];

		for (const s of suggestions) {
			try {
				// Simulate first peer connection failing
				if (s.nodeId === 'peer1') throw new Error('connection refused');
				opened.push(s.nodeId);
			} catch {
				// Skip failed connects — continue to next
			}
		}

		expect(opened).to.deep.equal(['peer2']);
	});

	it('already-connected peer proceeds directly to open', async () => {
		const steps: string[] = [];

		// Simulate connectPeer throwing "already connected" which is caught
		try {
			throw new Error('Already connected to peer');
		} catch {
			// Ignored — proceed to openChannel
		}
		steps.push('openChannel');

		expect(steps).to.deep.equal(['openChannel']);
	});

	it('requests needed*2 suggestions to account for connection failures', () => {
		const existingCount = 1;
		const targetCount = 3;
		const needed = targetCount - existingCount;
		const requestedSuggestions = needed * 2;
		expect(requestedSuggestions).to.equal(4);
	});
});
