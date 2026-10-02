import { expect } from 'chai';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import { exposeAndLeave, pay } from './helpers/ffor-world';
import { PaymentStatus } from '../../src/lightning/node/types';

describe('Concurrent slot resolution notifications', function () {
	this.timeout(30000);
	for (const version of [1, 2] as const) {
		it(`version ${version}: emits once after terminal custody is durable`, async () => {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			const w = createConcurrentWorld({ rStorage: storage });
			const events: Record<string, unknown>[] = [];
			w.r.on('ffor:slot-resolved', (event) => {
				const archived = storage.loadAllFforVouchers!().find(
					(entry) => entry.paymentHash === event.paymentHash
				)!;
				expect(archived.outcome?.outcome).to.equal('fulfilled');
				events.push(event);
			});
			try {
				activateWorld(w, true, undefined, version);
				const [invoice] = exposeAndLeave(w, [1]);
				const payment = pay(w, invoice);
				expect(payment.status).to.equal(PaymentStatus.COMPLETED);
				expect(events).to.have.length(0);
				w.sr.reconnect();
				expect(w.r.fforSync(w.srHex).ok).to.equal(true);
				await new Promise<void>((resolve) => setImmediate(resolve));
				expect(events).to.have.length(1);
				expect(events[0]).to.include({
					channelId: w.srHex,
					k: 1,
					paymentHash: payment.paymentHash.toString('hex'),
					outcome: 'fulfilled'
				});
				expect(events[0].amountMsat).to.be.a('string');
				expect(w.r.fforSync(w.srHex).ok).to.equal(true);
				await new Promise<void>((resolve) => setImmediate(resolve));
				expect(events).to.have.length(1);
			} finally {
				w.p.destroy();
				w.s.destroy();
				w.r.destroy();
				storage.close();
			}
		});
	}
});
