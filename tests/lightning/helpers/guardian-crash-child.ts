/**
 * Crash child for the SIGKILL acceptance tests. NOT a test file: spawned by
 * recovery-guardian-acceptance.test.ts as
 *
 *   node -r ts-node/register guardian-crash-child.ts <dbPath>
 *
 * and killed with SIGKILL mid-run. Protocol on stdout, one line each:
 *
 *   registered:<status>   the namespace exists
 *   attempting:<seq>      written BEFORE putState is called
 *   receipt:<seq>         written ONLY AFTER putState returned
 *   done                  the whole chain appended
 *
 * better-sqlite3 commits synchronously before putState can return, so any
 * receipt line the parent observes is an acknowledgment backed by a durable
 * commit: that is precisely the boundary the kill tests probe.
 */

import {
	GuardianStatus,
	ReferenceGuardian
} from '../../../src/lightning/recovery';
import {
	ACCEPT_GUARDIAN_IDS,
	ACCEPT_GUARDIAN_SECRETS,
	acceptChain,
	acceptRegistration
} from './guardian-accept-fixture';

function main(): void {
	const dbPath = process.argv[2];
	if (!dbPath) {
		process.stderr.write('usage: guardian-crash-child <dbPath>\n');
		process.exit(2);
	}
	const guardian = new ReferenceGuardian({
		path: dbPath,
		guardianSecret: ACCEPT_GUARDIAN_SECRETS[0],
		members: ACCEPT_GUARDIAN_IDS
	});
	const registered = guardian.register(acceptRegistration());
	process.stdout.write(`registered:${registered.status}\n`);
	if (
		registered.status !== GuardianStatus.OK &&
		registered.status !== GuardianStatus.OK_DUPLICATE
	) {
		process.exit(2);
	}
	for (const record of acceptChain()) {
		process.stdout.write(`attempting:${record.sequence}\n`);
		const response = guardian.putState({ record });
		if (
			response.status !== GuardianStatus.OK &&
			response.status !== GuardianStatus.OK_DUPLICATE
		) {
			process.stdout.write(`error:${record.sequence}:${response.status}\n`);
			process.exit(2);
		}
		process.stdout.write(`receipt:${record.sequence}\n`);
	}
	process.stdout.write('done\n');
	guardian.close();
}

main();
