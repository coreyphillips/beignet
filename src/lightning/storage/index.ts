import { SqliteStorage as SqliteStorageClass } from './sqlite-storage';

export * from './types';
export * from './serialization';
export { IStoredPaymentRef, IPaymentRowMatch } from './sqlite-storage';
export * from './encryption';
export { MemoryStorage } from './memory-storage';
export {
	STORAGE_CAPABILITIES,
	storageCapabilityMembers,
	hasStorageCapability,
	hasRecoveryStorage,
	partialStorageCapabilities
} from './capabilities';
export {
	IStorageConformanceCheck,
	storageConformanceChecks,
	runStorageConformanceSuite
} from './conformance';

// An alias rather than a re-export: TypeScript drops @deprecated on export
// specifiers, so editors would not flag the old path.
/**
 * @deprecated Import `SqliteStorage` from `beignet/lightning/sqlite`. This
 * re-export is removed in the next major release.
 */
export const SqliteStorage = SqliteStorageClass;
/**
 * @deprecated Import `SqliteStorage` from `beignet/lightning/sqlite`. This
 * re-export is removed in the next major release.
 */
export type SqliteStorage = SqliteStorageClass;
