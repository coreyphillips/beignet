import { SqliteStorage as SqliteStorageClass } from './sqlite-storage';

export * from './types';
export * from './serialization';
export { IStoredPaymentRef, IPaymentRowMatch } from './sqlite-storage';
export * from './encryption';

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
