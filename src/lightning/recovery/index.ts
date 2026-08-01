/**
 * Recovery Protocol (docs/RECOVERY-PROTOCOL.md).
 *
 * Phase 1: the safety transition layer and the durable outbox.
 * Phase 2: the hash-chained recovery journal, full-state snapshots with
 * compaction, and deterministic reconstruction.
 * Phase 3: the Recovery Capsule over BOLT 1 peer_storage.
 * Guardians and writer epochs are later phases.
 */

export * from './types';
export * from './recovery-manager';
export * from './frame-codec';
export * from './journal';
export * from './capsule';
export * from './guardian-wire';
export * from './guardian-store';
export * from './guardian';
export * from './guardian-proto';
export * from './guardian-http';
export * from './guardian-client';
export * from './writer-lease';
