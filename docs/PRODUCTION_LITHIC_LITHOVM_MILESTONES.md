# Production Lithic and native LithoVM milestones

Status: approved combined workstream; implementation active

The production compiler and native runtime ship through one conformance gate.
Compiler output is accepted only when the native runtime independently decodes,
validates and executes the exact artifact with deterministic results.

## M1 — Versioned artifact and execution boundary

Status: implemented in candidate

- versioned, strictly decoded native artifact;
- fixed static value ABI and canonical encoding;
- deterministic function dispatch and gas rejection;
- compiler-to-runtime execution tests;
- fail-closed rejection of unsupported source and malformed bytecode.

## M2 — Typed executable core

- typed expression and statement AST/IR;
- local variables, arithmetic, comparisons and control flow;
- overflow, division, recursion and resource limits;
- compiler/runtime differential and fuzz tests.

## M3 — Transactional state

- deterministic storage layout and namespacing;
- reads, writes and initialization;
- atomic commit/revert and rollback on every failure path;
- state transition, invariant and adversarial tests.

## M4 — Host effects and gas

- caller, value, block and chain context;
- events, transfers and contract calls;
- reentrancy and call-depth policy;
- versioned opcode and host-call gas schedule;
- deterministic receipts and observable failure semantics.

## M5 — LEP100-15

- domain-separated transaction digest and nonce policy;
- unique signer and threshold validation;
- atomic execution, signer changes and revocation;
- contract signatures, recovery and replay resistance;
- portable conformance vectors and negative tests.

## M6 — Makalu integration

- deterministic deployment and call interface in the L1 runtime;
- RPC, wallet, explorer and indexer support;
- real contract fixtures, upgrades, recovery and rollback rehearsal;
- performance and denial-of-service limits.

## M7 — Production release

- reproducible builds, SBOM and signed artifacts;
- compiler/runtime conformance, fuzzing and security review;
- versioning, compatibility and migration policy;
- `lithic.at` and `docs.lithic.at` updated to exact supported behavior;
- Makalu acceptance followed by explicit mainnet governance approval.

No milestone authorizes mainnet deployment by itself.
