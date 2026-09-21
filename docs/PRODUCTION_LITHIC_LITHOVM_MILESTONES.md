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

- typed expression AST/IR (checked `u64` arithmetic and comparisons implemented in candidate);
- immutable local bindings and structured `if`/`else` implemented in the version 2 candidate;
- remaining mutable bindings, loops and bounded recursion policy;
- overflow, division, recursion and resource limits;
- compiler/runtime differential and fuzz tests.

## M3 — Transactional state

Status: scalar storage implemented in the version 3 candidate

- deterministic ordered scalar storage schema implemented;
- typed reads, writes and zero initialization implemented;
- staged atomic commit and rollback on runtime and out-of-gas failures implemented;
- remaining collection storage, migrations, namespacing integration and broader adversarial tests.

## M4 — Host effects and gas

Status: context, events and staged native transfers implemented through version 6

- caller, value, block and chain context implemented behind explicit runtime APIs;
- typed ordered event schemas and successful-call event records implemented;
- balance-checked staged native transfers implemented;
- remaining contract calls;
- reentrancy and call-depth policy;
- context opcodes use the current versioned instruction gas schedule; host-call gas remains;
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
