# Lithic implementation status

This repository contains a preview compiler backend plus development scaffolds. Its design documents describe intended capabilities; they do not establish production availability.

| Tool | Current implementation |
|---|---|
| lithc | Parses/checks declarations and emits ABI plus executable EVM or versioned native LithoVM bytecode for the documented stateless subset. Native v2 output supports static parameters, immutable locals, structured `if`/`else`, checked `u64` arithmetic and comparisons. Unsupported semantics fail the complete build. |
| lithfmt | Parse-checked, literal-preserving whitespace normalization; supports --check. |
| lithlint | Declaration-level naming and AI-budget rules; supports --deny-warnings. Not a security analyzer. |
| lithdev | Placeholder shell entrypoint. No deployment execution. |
| lithls, lithtest, lithsec, lithpkg | Specification-only targets. No usable implementations here. |

The SDK compiler, formatter and linter wrappers invoke the Rust commands from this checkout. lithdev remains a placeholder. The native VM strictly decodes and executes the stateless formats documented in [Native LithoVM ABI v2](LITHOVM_ABI_V2.md) and [v1](LITHOVM_ABI_V1.md), including immutable locals, structured branches, checked expression execution and deterministic executed-path gas. Mutable locals, loops, storage, calls, events, transfers, receipts and zk authorization are not implemented; receipt and zk placeholders must not be used to authorize anything. The EVM target remains documented in [EVM backend v1](EVM_BACKEND_V1.md).

## Local development

Install Rust and the platform C/C++ linker, then run from this repository:

```sh
cargo build --workspace
cargo test --workspace
cargo run -p lithc -- --help
```

These commands build and test the toolchain. Passing them validates only the capability matrix above. No production installation, signing or deployment command is included.

## Lithosphere integration

A [local execution experiment](LITHOVM_EXECUTION_LAB.md) remains historical.
`lithc --emit lithovm` now emits the versioned native artifact described in
[Native LithoVM ABI v2](LITHOVM_ABI_V2.md), while retaining v1 decoding compatibility. This establishes the combined
compiler/runtime boundary; it does not yet establish production readiness.

The tested front end from `KaJLabs/Lithosphere/toolchain` has been imported here. See [import provenance and command changes](FRONTEND_IMPORT.md).

The EVM backend targets the deployed EVM interface on LITHO. The native
compiler and interpreter are currently library-level components and do not
claim that a `lithic_*` RPC namespace or on-chain native module is deployed.

## LEP100-15

LEP100-15 is a draft multisignature smart-account standard. See [the supplied draft](../packages/standards/lep100/LEP100-15.md). Its example contracts, SDK calls and deployment configurations are illustrative. No implementation or mainnet address is certified by inclusion in these docs.

Core acceptance requires deterministic signing vectors, domain and nonce replay protection, threshold and unique-signer checks, revocation, atomic execution, reentrancy protection, authorized signer changes, custody tests and contract-signature tests against the supported runtime. Recovery and optional AI/agent profiles require their own tests. Partial implementation must identify unsupported features.
