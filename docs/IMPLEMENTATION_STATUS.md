# Lithic implementation status

This repository contains a preview compiler backend plus development scaffolds. Its design documents describe intended capabilities; they do not establish production availability.

| Tool | Current implementation |
|---|---|
| lithc | Parses/checks declarations and emits ABI plus executable EVM deployment/runtime bytecode for the documented stateless subset with static ABI parameters and constant or identity returns. Unsupported semantics fail the complete build. |
| lithfmt | Parse-checked, literal-preserving whitespace normalization; supports --check. |
| lithlint | Declaration-level naming and AI-budget rules; supports --deny-warnings. Not a security analyzer. |
| lithdev | Placeholder shell entrypoint. No deployment execution. |
| lithls, lithtest, lithsec, lithpkg | Specification-only targets. No usable implementations here. |

The SDK compiler, formatter and linter wrappers invoke the Rust commands from this checkout. lithdev remains a placeholder. The native VM scaffold has no separate contract execution implementation; receipt and zk verification placeholders must not be used to authorize anything. The current executable target is documented in [EVM backend v1](EVM_BACKEND_V1.md).

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
The supported `lithc` output for the initial release is EVM bytecode described
in [EVM backend v1](EVM_BACKEND_V1.md).

The tested front end from `KaJLabs/Lithosphere/toolchain` has been imported here. See [import provenance and command changes](FRONTEND_IMPORT.md).

The initial backend explicitly targets the deployed EVM interface on LITHO. It does not claim that a separate native LithoVM module or `lithic_*` RPC namespace exists.

## LEP100-15

LEP100-15 is a draft multisignature smart-account standard. See [the supplied draft](../packages/standards/lep100/LEP100-15.md). Its example contracts, SDK calls and deployment configurations are illustrative. No implementation or mainnet address is certified by inclusion in these docs.

Core acceptance requires deterministic signing vectors, domain and nonce replay protection, threshold and unique-signer checks, revocation, atomic execution, reentrancy protection, authorized signer changes, custody tests and contract-signature tests against the supported runtime. Recovery and optional AI/agent profiles require their own tests. Partial implementation must identify unsupported features.
