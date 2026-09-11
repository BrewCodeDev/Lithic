# Lithic implementation status

This repository is a development scaffold. Its design documents describe intended capabilities; they do not establish production availability or mainnet support.

| Tool | Current implementation |
|---|---|
| lithc | Parses declarations and emits summary, AST, declaration ABI or conservative checks. No executable bytecode. |
| lithfmt | Parse-checked, literal-preserving whitespace normalization; supports --check. |
| lithlint | Declaration-level naming and AI-budget rules; supports --deny-warnings. Not a security analyzer. |
| lithdev | Placeholder shell entrypoint. No deployment execution. |
| lithls, lithtest, lithsec, lithpkg | Specification-only targets. No usable implementations here. |

The SDK compiler, formatter and linter wrappers invoke the Rust commands from this checkout. lithdev remains a placeholder. The VM scaffold has no contract execution implementation; receipt and zk verification placeholders must not be used to authorize anything.

## Local development

Install Rust and the platform C/C++ linker, then run from this repository:

```sh
cargo build --workspace
cargo test --workspace
cargo run -p lithc -- --help
```

These commands build and test the scaffold. Passing the existing tests does not establish language conformance, secure verification or deployable bytecode. No production installation or deployment command is available here.

## Lithosphere integration

The tested front end from `KaJLabs/Lithosphere/toolchain` has been imported here. See [import provenance and command changes](FRONTEND_IMPORT.md). This does not establish executable bytecode generation.

An EVM RPC on Lithosphere does not, by itself, demonstrate native LithoVM execution. Published integration instructions need an identified compiler target, exact runtime version, deployment interface and independently verified execution example. Lithic and Solidity support are separate from any policy requiring a particular language.

## LEP100-15

LEP100-15 is a draft multisignature smart-account standard. See [the supplied draft](../packages/standards/lep100/LEP100-15.md). Its example contracts, SDK calls and deployment configurations are illustrative. No implementation or mainnet address is certified by inclusion in these docs.

Core acceptance requires deterministic signing vectors, domain and nonce replay protection, threshold and unique-signer checks, revocation, atomic execution, reentrancy protection, authorized signer changes, custody tests and contract-signature tests against the supported runtime. Recovery and optional AI/agent profiles require their own tests. Partial implementation must identify unsupported features.
