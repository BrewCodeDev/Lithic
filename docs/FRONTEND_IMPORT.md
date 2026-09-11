# Tested front-end import

Imported from KaJLabs/Lithosphere snapshot
`cee91f54186b6f07de08ad090394bfa2f46e6793`, under `toolchain/crates/`:
`lithic-syntax`, `lithc`, `lithfmt` and `lithlint`, including their existing tests.
The original front-end commit is `e0dbcf6795f879bf7d0092fff419cba10049bd44`
(bachal-abro); conservative checks were added in `d675555` (bachal-mb).
Source history remains available in that repository; this is a source import,
not a merge of its unrelated chain and infrastructure history.

Golden contract fixtures are copied unchanged from the source snapshot's
`Makalu/contracts/src`. They are parser fixtures, not deployment examples.
The golden-test path is local to this repository. Package versions retain the
destination workspace's 0.1.0 convention; this does not publish a release.

## Command transition

The old `lithc compile` command emitted a dummy source-hash container. It is
replaced by the tested front end, which offers summary, AST, declaration ABI
and conservative declaration checks. There is no bytecode output mode.

```sh
cargo run -p lithc -- --emit check apps/examples/frontend/hello.lithic
cargo run -p lithc -- --emit ast apps/examples/frontend/hello.lithic
cargo run -p lithfmt -- --check apps/examples/frontend/hello.lithic
cargo run -p lithlint -- --deny-warnings apps/examples/frontend/hello.lithic
```

`check` does not type-check or execute function bodies. Declaration ABI is
descriptive output, not an approved runtime ABI. Existing draft syntax such as
LEP100-15 is not yet supported. Formatter and linter retain their bounded
whitespace/declaration behavior. VM packages remain separate scaffolds.

## Next boundary

Before executable compilation, specify LithoVM bytecode and versioning,
instruction semantics, gas, storage, calls, rollback, deployment format and
host APIs. Implement body parsing and type checking, then code generation
and execution tests against that interface. The public VM scaffold currently
does not execute contract instructions; do not infer a production runtime
from its name or its permissive verification placeholders.
