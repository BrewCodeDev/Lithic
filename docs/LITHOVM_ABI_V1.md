# Native LithoVM artifact and call ABI v1

Status: implementation milestone 1; stateless subset

Target identifier: `lithovm-native-v1`

This document fixes the first executable boundary shared by `lithc` and the
native `lithovm` crate. It is deliberately small so bytecode decoding,
canonical values, dispatch and gas rejection can be tested before storage and
external effects are introduced.

## Artifact encoding

All integers use unsigned big-endian encoding. An artifact contains:

1. seven-byte ASCII magic `LITHOVM`;
2. one-byte version (`1`);
3. `u16` function count;
4. each function in declaration order:
   - `u16` UTF-8 name length and name bytes;
   - `u16` parameter count and one type byte per parameter;
   - one return-type byte;
   - one return opcode followed by its operand.

Type bytes are `1=u64`, `2=u256`, `3=bool`, `4=address`, and `5=bytes32`.
Return opcode `1` carries one canonical 32-byte constant. Return opcode `2`
carries a `u16` parameter index. Decoders reject unknown versions, types and
opcodes, duplicate function names, invalid identifiers, truncation, trailing
bytes, non-canonical words, bad parameter indexes and type mismatches.

## Calls and values

The caller supplies an exact function name plus an ordered list of 32-byte
arguments. `u64` occupies the low eight bytes, `bool` is zero or one, and an
address occupies the low twenty bytes. `u256` and `bytes32` may use all bytes.
The VM validates every argument before execution.

Milestone-1 gas is deterministic: 10 base units plus 2 units per argument.
Insufficient gas rejects the call without a result.

## Current compiler subset

Functions must be public, synchronous, stateless, use only the five static
types above, declare a return type, and contain exactly one return of a literal
or same-typed parameter. Any unsupported declaration or body rejects the whole
compilation.

## Next compatible extensions

Typed expressions and statements, storage transactions and rollback, events,
caller/value, transfers and calls require new versioned instructions and gas
rules. They must retain strict decoding and atomic failure. Version 1 must not
be silently reinterpreted when those features are added.
