# Preview release process

1. Merge the reviewed cumulative compiler/runtime PR.
2. Create and push a reviewed annotated tag named `lithic-v<version>`.
3. The release workflow builds locked Linux, Windows and Apple Silicon binaries
   for `lithc`, `lithfmt` and `lithlint`.
4. Verify every archive against its adjacent SHA-256 file and run the packaged
   compiler against the published examples.
5. Review the draft GitHub release and publish it only after approval.

The workflow deliberately creates a draft. A passing build does not authorize
production deployment or claim native LithoVM mainnet integration.
