# plans/

Where this package's planning artifacts live once it has a repo.

Before scaffolding, they sit in foundry at `packages/oauth-host/` — recon docs,
the synthesis, the build plan. `standards/done.md` requires them to move here
when the repo exists, and foundry's un-ignore line for `packages/oauth-host/` to
be removed in the same commit. Two copies drifting is worse than none.

Expected contents:

```
recon-<repo>.md     one per source implementation
synthesis.md        the divergence table and where each divergence landed
build-plan.md       the finalized plan — public API, config surface, adapters
```

Keep them. They are the record of *why* the config surface has the keys it has,
and every one of those keys exists because two implementations disagreed. That
reasoning is invisible in the code and impossible to reconstruct later.
