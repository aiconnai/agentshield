# Review Canvas

Review canvas files capture reasoning evidence for complex changes before implementation is judged complete.

Create a canvas when a change matches any trigger:

- More than 200 non-generated lines changed.
- Changes to storage schema, migrations, or data invariants.
- MCP tool surface changes.
- Hook, intelligence, consolidation, embedding, sync, or attestation behavior changes.
- Public SDK contract changes.
- New external dependency, backend, transport, cache, queue, or networked service.
- Harness gate, invariant, bootstrap, sensor, or review policy changes.

Canvas files are evidence, not approval. A post-review can still fail after a complete canvas.
