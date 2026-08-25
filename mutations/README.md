# Targeted mutations

`python tools/mutation_test.py` makes isolated temporary source copies, applies ten
security-critical mutations, and runs the targeted regression that must kill each
one. The committed report is `artifacts/mutation-report.json`.

Mutations cover repository binding, lineage, exact SHA length, challenge path scope,
independent validator derivation, evidence-error classification, both deadline
guards, exact final target matching, and the consumer's live authorization read.

