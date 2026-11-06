# Task Catalog

`catalog.json` contains 30 original local security-agent tasks, split evenly
across the five classes used in the paper.  The harness materializes each task's
`ground_truth.fixture_files` into a temporary workspace, gives the model only
tool access to that workspace, and scores the final artifact with the
deterministic predicate in the manifest.

`sanity_catalog.json` contains 12 local non-security coding tasks that use the
same fixture, controller, success-predicate, trace, and analysis path. These
tasks test whether an aligned-versus-uncensored gap is specific to the security
suite or reflects a broader coding/grounding difference.

Both catalogs include `grounding_targets` fields for expected files, symbols,
issue terms, and evidence terms. The analysis code scores these by deterministic
case-insensitive substring matching against tool calls and final artifacts.

These tasks are deliberately small.  They are intended to measure whether a
model completes security-agent workflow steps under controlled authorization,
not to provide reusable offensive procedures.
