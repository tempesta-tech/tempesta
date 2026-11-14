# Agent Guidelines

Follow Tempesta FW [coding style](https://github.com/tempesta-tech/tempesta/blob/master/doc/CodingStyle)
for C and C++ code. For Python code, follow the Black and isort configuration in
`t/func/pyproject.toml` and otherwise follow [PEP 8](https://peps.python.org/pep-0008/).

Read `README.md` and `t/func/README.md` for build and functional-test setup. Preserve
unrelated tracked and untracked changes in the working tree.


## New Code Development

Make the smallest change that fixes the requested task.

If adjacent changes would be useful, mention them, but do not include them without a
specific request.

For all C and C++ changes, check whether unit or functional tests cover the behavior
and propose a new test if they do not.

Propose wiki, referenced in README.md, changed if the new functionality affects
configuration or project architecture already covered in the documentation.

Always perform a self-review according to the section below. Report the exact tests
run and clearly identify anything that was not tested.

### Security

This project is a network security gateway, so all ingress (client) network data must
be validated for valid values:

1. use ingress data in pointer arithmetics and memory accesses only after the initial
   value check and resulting pointer check
2. check values against possible integer overflows
3. check protocol semantics against ingress data (e.g. invalid flags and field
   values)

### Performance

This project is performance critical:

1. O(1) algorithms are more preferred that larger complexity
2. Do as little data structures traversal as possible
3. Avoid data copies and copy data when zero-copying is more expensive
4. Take care about spacial locality
5. Take care about shared data and locks on large multi-core and NUMA systems


## Code Review

Perform the review as independent passes.

1. Compliance with the coding style above and the
   [development guidelines](https://tempesta-tech.com/knowledge-base/Development-guidelines/).
2. Memory safety, including integer bounds, packet bounds, lifetimes, and ownership.
3. Unnecessary architecture changes, single-use abstractions, dependency-graph
   regressions from new `#include` directives, excessive function size, and tangled
   control flow.
4. Analyze locking and synchronization.
5. Security vulnerabilities, especially in code processing untrusted network input.
   The project runs at the Internet edge.
6. Performance regressions and work amplification that could create denial-of-service
   vectors.
7. Whether tests exercise observable behavior and failure paths, not only successful
   execution.

When model selection is under the operator's control, use the most capable available
model and the highest practical reasoning effort for non-trivial security,
architecture, and performance reviews.
