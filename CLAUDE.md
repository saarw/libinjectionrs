The directory libinjection-c is a git submodule with the original libinjection repo.

Further instructions for how C should be mapped to Rust is in docs/ARCHITECTURE.md and docs/PORTING_STRATEGY.md

The root directory contains comparison-bin and ffi-harness directories for running comparisons to C behavior. The libinjection-debug directory is a tool for debugging tokenization and folding issues.

Whenever we explore a failing test, DO NOT immediately workaround the bug in the Rust code, instead:
1. Explore the C and Rust code and write a detailed report about what difference may be causing the difference. Identify any other differences between the C code's logic and Rust implementation as well.
2. Propose a fix that makes the Rust code behave exactly the same as the C code in the general sense, not just for the particular test case.

We want the Rust code of the port to follow the C code exactly and not just behave the same for particular tests.