# Autogen

This module is not to be confused with [GNU AutoGen][autogen], even though they
share a similar purpose: generating code/configuration files for a project.

## Generating C code

This module is able to generate C code that is incorporated into the runtime,
based on the HAL symbol configuration file passed.
For now, this is about creating a static array of symbol to address mappings
for functions present in a firmware.

The generated source file will be placed into the configured output directory
and is supposed to be compiled and linked into the runtime at build time.

## Generating YAML configuration files

The module is also able to generate YAML configuration files for rewriting
firmware binaries.
More specifically, the module extracts function's addresses from the compiled
runtime and creates a configuration file that can be used by the firmware
rewriter to introduce the corresponding branches into the runtime.

Currently, this method is used to determine the address of the HAL function
dispatcher and the timer emulator (based on incrementing a tick every
intercepted basic block).

[autogen]: https://www.gnu.org/software/autogen/
