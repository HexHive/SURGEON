# Runtime

The runtime's purpose is to `mmap` a firmware image into its address space and
to jump there in order to execute the firmware's code.

The runtime is linked statically and loaded at `0xf0000000` (see the [linker
script][linker]) in order to not pollute the address space with dynamically
loaded libraries or the runtime itself.
The rationale behind this base address is as follows:

For certain Arm Cortex-M MCUs (especially [M0][m0], [M3][m3], [M7][m7]), the
address range `0xE0100000 - 0xFFFFFFFF` is reserved for implementation-specific
access to devices, which is typically non-executable.
Under the assumption that no peripherals are mapped at those locations for a
given firmware (_requires verification!_), this memory region is never
intentionally accessed by a firmware image and is therefore suitable for
"hiding" our runtime code.

[linker]: ./link.lds
[m0]: https://developer.arm.com/documentation/dui0497/a/the-cortex-m0-processor/memory-model/behavior-of-memory-accesses
[m3]: https://developer.arm.com/documentation/dui0552/a/the-cortex-m3-processor/memory-model/behavior-of-memory-accesses
[m7]: https://developer.arm.com/documentation/dui0646/b/The-Cortex-M7-Processor/Memory-model/Behavior-of-memory-accesses
