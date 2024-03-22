# fw-example

Even though the code is supposed to resemble a real firmware as an example to
test the runtime, the resulting ELF can not actually be loaded onto a MCU and
executed on the same (missing HALs, linker scripts, etc.)!
In its current state, the example is a freestanding ELF issuing Linux system
calls.
Please regard the code in this directory therefore as purely experimental!
