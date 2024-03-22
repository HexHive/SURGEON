# SURGEON

This repository contains the code for SURGEON, aiming to enable high
performance, high fidelity re-hosting for embedded systems' firmware.

SURGEON was presented at [BAR '24][bar24] ([paper][paper]).

## Prerequisites

We assume an up-to-date Ubuntu system (Jammy Jellyfish, 22.04 LTS) as the base
system.
You should be able to follow any instructions below with a Debian installation,
different Ubuntu versions or other distributions as well, but your mileage may
vary.

You should have a current version of Docker and its compose plugin installed.
If not, please follow [the instructions in the Docker documentation][docker].

For all features (including cross-building), enable [BuildKit][buildkit] by
either setting the environment variable `DOCKER_BUILDKIT=1` or adding the
following snippet to `/etc/docker/daemon.json` and restarting the daemon:

```json
{
    "features": {
        "buildkit": true
        }
}
```

Afterwards, enable cross-compilation/cross-execution by registering the
corresponding binfmt handlers through a Docker container:

```bash
# Register the QEMU backend with binfmt
sudo docker run --rm --privileged \
         multiarch/qemu-user-static \
         --reset \
         -p yes
```

Please note that this configuration does not survive reboots of your host
kernel and needs to be re-executed on every boot.
If you would like to make this setting persistent, please check how to register
binfmt handlers leveraging qemu-user binaries persistently through
`systemd-binfmt`, `update-binfmts`, or whatever other mechanism your
distribution/init system provides.

If `sudo docker buildx ls` after this step shows you an active builder instance
(ideally, the `default` instance) that supports the target Arm architectures,
you're good to go.
If not, create and enable a cross-builder as follows:

```bash
# Create a cross-builder instance
sudo docker buildx create \
         --name armcross \
         --node armcross \
         --platform linux/amd64,linux/i368,linux/arm64,linux/arm/v7 \
         --use
```

To check whether everything worked, the following command should yield
`aarch64` as output:

```bash
sudo docker run --rm -it --platform linux/arm64 ubuntu:rolling uname -m
```

## Building/Running/Debugging

If the below subsections don't answer your questions, check the main
[Makefile][make-main] (i.e., `make help`) for building and running the code.

### Building the Docker image and running the container

`make build` builds the image, `make run` spawns a container.

Specify the firmware to run via the `FIRMWARE` variable which takes the path
relative to the [`firmware`][firmware] directory as a value.
For example, to run the P2IM CNC firmware in SURGEON, you only need to invoke
`make run FIRMWARE=p2im/cnc`.
This runs a single instance of the firmware and connects the peripheral inputs
and outputs to your `stdin` and `stdout`, respectively.

For fuzzing, just replace `run` with `run-fuzz` in the command above, e.g.,
`make run-fuzz FIRMWARE=p2im/cnc`.
This will spawn a container with AFL++ fuzzing the specified firmware for 24
hours.

### Debugging

#### Attaching via GDB

No matter your host architecture (in theory; tested only on amd64 and aarch64),
`make debug FIRMWARE=...` spawns the runtime either wrapped in `qemu-arm` or
`gdbserver` (provided that you built the runtime beforehand and rewrote the
firmware binary, e.g., with a run of `make run FIRMWARE=...`), both listening
on `localhost:1234`.

To debug, run an Arm-capable gdb on your host[^gdb-docker] (e.g.,
`aarch64-linux-gnu-gdb`, `arm-none-eabi-gdb` or `gdb-multiarch`) and execute
`target remote :1234` in the gdb prompt.
From there on, you should be attached to the gdb stub in the container and can
use gdb as usual.
In order to get the symbols right, launch gdb on the `runtime` executable or
add it with gdb's `file` command and add the firmware symbols with gdb's
`add-symbol-file` command.
An exemplary gdb startup command line you can copy-paste into your shell could
look as follows:

```bash
gdb-multiarch -iex "set confirm off" \
         -iex "add-symbol-file <path_to_rewritten_fw_binary>" \
         -ex "target remote :1234" \
         <path_to_compiled_runtime>
```

#### Increasing Debug Output

By default, not much is logged to `stdout` in order to reduce the frequency of
corresponding syscalls and therefore speed up fuzzing campaigns.
For debugging purposes, we recommend increasing the log level for the handlers
in the corresponding [\_\_init\_\_.py][halucinator-loglevel] if you are using
the HALucinator Python handlers for peripheral emulation.

Note that for native handlers, we increase/reduce debug output automatically
based on the use case.  
`make run FIRMWARE=...` will build a runtime with debug output in the native
handlers enabled, `make run-fuzz FIRMWARE=...` for the fuzzing campaigns will
build a runtime with debug output in the native handlers disabled.
`make debug FIRMWARE=...` takes the last version of the runtime that has been
built, no matter whether the runtime has been targeted for single runs or for
fuzzing campaigns.

### General Re-hosting Workflow

1. The `autogen` module needs to be invoked to generate the necessary C code to
   be compiled into the runtime from the configuration files.
2. The runtime needs to be compiled and linked.
   This step also extracts the addresses of certain functions from the linked
   binary in order to provide them as jump targets to the rewriter.
3. The rewriter processes the firmware binary and uses the addresses generated
   in step 2 for any jump targets (e.g., the HAL function dispatcher).

Our build system takes care of the order of those steps and any dependencies
between them.

## License

Unless otherwise specified in the file header, all code and other documents in
this repository are subject to the MIT license.
Please check [the license file][license] for more information.

[bar24]: https://ndss-bar24.github.io/program
[buildkit]: https://docs.docker.com/develop/develop-images/build_enhancements/
[docker]: https://docs.docker.com/engine/install/ubuntu/
[firmware]: /firmware
[halucinator-loglevel]: /src/halucinator/__init__.py
[license]: /LICENSE
[make-main]: /Makefile
[paper]: https://hexhive.epfl.ch/publications/files/24BAR.pdf

[^gdb-docker]: Running gdb inside of Docker will by default not work due to
               restrictions when accessing the ptrace API.
               If you are willing to fiddle with the Docker container's
               permissions/capabilities, you should be able to get that working
               as well, though. For simplicity, we recommend running gdb on the
               host.
