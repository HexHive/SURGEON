#!/bin/bash

# Set base directory if not provided in environment
WORKDIR=${WORKDIR:-/surgeon/src}
# Set firmware file to use provided as an argument (or default if none)
FIRMWARE=${1:-fw-example}
# Set path to firmware binary
FIRMWARE_BASE=$(basename ${FIRMWARE})
OUTDIR=/surgeon/out/${FIRMWARE_BASE}
FIRMWARE_BIN=${OUTDIR}/${FIRMWARE_BASE}

# Make sure that we have defaults for the AFL shared memory addresses in the env
export INSTR_CTRL_ADDR=${INSTR_CTRL_ADDR:-0xE0100000}
export SHM_ADDR=${SHM_ADDR:-0xE0101000}

# Update PYTHONPATH so that we can use our modules from anywhere in the system
export PYTHONPATH=${PYTHONPATH}:${WORKDIR}

# Quit on errors
set -ue

trap "exit 0" SIGINT

# Run either qemu-user with the gdb stub or a gdb server, depending on host arch
if [[ $(uname -m) == "aarch64" ]]; then
    gdbserver --once localhost:1234 ${OUTDIR}/src/runtime/runtime -x NOFORK \
        -f ${FIRMWARE_BIN}-rewritten -t ${FIRMWARE_BIN}-rewritten-tramp
else
    qemu-arm -g 1234 ${OUTDIR}/src/runtime/runtime -x NOFORK \
        -f ${FIRMWARE_BIN}-rewritten -t ${FIRMWARE_BIN}-rewritten-tramp
fi
