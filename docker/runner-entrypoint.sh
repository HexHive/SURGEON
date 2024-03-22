#!/bin/bash

# Set base directories if not provided in environment
WORKDIR=${WORKDIR:-/surgeon}
FWDIR=${FWDIR:-/surgeon/firmware}
# Set firmware file to use provided as an argument (or default if none)
FIRMWARE=${1:-fw-example}
# Determine whether to fuzz (and if yes for how long) or what else to do
ACTION=${2:-run}
FUZZTIME=${AFL_TIMEOUT:-86400}
SURGEON_AFL_TIMEOUT=${SURGEON_AFL_TIMEOUT:-1000}
# Set path to firmware src and binary
FIRMWARE_SRC=${FWDIR}/${FIRMWARE}
FIRMWARE_BASE=$(basename ${FIRMWARE})
OUTDIR=${WORKDIR}/out/${FIRMWARE_BASE}

# Make sure that we have defaults for the AFL shared memory addresses in the env
export INSTR_CTRL_ADDR=${INSTR_CTRL_ADDR:-0xE0100000}
export SHM_ADDR=${SHM_ADDR:-0xE0101000}

# Update PYTHONPATH so that we can use our modules from anywhere in the system
export PYTHONPATH=${PYTHONPATH}:${WORKDIR}/src

# Quit on errors
set -ue

# Enable the python virtualenv for the rewriter
source /root/.venv/bin/activate

# Setup meson if not already done
if [[ ! -d ${OUTDIR} ]]; then
    meson setup \
        --backend=ninja \
        --layout=mirror \
        --native-file=${WORKDIR}/arm-linux-gnueabihf.ini \
        --cross-file=${WORKDIR}/arm-linux-musleabi.ini \
        ${OUTDIR} \
        ${WORKDIR}
fi

[[ "${ACTION}" == "fuzz" ]] && BUILDTYPE="release" || BUILDTYPE="debug"

# Configure meson for the firmware and build type
meson configure ${OUTDIR} --buildtype=${BUILDTYPE} -Dfirmware=${FIRMWARE}

# Build runtime and rewrite firmware if necessary
ninja -C ${OUTDIR}

RUNTIME_BIN=${OUTDIR}/src/runtime/runtime
FIRMWARE_BIN=${OUTDIR}/${FIRMWARE_BASE}
# Run the runtime (if it was built successfully)
if [[ "$ACTION" == "run" ]]; then
    ${RUNTIME_BIN} -x NOFORK -f ${FIRMWARE_BIN}-rewritten -t ${FIRMWARE_BIN}-rewritten-tramp
elif [[ "$ACTION" == "fuzz" ]]; then
    afl-fuzz -t ${SURGEON_AFL_TIMEOUT} \
        -i ${WORKDIR}/out/afl-in \
        -o ${WORKDIR}/out/afl-out \
        -V ${FUZZTIME} \
        ${RUNTIME_BIN} -x FORKSERVER -f ${FIRMWARE_BIN}-rewritten -t ${FIRMWARE_BIN}-rewritten-tramp
elif [[ "$ACTION" == "build" ]]; then
    echo "[INFO] Built runtime and instrumented firmware successfully"
else
    echo "[ERROR] Unknown argument ${ACTION}: use 'run' for a single "`
        `"execution, 'fuzz' for an AFL++ fuzzing campaign, or 'build' "`
        `"for only building the runtime/rewriting the firmware"
fi
