#!/bin/bash

# Set base directory if not provided in environment
WORKDIR=${WORKDIR:-/surgeon/src}
# Set firmware file to use provided as an argument (or default if none)
FIRMWARE=${1:-fw-example}
# Set path to firmware binary
FIRMWARE_BASE=$(basename ${FIRMWARE})
OUTDIR=/surgeon/out/${FIRMWARE_BASE}
FIRMWARE_BIN=${OUTDIR}/${FIRMWARE_BASE}
# Range qemu-user collects traces for
TRACE_CODE_START=${2:-0x08000000}
TRACE_CODE_END=${3:-0x08010000}
# Make sure that we have defaults for the AFL shared memory addresses in the env
export INSTR_CTRL_ADDR=${INSTR_CTRL_ADDR:-0xE0100000}
export SHM_ADDR=${SHM_ADDR:-0xE0101000}

# Update PYTHONPATH so that we can use our modules from anywhere in the system
export PYTHONPATH=${PYTHONPATH}:${WORKDIR}

# Quit on errors
set -ue

trap "exit 0" SIGINT

if [[ -f ${OUTDIR}/input ]]; then

cat ${OUTDIR}/input | timeout 5s qemu-arm -D ${OUTDIR}/trace.txt -d cpu,nochain -dfilter ${TRACE_CODE_START}..${TRACE_CODE_END} ${OUTDIR}/runtime -x NOFORK -f ${FIRMWARE_BIN}-rewritten -t ${FIRMWARE_BIN}-rewritten-tramp || true

else

  echo "Input file missing: ${OUTDIR}/input"

fi
