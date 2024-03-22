#!/usr/bin/env bash

# Quit on errors
set -ue

# Set base directories if not provided in environment
WORKDIR=${WORKDIR:-/surgeon/src}
FWDIR=${FWDIR:-/surgeon/firmware}
# Set firmware file to use provided as an argument (or default if none)
FIRMWARE=${1:-fw-example}
# Set path to firmware src and binary
FIRMWARE_SRC=${FWDIR}/${FIRMWARE}
FIRMWARE_BASE=$(basename ${FIRMWARE})
OUTDIR=/surgeon/out/${FIRMWARE_BASE}
FIRMWARE_BIN=${FIRMWARE_SRC}/${FIRMWARE_BASE}

# Create ghidraproj folder if not exist yet
if [[ ! -d ${OUTDIR}/ghidraproj ]]; then
    mkdir -p ${OUTDIR}/ghidraproj
fi

# `$(FIRMWARE)_syms.yaml` contains addresses of HAL functions that we do not
# want to instrument. Giving this file to Ghidra here ensures that these funcs
# are excluded from the resulting basic block list.
SYMS=${FIRMWARE_SRC}/${FIRMWARE_BASE}_syms.yaml
if [[ -f ${SYMS} ]]; then
# Get all BBs for instrumentation (first postscript: get all BBs in the file,
# second postscript: get "below HAL BBs in the file)
    /ghidra/support/analyzeHeadless \
        ${OUTDIR}/ghidraproj tmpProj \
        -import ${FIRMWARE_BIN} \
        -postScript /surgeon/src/ghidrathon/basic_blocks.py ${SYMS} \
        -postScript /surgeon/src/ghidrathon/hal.py ${SYMS} \
        -deleteProject
else
    /ghidra/support/analyzeHeadless \
        ${OUTDIR}/ghidraproj tmpProj \
        -import ${FIRMWARE_BIN} \
        -postScript /surgeon/src/ghidrathon/basic_blocks.py \
        -deleteProject
fi
