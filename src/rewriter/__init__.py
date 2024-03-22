#!/usr/bin/env python3

# Make sure that Capstone and Keystone are initialized when the module is loaded
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB
# Init capstone
EF_DISASM = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
EF_DISASM.detail = True
# Init keystone
EF_ASM = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

