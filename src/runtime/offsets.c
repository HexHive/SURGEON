/*
 * This file is never linked against and only serves to calculate `struct`
 * offsets at build time for using the offsets in assembly code.
 * Check the Makefile to see how it's used.
 */

#include <surgeon/context.h>
#include <surgeon/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>

#define DEFINE(sym, val)                       \
    do {                                       \
        printf("#define " #sym " %u \n", val); \
    } while (0)
#define OFFSETOF(s, m) DEFINE(OFFSETOF_##s##_##m, offsetof(s, m))
#define SIZEOF(s) DEFINE(SIZEOF_##s, sizeof(s))

/**
 * @brief Print offsets/sizes of structs
 *
 * @param argc number of arguments
 * @param argv arguments
 *
 * @returns int status code
 */
int main(UNUSED int argc, UNUSED char *argv[]) {
    /* Header */
    puts("/*");
    puts(" * Warning: This is an auto-generated header file.");
    puts(" * Do not modify the file, it will be overwritten by the next");
    puts(" * invocation of the compiler.");
    puts(" */");
    puts("#ifndef STRUCT_OFFSETS_H");
    puts("#define STRUCT_OFFSETS_H");
    puts("#pragma once");
    puts("");
    /* context_t struct (from surgeon/context.h)*/
    OFFSETOF(context_t, r0);
    OFFSETOF(context_t, r1);
    OFFSETOF(context_t, r2);
    OFFSETOF(context_t, r3);
    OFFSETOF(context_t, r4);
    OFFSETOF(context_t, r5);
    OFFSETOF(context_t, r6);
    OFFSETOF(context_t, r7);
    OFFSETOF(context_t, r8);
    OFFSETOF(context_t, r9);
    OFFSETOF(context_t, r10);
    OFFSETOF(context_t, r11);
    OFFSETOF(context_t, r12);
    OFFSETOF(context_t, sp);
    OFFSETOF(context_t, lr);
    OFFSETOF(context_t, pc);
    OFFSETOF(context_t, xpsr);
    SIZEOF(context_t);
    puts("");
    /* mcontext_t struct (from ucontext.h) */
    OFFSETOF(mcontext_t, arm_r0);
    OFFSETOF(mcontext_t, arm_r1);
    OFFSETOF(mcontext_t, arm_r2);
    OFFSETOF(mcontext_t, arm_r3);
    OFFSETOF(mcontext_t, arm_r4);
    OFFSETOF(mcontext_t, arm_r5);
    OFFSETOF(mcontext_t, arm_r6);
    OFFSETOF(mcontext_t, arm_r7);
    OFFSETOF(mcontext_t, arm_r8);
    OFFSETOF(mcontext_t, arm_r9);
    OFFSETOF(mcontext_t, arm_r10);
    OFFSETOF(mcontext_t, arm_fp);
    OFFSETOF(mcontext_t, arm_ip);
    OFFSETOF(mcontext_t, arm_sp);
    OFFSETOF(mcontext_t, arm_lr);
    OFFSETOF(mcontext_t, arm_pc);
    OFFSETOF(mcontext_t, arm_cpsr);
    SIZEOF(mcontext_t);
    puts("");
    puts("#endif /* STRUCT_OFFSETS_H */");
}
