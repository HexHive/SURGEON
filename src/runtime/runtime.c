/* ##############   Includes   ############## */
#include <elf.h>
#include <surgeon/context.h>
#include <surgeon/emu_handler.h>
#include <surgeon/forkserver.h>
#include <surgeon/instrumentation.h>
#include <surgeon/runtime.h>
#include <surgeon/symbols.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

/* ##############   Typedefs   ############## */
typedef enum _execmode_e {
    NOFORK,      // do not fork, we jump to the target in the current process
    FORKONCE,    // we fork and wait for the child in the parent
    FORKSERVER,  // the forkserver expected by afl
} execmode_t;

/* #########   Function signatures   ######## */
static void NORETURN _main(int argc, char *argv[], UNUSED char *envp[]);
static void NORETURN usage(const char *exec);
static void fork_target(void *entrypoint);
static uintptr_t load_elf(const char *elf_filename);
static success_t verify_header(FILE *elf_file);
static success_t map_rw_region(uintptr_t base, size_t size);
static success_t map_elf(FILE *elf_file, uintptr_t *entrypoint);
static void UNUSED print_coverage_map(char *shm);
static inline void NORETURN call_elf(const void *entrypoint);
static void call_python_handler(const symbol_t *sym);
void *map_region_from_env(const char *env_var, size_t size);
void USED dispatch_c(void);

/* ###############   Globals   ############## */
/* The stack we use for our code to make sure it's not colliding with the FW */
uint8_t stack[STACKSIZE + ARGENVSIZE] = {0};

int main(int argc, char *argv[], char *envp[]) {
    /* We need to pivot the stack to a location we control. The reason for that
     * is that we observed situations where the stack was mapped into regions
     * overlapping with regions that we use for setting up the firmware address
     * space. */
    ucontext_t uctx = {0};
    /* Get the current context */
    if (getcontext(&uctx) == -1) {
        perror("Encountered error during context retrieval");
        return EXIT_FAILURE;
    }

    /* Copy argv and envp to the upper addresses of our new stack */
    uintptr_t stack_top = (uintptr_t)stack + sizeof(stack);
    /* Copy argv */
    stack_top -= sizeof(argv[0]) * (argc + 1);
    char **new_argv = (char **)stack_top;
    for (size_t i = 0; i < (size_t)argc; i++) {
        size_t arg_len = strlen(argv[i]) + 1;
        /* Make space on the stack */
        stack_top -= arg_len;
        /* Copy argument and set pointer in argv */
        memcpy((void *)stack_top, argv[i], arg_len);
        new_argv[i] = (char *)stack_top;
    }
    new_argv[argc] = NULL;
    /* Copy envp */
    size_t envc = 0;
    /* First, count length of envp array */
    while (envp[envc] != NULL) {
        envc++;
    }
    /* Second, do the actual copy similar to argv above */
    stack_top -= sizeof(envp[0]) * (envc + 1);
    char **new_envp = (char **)stack_top;
    for (size_t i = 0; i < envc; i++) {
        size_t env_len = strlen(envp[i]) + 1;
        /* Make space on the stack */
        stack_top -= env_len;
        /* Copy argument and set pointer in envp */
        memcpy((void *)stack_top, envp[i], env_len);
        new_envp[i] = (char *)stack_top;
    }
    new_envp[envc] = NULL;
    /* Update the libc environment pointer in addition to passing new_envp on */
    __environ = new_envp;

    /* Make sure we didn't overflow the part of the stack that is dedicated to
     * argv and envp */
    if (stack_top < (uintptr_t)stack + STACKSIZE) {
        fprintf(
            stderr,
            "argv/envp overflowed into the stack region for the new context. "
            "Increase the range dedicated to argv/envp and try again.");
        return EXIT_FAILURE;
    }

    /* Modify the context to use our new stack */
    uctx.uc_link = NULL;
    uctx.uc_stack.ss_sp = &stack;
    uctx.uc_stack.ss_size = STACKSIZE;
    makecontext(&uctx, (void (*)(void))_main, 3, argc, new_argv, new_envp);
    /* Switch context to our actual main function */
    if (setcontext(&uctx) == -1) {
        perror("Encountered error during context switching");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/**
 * @brief The main function after pivoting the stack
 *
 * In order to avoid collisions with the firmware, we pivot the stack and
 * use this function as our actual main function. The original main function
 * only takes care of the stack management.
 *
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param envp Array of environment variables
 */
static void NORETURN _main(int argc, char *argv[], UNUSED char *envp[]) {
    char *fw_filename = NULL;
    char *tramp_filename = NULL;
    execmode_t execmode = NOFORK;

    /* Define and parse command line arguments */
    while (true) {
        static const struct option long_opts[] = {
            {"execmode", required_argument, NULL, 'x'},
            {"file", required_argument, NULL, 'f'},
            {"trampoline", required_argument, NULL, 't'},
            {"help", no_argument, NULL, 'h'},
        };

        static const char short_opts[] = "x:f:t:h";
        int opt_index = 0;

        int c = getopt_long(argc, argv, short_opts, long_opts, &opt_index);
        /* End of arguments */
        if (c == -1) {
            break;
        }

        /* Parse current argument */
        switch (c) {
            case 'x': {
                printf("Execution mode %s\n", optarg);
                if (!strcmp(optarg, "NOFORK")) {
                    execmode = NOFORK;
                } else if (!strcmp(optarg, "FORKONCE")) {
                    execmode = FORKONCE;
                } else if (!strcmp(optarg, "FORKSERVER")) {
                    execmode = FORKSERVER;
                } else {
                    usage(basename(argv[0]));
                }
                break;
            }
            case 'f': {
                printf("Firmware file name passed: %s\n", optarg);
                fw_filename = optarg;
                break;
            }
            case 't': {
                printf("Trampoline file name passed: %s\n", optarg);
                tramp_filename = optarg;
                break;
            }
            case 'h':
            case ':':
            case '?': {
                usage(basename(argv[0]));
                break;
            }
            default: {
                abort();
                break;
            }
        }
    }

    /* Check whether file argument is provided, exit if not */
    if (argc < 2 || fw_filename == NULL) {
        usage(basename(argv[0]));
    }

    /* Create the address space layout the firmware expects. The order of
     * mappings is important since all calls to mmap use MAP_FIXED and may
     * therefore override previous mappings:
     * 1. Map SRAM region
     * 2. Map PPB region
     * 3. Map firmware (which might override parts of SRAM!)
     * 4. Map MMIO range (which might override the previous stack used before
     *    the pivot in from main to _main). This needs to come last because
     *    the pointers to program arguments are otherwise not valid anymore! */

    /* Map the SRAM region the firmware to be mapped expects */
    if (map_rw_region(RAM_BASE, RAM_SIZE) != SUCCESS) {
        fprintf(stderr, "Could not map SRAM region for firmware.");
        exit(EXIT_FAILURE);
    }

    /* Map the (Private Peripheral Bus) PPB region the firmware to be mapped
     * expects
     * TODO: actually map functionality to this region, this is where NVIC,
     * system configuration registers, etc. are supposed to be located! Also,
     * make sure this mapping is even required and we do not abstract accesses
     * to the PPB away with HAL handlers anyway */
    if (map_rw_region(PPB_BASE, PPB_SIZE) != SUCCESS) {
        fprintf(stderr, "Could not map PPB region for firmware.");
        exit(EXIT_FAILURE);
    }

    /* Map the ELF file(s) into the address space */
    uintptr_t entrypoint = 0;
    entrypoint = load_elf(fw_filename);
    if (tramp_filename) {
        load_elf(tramp_filename);
    }

    /* Map the MMIO region to not crash immediately on accesses to the region.
     * Does not exactly mimick HALucinators behavior (read 0, ignore write) but
     * reads whatever has been written before. That's "good enough" without
     * needing to resort to kernel/device shenanigans for getting HALucinator's
     * behavior. */
    if (map_rw_region(MMIO_BASE, MMIO_SIZE) != SUCCESS) {
        fprintf(stderr, "Could not map MMIO region for firmware.");
        exit(EXIT_FAILURE);
    }

    /* Initialize the firmware's VTOR to a marker so that we can detect if it
     * has not been initialized yet (the firmware will overwrite that in the
     * reset handler anyways) */
    *VTOR = (vect_t *)UNINITIALIZED;

    /* Initialize the embedded Python interpreter for our handlers */
    if (!Py_IsInitialized()) {
        /* Make our C module available to the interpreter */
        PyImport_AppendInittab("surgeon", &PyInit_surgeon);
        /* Init the interpreter */
        Py_Initialize();
        /* Eagerly pre-initialize/import the handlers */
        if (PyImport_ImportModule("halucinator") == NULL) {
            fprintf(stderr,
                    "WARNING: 'halucinator' module could not be "
                    "pre-initialized. Execution will continue but may be "
                    "slower or imports may fail later on.");
        }
    }

    /* Set the signal handler for instruction transplantation traps */
    if (set_emu_handler() != SUCCESS) {
        fprintf(stderr, "Could not register emulation request handler.");
        exit(EXIT_FAILURE);
    }

    if (execmode == NOFORK || execmode == FORKONCE) {
        /* Obtain instrumentation control runtime address, map it, and populate
         * it. */

        cov_instr_ctrl_t *instr_ctrl = (cov_instr_ctrl_t *)map_region_from_env(
            INSTR_CTRL_ADDR_ENV, PAGESIZE);
        if (!instr_ctrl) {
            fprintf(stderr, "Cannot map instrumentation control region\n");
            exit(EXIT_FAILURE);
        }

        /* Initialize prev_location with a random value to mimic the behavior of
         * afl-as. */
        instr_ctrl->prev_location = (rand() % (1 << 16)) + 1;

        void *shm = map_region_from_env(SHM_ADDR_ENV, AFL_MAP_SIZE);
        if (!shm) {
            fprintf(stderr, "Cannot map shared memory region\n");
            exit(EXIT_FAILURE);
        }

        bzero(shm, AFL_MAP_SIZE);

        if (execmode == NOFORK) {
            call_elf((void *)entrypoint);
        } else {
            /* Fork and execute the target */
            fork_target((void *)entrypoint);
#ifndef NDEBUG
            print_coverage_map(shm);
#endif /* NDEBUG */
        }
    } else if (execmode == FORKSERVER) {
        int ret = start_forkserver(call_elf, (void *)entrypoint);
        if (!ret) {
            fprintf(stderr, "Faild starting forkserver.");
        }
    }

    /* Tear down the embedded Python interpreter for our handlers */
    Py_FinalizeEx();

    exit(EXIT_SUCCESS);
}

/**
 * @brief Map a region of size `size` given by the environment variable
 * `env_var`.
 *
 * @param env_var Identifier of the env var.
 * @param size    The size of the mapping.
 * @return void*  Address of the new mapping.
 */
void *map_region_from_env(const char *env_var, size_t size) {
    char *region_addr_s = getenv(env_var);
    if (!region_addr_s) {
        fprintf(stderr, "%s missing\n", env_var);
        return NULL;
    }

    char *endptr = NULL;
    uintptr_t region_addr = (uintptr_t)strtoll(region_addr_s, &endptr, 16);
    if (errno == ERANGE || errno == EINVAL || *endptr != '\0') {
        fprintf(stderr, "Cannot convert address %s\n", region_addr_s);
        return NULL;
    }

    void *region = mmap((void *)region_addr, size, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED, -1, 0);

    if (region == MAP_FAILED) {
        fprintf(stderr, "Failed to map region\n");
        return NULL;
    }

    return region;
}

/**
 * @brief Print usage information
 *
 * @param exec Name of the executable
 */
static void NORETURN usage(const char *exec) {
    fprintf(stderr,
            "Usage: %s [-h/--help] [-x/--execmode "
            "(NOFORK|FORKONCE|FORKSERVER)] -f/--file <firmware-image> "
            "[-t/--trampoline <trampoline-image>]\n",
            exec);
    exit(EXIT_SUCCESS);
}

/**
 * @brief Print the AFL coverage map ('.' = no hit, 'x' = hit)
 *
 * @param shm Memory region holding coverage map of size `AFL_MAP_SIZE`
 */
static void print_coverage_map(char *shm) {
    for (size_t i = 0; i < AFL_MAP_SIZE / 128; i++) {
        printf("%p: ", &shm[i * 128]);
        for (size_t j = 0; j < 128; j++) {
            if (shm[(i * 128) + j] == '\0') {
                printf(".");
            } else {
                printf("x");
            }
        }
        printf("\n");
    }
    return;
}

/**
 * @brief Load the elf into this address space and return the elf's entrypoint.
 *
 * Open `elf_filename`, check its ELF header, and map its loadable segemnts into
 * this address space.
 *
 * @param elf_filename File path to ELF.
 * @return Entrypoint to the mapped ELF.
 */
static uintptr_t load_elf(const char *elf_filename) {
    uintptr_t entrypoint = 0;

    /* Open the file we received */
    FILE *elf_file = fopen(elf_filename, "r");
    if (elf_file == NULL) {
        fprintf(stderr, "Failed to open file\n");
        exit(EXIT_FAILURE);
    }

    /* Verify the ELF headers */
    if (verify_header(elf_file) != SUCCESS) {
        fprintf(stderr, "Invalid file type\n");
        return EXIT_FAILURE;
    }

    /* Map the ELF into memory */
    if (map_elf(elf_file, &entrypoint) != SUCCESS) {
        fprintf(stderr, "Failed to map ELF into memory\n");
        return EXIT_FAILURE;
    }

    return entrypoint;
}

/**
 * @brief Fork, run the target in the child, and wait for child in the parent.
 *
 * @param entrypoint Entrypoint of the target (already mapped in our address
 *                   space)
 */
static void fork_target(void *entrypoint) {
    pid_t child_pid;
    int status = 0;

    child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        goto error;
    }

    if (!child_pid) {
        /* Transfer control to the loaded ELF */
        call_elf((void *)entrypoint);
    }

    if (waitpid(child_pid, &status, 0) < 0) {
        perror("waitpid");
        goto error;
    }
    printf("Child terminated with status %#x\n", status);

error:
    return;
}

/**
 * @brief Verify the ELF file's headers
 *
 * Verifies the passed file by checking whether it's actually an ELF file or not
 * and if yes, whether it targets the architectures currently supported by
 * SURGEON.
 *
 * @param elf_file Open file handle pointing to the file to verify
 * @return SUCCESS if file is valid ELF, ERROR otherwise
 */
static success_t verify_header(FILE *elf_file) {
    Elf32_Ehdr header = {0};
    /* Make sure we're at the start of the file before reading */
    rewind(elf_file);
    size_t bytes_read = fread(&header, 1, sizeof(Elf32_Ehdr), elf_file);
    if (bytes_read != sizeof(Elf32_Ehdr)) {
        /* Couldn't read full header */
        return ERROR;
    }
    if (header.e_ident[EI_MAG0] != ELFMAG0 /**/
        || header.e_ident[EI_MAG1] != ELFMAG1
        || header.e_ident[EI_MAG2] != ELFMAG2
        || header.e_ident[EI_MAG3] != ELFMAG3
        || header.e_ident[EI_CLASS] != ELFCLASS32) {
        /* Invalid file type */
        return ERROR;
    }
    return SUCCESS;
}

/**
 * @brief Map a given memory range read-write
 *
 * The function maps a memory range given by base and size with RW permissions.
 * This memory range can for example act as the SRAM or PPB region for the
 * firmware (see ARMv7-M Architecture Reference Manual, Chapter "System Address
 * Map"). Note that this function needs to be called before mapping the ELF
 * because it might otherwise overwrite parts of the mapped ELF due to the usage
 * of MAP_FIXED!
 *
 * @param base The base address where to map the region
 * @param size The size of the desired region
 * @return success_t SUCCESS if the region could successfully be mapped, ERROR
 * otherwise
 */
static success_t map_rw_region(uintptr_t base, size_t size) {
    /* Prepare mmap arguments */
    void *target = (void *)ROUND_PAGE_DOWN(base);
    size_t length = ROUND_PAGE_UP(size);
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;
    /* Map the region */
    void *addr = mmap(target, length, prot, flags, -1, 0);
    /* Make sure that the region is located where we want it to be */
    return ((uintptr_t)addr == (uintptr_t)ROUND_PAGE_DOWN(base)) ? SUCCESS
                                                                 : ERROR;
}

/**
 * @brief Map an ELF's segments into the process
 *
 * The function calls mmap to map all loadable segments of the ELF file passed
 * via the parameter elf_file at their corresponding addresses into the
 * process's address space.
 *
 * @param[in] elf_file Open file handle pointing to the file to load
 * @param[out] entrypoint Entry point address of the loaded ELF
 * @return success_t SUCESS if all segments could successfully be mapped, ERROR
 * otherwise
 */
static success_t map_elf(FILE *elf_file, uintptr_t *entrypoint) {
    Elf32_Ehdr ehdr = {0};
    /* Make sure we're at the start of the file before reading */
    rewind(elf_file);
    size_t bytes_read = fread(&ehdr, 1, sizeof(Elf32_Ehdr), elf_file);
    if (bytes_read != sizeof(Elf32_Ehdr)) {
        /* Couldn't read full header */
        return ERROR;
    }
    *entrypoint = ehdr.e_entry;

    if (fseek(elf_file, ehdr.e_phoff, SEEK_SET) != 0) {
        /* Seeking the program header offset failed */
        return ERROR;
    }

    int fd = fileno(elf_file);
    for (size_t i = 0; i < ehdr.e_phnum; i++) {
        Elf32_Phdr phdr = {0};
        /* No fseek necessary because fread advances the pointer */
        if (fread(&phdr, 1, ehdr.e_phentsize, elf_file) != ehdr.e_phentsize) {
            /* Reading the next program header entry failed */
            return ERROR;
        }
        if (phdr.p_type != PT_LOAD) {
            /* Skip non-LOAD segments */
            continue;
        }

        if (phdr.p_filesz == 0) {
            continue;
        }

        void *target = (void *)ROUND_PAGE_DOWN(phdr.p_vaddr);
        off_t source = (off_t)ROUND_PAGE_DOWN(phdr.p_offset);
        /* Map more than we actually need... some ELF headers are messed up
         * TODO: outsource that into a configuration */
        size_t len = ROUND_PAGE_UP(phdr.p_memsz) * 2;
        int prot = PROT_NONE;
        prot |= (phdr.p_flags & PF_R) ? PROT_READ : 0;
        prot |= (phdr.p_flags & PF_W) ? PROT_WRITE : 0;
        prot |= (phdr.p_flags & PF_X) ? PROT_EXEC : 0;
#ifndef NDEBUG
        fprintf(stderr, "Mapping 0x%08zx - 0x%08zx %c%c%c\n", (uintptr_t)target,
                (uintptr_t)target + len, (phdr.p_flags & PF_R) ? 'r' : '-',
                (phdr.p_flags & PF_W) ? 'w' : '-',
                (phdr.p_flags & PF_X) ? 'x' : '-');
#endif /* NDEBUG */
        void *addr =
            mmap(target, len, prot, MAP_PRIVATE | MAP_FIXED, fd, source);
        if (addr != target) {
            /* Requested mapping could not be conducted */
            return ERROR;
        }
    }

    return SUCCESS;
}

/**
 * @brief Transfer control to the provided entrypoint.
 *
 * The function branches to the given entrypoint. Based on the lowest bit of the
 * entrypoint address, it either branches to Thumb mode or to Arm mode. Arm's
 * BX instruction takes care of that differentiation automatically.
 * We also store the current stack pointer in order to be able to restore it
 * later on in the HAL dispatcher.
 *
 * @param entrypoint Pointer to the loaded ELF's entry point
 */
static inline void NORETURN call_elf(const void *entrypoint) {
    /* Set a stack pointer for the firmware at the RAM top. The firmware might
       set its own stack pointer which is totally fine but we have a fallback
       in this case if it does not.
       TODO: load initial stack pointer from vector table instead */
    uintptr_t fw_ram_top = ROUND_PAGE_DOWN(RAM_BASE) + ROUND_PAGE_UP(RAM_SIZE);
    uintptr_t msp = fw_ram_top;
    uintptr_t psp =
        fw_ram_top - (16 * 1024); /* 16KiB of main stack are hopefully enough */

    asm volatile(
        "vmov.32 " STR(MSP_EMU_REG) ", %[msp] \n\t"
        "vmov.32 " STR(PSP_EMU_REG) ", %[psp] \n\t"
        "str sp, [%[ldr_stack]]               \n\t"
        "mov sp, %[psp]                       \n\t"
        "bx %[entry]                          \n\t"
        :
        : [entry] "r"(entrypoint), [ldr_stack] "r"(&runtime_sp), [msp] "r"(msp),
          [psp] "r"(psp)
        : "memory");
    /* Will never return here from the loaded firmware image */
    __builtin_unreachable();
}

/**
 * @brief Call into the Python context.
 *
 * The function calls into the in-process Python context/interpreter.
 * For now, this is only a wrapper around an example handler and will be
 * extended to call into HALucinator-style handlers later.
 *
 * @param sym_name The symbol name passed to the Python context.
 */
static void call_python_handler(const symbol_t *sym) {
    PyObject *pName = NULL;
    PyObject *pModule = NULL;
    PyObject *pFunc = NULL;
    PyObject *pArgs = NULL;
    PyObject *pValue = NULL;
    const char *module = "halucinator";
    const char *function = "call_handler";

    pName = PyUnicode_DecodeFSDefault(module);
    /* Error checking of pName left out */

    if (!(pModule = PyImport_GetModule(pName))) {
        /* Import HALucinator handlers if it hasn't happened yet */
        pModule = PyImport_Import(pName);
    }
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, function);
        /* pFunc is a new reference */

        if (pFunc && PyCallable_Check(pFunc)) {
            /* Two arguments: handler name and symbol address */
            pArgs = PyTuple_New(2);
            /* Argument 1: handler name */
            pValue = PyUnicode_FromString(sym->handler);
            if (!pValue) {
                Py_DECREF(pArgs);
                Py_DECREF(pModule);
                fprintf(stderr, "Cannot convert argument\n");
                return;
            }
            PyTuple_SetItem(pArgs, 0, pValue);
            /* Argument 2: symbol address */
            pValue = PyLong_FromSize_t((size_t)sym->sym_addr);
            if (!pValue) {
                Py_DECREF(pArgs);
                Py_DECREF(pModule);
                fprintf(stderr, "Cannot convert argument\n");
                return;
            }
            PyTuple_SetItem(pArgs, 1, pValue);
            /* Call the handler */
            pValue = PyObject_CallObject(pFunc, pArgs);
            Py_DECREF(pArgs);
            if (pValue != NULL && PyObject_IsTrue(pValue)) {
                Py_DECREF(pValue);
            } else {
                PyErr_Print();
                fprintf(stderr, "Call failed\n");
            }
        } else {
            if (PyErr_Occurred())
                PyErr_Print();
            fprintf(stderr, "Cannot find function \"%s\"\n", function);
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    } else {
        PyErr_Print();
        fprintf(stderr, "Failed to load \"%s\"\n", module);
    }
}

/**
 * @brief Dispatch the call site to the corresponding handler.
 *
 * The function checks its call site to determine which HAL function the caller
 * intended to call. This information is then used to dispatch to the
 * corresponding handler taken from/inspired by HALucinator.
 */
void dispatch_c(void) {
    /* Get the HAL function's PC from the context */
    uintptr_t hal_func = (uintptr_t)fw_context.pc;

    /* Figure out which HAL function was called => -4 because of Arm Thumb PC
       prefetch */
    uintptr_t func_ptr = hal_func - 4;
    for (size_t i = 0; i < symbol_num; i++) {
        if (symbols[i].sym_addr == func_ptr) {
#ifndef NDEBUG
            puts(symbols[i].sym_name);
#endif /* NDEBUG */
            call_python_handler(&symbols[i]);
            /* Assume only a single handler per symbol is called */
            break;
        }
    }
}
