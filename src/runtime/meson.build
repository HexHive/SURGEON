runtime_path = meson.current_source_dir()

runtime_srcs = files(
    'context.c',
    'dispatcher.S',
    'emu_handler.c',
    'forkserver.c',
    'interrupts.c',
    'interrupts_asm.S',
    'runtime.c',
    'timer.c'
)
runtime_srcs += autogen_c

offset_generator_srcs = files('offsets.c')

subdir('handlers')
subdir('models')

py_dep = dependency('python3-embed', static: true)
zlib_dep = dependency('zlib', static: true)
expat_dep = dependency('expat', static: true)

runtime_linker_script = files(runtime_path / 'link.lds')

runtime_cflags = get_option('build.c_args')

if py_dep.found()
    # Disabling the warning is required because of native Python extensions
    runtime_cflags += ['-Wno-cast-function-type']
endif

runtime_ldflags = ['-static',
                  '-T', runtime_linker_script[0].full_path()]

# Prevent runtime from using the D16/D17 floating point registers because we use
# them for our MSP/PSP emulation
runtime_cflags += ['-ffixed-d16', '-ffixed-d17']

incdir = include_directories('include')

offset_generator = executable('offsets',
    sources: offset_generator_srcs,
    c_args: runtime_cflags,
    include_directories: incdir,
    dependencies: [py_dep],
    native: true
)

struct_offsets = custom_target('struct_offsets.h',
    output: 'struct_offsets.h',
    command: [offset_generator],
    capture: true
)

runtime_srcs += struct_offsets

runtime = executable('runtime',
    sources: runtime_srcs,
    c_args: runtime_cflags,
    include_directories: incdir,
    link_args: runtime_ldflags,
    link_depends: runtime_linker_script,
    dependencies: [py_dep, zlib_dep, expat_dep],
    native: true
)
