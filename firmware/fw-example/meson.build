c_files = files('fw-example.c', 'syscalls.c')

c_flags = get_option('c_args')
c_flags += ['-Wall', '-Wextra', '-Werror']

exe = executable('fw-example',
    c_files,
    c_args: c_flags,
    link_args: c_flags,
    native: false
)
