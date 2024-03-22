c_files = files('cov-test.c', 'syscalls.c')

c_flags = get_option('c_args')
c_flags += ['-Wall', '-Wextra', '-Werror']

exe = executable('cov-test',
    c_files,
    c_args: c_flags,
    link_args: c_flags,
    native: false
)
