project('surgeon', 'c',
  meson_version: '>=1.4.0',
  default_options: [
    'prefer_static=true',
    'strip=false',
    'werror=true',
    'warning_level=3',
    'b_ndebug=if-release',
    'b_pie=false',
    ],
  version: '0.1.0',
  license: 'MIT'
)

pymod = import('python')
prog_python = pymod.find_installation('python3', required : true)

firmware = get_option('firmware')

# Only keep the last path component as target
target = firmware.split('/')[-1]

src_path = 'firmware' / firmware
# Add firmware-specific meson configs
subdir(src_path)

autogen_c = custom_target(target + '_autogen.c',
    input: src_path / target + '_syms.yaml',
    output: target + '_autogen.c',
    command: [prog_python, '-m', 'autogen',
                           '-c', '@INPUT@',
                           '-o', '@OUTPUT@'],
)

# Add runtime
subdir('src')

autogen_yaml = custom_target(target + '_autogen.yaml',
    input: runtime,
    output: target + '_autogen.yaml',
    command: [prog_python, '-m', 'autogen',
                           '-l', '@INPUT@',
                           '-o', '@OUTPUT@'],
)

deps = files(src_path / target + '-trans-bbs.yaml',
             src_path / target + '-cov.yaml',
             src_path / target + '_syms.yaml')
deps += autogen_yaml
deps += exe

cov = get_option('coverage')
coverage = '--' + (cov ? '' : 'no-') + 'coverage'

# Trampoline file in output is an implicit output of the rewriter
custom_target(target + '-rewritten',
    input: deps,
    output: [target + '-rewritten', target + '-rewritten-tramp'],
    command: [prog_python, '-m', 'rewriter',
                           '-t', '@INPUT0@',
                           '-i', '@INPUT1@',
                           coverage,
                           '-e',
                           '-s', '@INPUT2@',
                           '-b', '@INPUT3@',
                           '@INPUT4@', '@OUTPUT0@'],
    build_by_default: true
)
