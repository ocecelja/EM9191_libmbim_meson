##############################################################################
# Project
project('lm_em919x', ['cpp', 'c'],
  version: '0.1.0',
  license: 'TBD',
  meson_version: '>=0.54.0',
  default_options: [
    'cpp_std=c++17',
  ])

##############################################################################
# Versioning, project and libraries

# There are so many versioning schemes, each of which is incompatible with
# others. We'll manage best by keeping things simple:
#
# - The package version follows semver
# - The library version is the package version
# - The ABI version, i.e. the compatibility we expect, is the major
#   component of the package
_splitver = meson.project_version().split('.')
PACKAGE_MAJOR = _splitver[0]
PACKAGE_MINOR = _splitver[1]
PACKAGE_PATCH = _splitver[2]

ABI_VERSION = PACKAGE_MAJOR
LIB_VERSION = meson.project_version()
PACKAGE_VERSION = meson.project_version()

##############################################################################
# Configuration

conf_data = configuration_data()

cpp_compiler = meson.get_compiler('cpp')
c_compiler = meson.get_compiler('c')

### Version and package information
conf_data.set_quoted('LM_EM919X_PACKAGE_MAJOR', PACKAGE_MAJOR)
conf_data.set_quoted('LM_EM919X_PACKAGE_MINOR', PACKAGE_MINOR)
conf_data.set_quoted('LM_EM919X_PACKAGE_PATCH', PACKAGE_PATCH)
conf_data.set_quoted('LM_EM919X_PACKAGE_VERSION', PACKAGE_VERSION)
conf_data.set_quoted('LM_EM919X_ABI_VERSION', ABI_VERSION)
conf_data.set_quoted('LM_EM919X_LIB_VERSION', LIB_VERSION)

conf_data.set_quoted('LM_EM919X_PACKAGE_NAME', meson.project_name())
conf_data.set_quoted('LM_EM919X_PACKAGE_URL', 'https://github.com/AnyWi/shared_library_EM919x')


source_base = meson.current_source_dir()

##############################################################################
# Link manager (library, headers)
linkmanager_prefix = get_option('linkmanager_prefix')
linkmanager_libdir = join_paths(linkmanager_prefix, get_option('libdir'))
linkmanager_includes = join_paths(linkmanager_prefix, get_option('includedir'))
message(linkmanager_includes)
message(linkmanager_libdir)

linkmanager_lib = cpp_compiler.find_library('linkmanager',
  dirs: [
    linkmanager_libdir,
    join_paths(source_base, linkmanager_libdir),
  ]
)

header = 'linkmanager' / 'api' / 'modules.h'
has_modules_header = cpp_compiler.has_header(header,
  include_directories: [
    include_directories(linkmanager_includes),
  ],
  required: false,
)
if has_modules_header
  linkmanager_includes = include_directories(linkmanager_includes)
else
  tmp = join_paths(source_base, linkmanager_includes) 
  has_modules_header = cpp_compiler.has_header(header,
    include_directories: [include_directories(tmp)],
  )
  linkmanager_includes = include_directories(tmp)
endif

linkmanager_dep = declare_dependency(
  include_directories: [
    linkmanager_includes,
  ],
  dependencies: [
    linkmanager_lib,
  ]
)

##############################################################################
# Other dependencies
json = subproject('nlohmann_json')

##############################################################################
# Common library (static)

common_lib = static_library('common',
  [
    'shared_example' / 'common' / 'dev_util.c',
    'shared_example' / 'common' / 'ping.c',
    'shared_example' / 'common' / 'switype_256bit.c',
    'shared_example' / 'common' / 'displaysettings.c',
    'shared_example' / 'common' / 'proc_util.c',
    'shared_example' / 'common' / 'sysinfo.c',
    'shared_example' / 'common' / 'netlink_util.c',
    'shared_example' / 'common' / 'str_util.c',
  ],
  install: false,
)
common_dep = declare_dependency(
  include_directories: [
    'shared_example' / 'common'
  ],
  link_with: common_lib,
)

##############################################################################
# Lite-MBIM library (static, pre-compiled)

litembim_lib = c_compiler.find_library('lite-mbim',
  dirs: [ join_paths(source_base, 'shared_example' / 'lite-mbim' ) ]
)
litembim_dep = declare_dependency(
  include_directories: [
    'shared_example' / 'lite-mbim'
  ],
  dependencies: [
    litembim_lib,
  ]
)

##############################################################################
# Plugin

plugin = shared_module('lm_em919x',
  [
    'shared_example' / 'plugin.cpp',
  ],
  dependencies: [
    common_dep,
    litembim_dep,
    linkmanager_dep,
    json.get_variable('nlohmann_json_dep'),
  ],
)
