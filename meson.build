project('wlx', 'c',
  version: '0.0.1',
  license: 'GPL-2.0-only',
  default_options: [
    'c_std=c17',
    'warning_level=3',
  ],
)

c_args = [
  '-Wno-unused-parameter',
  '-D_POSIX_C_SOURCE=200809L',
]
add_project_arguments(c_args, language: 'c')

dbus_dep = dependency('dbus-1')
libevent_dep = dependency('libevent_core')
libinput_dep = dependency('libinput')
udev_dep = dependency('libudev')

conf = configuration_data()
# Not implemented yet
conf.set('WLX_STATIC_MODULES', get_option('static_modules'))
conf_h = configure_file(output: 'config.h', configuration: conf)

src = files([
  # TODO: Move backends into their own modules
  'backend-tty.c',
  'context.c',
  'notify.c',
  'session.c',
])

dep = [
  dbus_dep,
  libinput_dep,
  udev_dep,
]

# The wlx_* variables are considered "API" for using this as a subproject.

wlx_inc = include_directories('include')

wlx_lib = library('wlx', src, conf_h,
  dependencies: dep,
  include_directories: wlx_inc,
  install: true,
)
wlx_dep = declare_dependency(
  link_with: wlx_lib,
  include_directories: wlx_inc,
)

# Helper library for users using libevent

wlx_libevent_lib = library('wlx-libevent', 'libevent.c', conf_h,
  dependencies: [wlx_dep, libevent_dep],
  include_directories: wlx_inc,
  install: true,
)
wlx_libevent_dep = declare_dependency(
  link_with: wlx_libevent_lib,
  include_directories: wlx_inc,
)

executable('wlx_test', 'test.c',
  dependencies: [wlx_dep, wlx_libevent_dep, libevent_dep],
)
