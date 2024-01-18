project('backend', 'cpp',
  version : '0.1',
  default_options : ['warning_level=3',
                     'cpp_std=c++20'])
  subdir('trezor-crypto')
http=dependency('cpp-httplib')


exe = executable('backend', 
['backend.cpp',
  'src/crypto/verushash/verushash.cpp',
  'src/crypto/verushash/verus_clhash_port.cpp',
  'src/general/hex.cpp',
  src_trezorcrypto,
  ],
  dependencies: http,
  include_directories: ['src', include_trezorcrypto],
  install : true)

test('basic', exe)
