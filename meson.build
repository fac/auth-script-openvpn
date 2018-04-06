project(
    'openvpn-plugin-auth-script',
    'c',
    default_options : ['c_std=c99']
)
add_project_arguments('-D_POSIX_C_SOURCE=200809L', language: 'c')

library(
    'openvpn-plugin-auth-script',
    'openvpn-plugin-auth-script.c',
    name_prefix: '',
    c_args : [
        '-I/usr/include/openvpn',      # Debian
        '-I/usr/local/include',        # FreeBSD
        '-I/usr/local/include/openvpn' # OpenBSD
    ]
)
