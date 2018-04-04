project(
    'openvpn-plugin-auth-script',
    'c',
    default_options : ['c_std=c99']
)

library(
    'openvpn-plugin-auth-script',
    'openvpn-plugin-auth-script.c',
    name_prefix: '',
    c_args : [
        '-I/usr/include/openvpn', # Debian
        '-I/usr/local/include'    # FreeBSD
    ]
)
