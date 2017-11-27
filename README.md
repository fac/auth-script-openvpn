# OpenVPN Auth Script Plugin

Runs an external script to decide whether to authenticate a user or not. Useful for checking 2FA on VPN auth attempts as it doesn't block the main openvpn process, unlike passing the script to `--auth-user-pass-verify` flag.

The idea of the plugin is to do as little as possible, and let the external binary do all the heavy lifting itself.

## Installation

Compile the shared library with `make plugin` and copy `auth_script.so` into your `lib/openvpn/plugins/` folder.

Copy your external script onto the machine in a sane place, making sure it's executable by the user openvpn is running as.

Configure the plugin in your openvpn config, passing the path to the external script as the second argument:

    plugin /path/to/auth_script.so /path/to/external/script.sh

If your script needs aditional arguments you can put them after script path and they will get passed to the script:

    plugin /path/to/auth_script.so /path/to/external/script.sh arg1 arg2

## External Script requirements

The script used to handle authentication has a very specific set of skills it needs, and if you don't provide those it will hunt you down in silence.

It needs to:

* Be executable by the user openvpn runs as
* Read `username` and `password` from the `ENV` to check them
* Read `auth_control_file` from the `ENV` and write a single character to that path to signify auth success/failure
    * To **allow** authentication, write `1` to the file
    * To **block** authentication, write `0` to the file
* Exit with status code 0
* Not depend on `PATH` variable (eg, don't use `/usr/bin/env` in shebang)

Example env the script is called in:

    PWD=/
    SHLVL=0
    auth_control_file=/tmp/openvpn_acf_9090e6750844ee26d7f23efbad0e95c2.tmp
    config=/opt/local/etc/openvpn/testvpn.conf
    daemon=1
    daemon_log_redirect=0
    daemon_pid=10502
    daemon_start_time=1488892554
    dev=tun0
    dev_type=tun
    ifconfig_local=192.168.2.1
    ifconfig_remote=192.168.2.2
    link_mtu=1572
    local_port_1=1194
    password=b
    proto_1=tcp-server
    redirect_gateway=0
    remote_port_1=1194
    route_gateway_1=192.168.2.2
    route_netmask_1=255.255.255.0
    route_network_1=192.168.2.0
    route_vpn_gateway=192.168.2.2
    script_context=init
    tun_mtu=1500
    untrusted_ip=192.168.3.4
    untrusted_port=54357
    username=a
    verb=9

### Static Challenge

If you're using `static-challenge`, you might wonder where the response value is in the env hash. See the OpenVPN management-notes docs for more info, but it's passed as part of the password.

The format in the env password value is `SCRV1:<BASE64_PASSWORD>:<BASE64_RESPONSE>`

## License

See LICENSE.
