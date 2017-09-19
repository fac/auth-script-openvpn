%global _hardened_build 1

%global commit 8433ee25891a2ba40558e254fb2ae23cf05df8c4
%global shortcommit %(c=%{commit}; echo ${c:0:7})

Name:           openvpn-plugin-auth-script
Version:        0.0.0 
Release:        0.1%{?dist}
Summary:        OpenVPN plugin to auth connections using non-blocking external script

License:        ASL 2.0
URL:            https://github.com/fkooman/auth-script-openvpn
Source0:        https://github.com/fkooman/auth-script-openvpn/archive/%{commit}/%{name}-%{shortcommit}.tar.gz

BuildRequires:  openvpn-devel
Requires:       openvpn

%description
Runs an external script to decide whether to authenticate a user or not. 
Useful for checking 2FA on VPN auth attempts as it doesn't block the main 
openvpn process, unlike passing the script to --auth-user-pass-verify flag.

The idea of the plugin is to do as little as possible, and let the external 
binary do all the heavy lifting itself.

%prep
%autosetup -n auth-script-openvpn-%{commit}

%build
CFLAGS="%{optflags}" %make_build

%install
mkdir -p %{buildroot}%{_libdir}/openvpn/plugins
cp auth_script.so %{buildroot}%{_libdir}/openvpn/plugins

%files
%license LICENSE
%doc README.md
%{_libdir}/openvpn/plugins

%changelog
* Tue Sep 19 2017 François Kooman <fkooman@tuxed.net> - 0.0.0-0.1
- initial package
