Summary: TACACS+ Daemon
Name: tacacs+
Group: Networking/Servers
Version: F4.0.4.28
Release: 2.el7
License: Cisco

Packager: paihu
Vendor: Cisco

Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: gcc, bison, flex, m4, pam-devel, tcp_wrappers, tcp_wrappers-devel
Requires: pam, tcp_wrappers

%description

%prep
%setup

%build
%configure --enable-acls --enable-uenable
%{__make}

%install
%{__rm} -rf %{buildroot}
%makeinstall
%{__install} -Dp -m0644 tac_plus.sysconfig %{buildroot}etc/sysconfig/tac_plus
%{__install} -Dp -m0644 tac_plus.service %{buildroot}usr/lib/systemd/system/tac_plus.service
%{__install} -Dp -m0640 tacacs.xml %{buildroot}usr/lib/firewalld/services/tacacs.xml
### Clean up buildroot
%{__rm} -f %{buildroot}%{_infodir}/dir

%post

%preun

%clean
%{__rm} -rf %{buildroot}

%files

/usr/include/tacacs.h
/usr/bin/tac_pwd
/usr/bin/tac_plus
/usr/share/tacacs+/users_guide
/usr/share/tacacs+/tac_convert
/usr/share/tacacs+/do_auth.py
/usr/share/man/man5/tac_plus.conf.5.gz
/usr/share/man/man8/tac_pwd.8.gz
/usr/share/man/man8/tac_plus.8.gz
%{_libdir}/libtacacs.so.1.0.0
%{_libdir}/libtacacs.so.1
%{_libdir}/libtacacs.so
%{_libdir}/libtacacs.a
%{_libdir}/libtacacs.la
/etc/sysconfig/tac_plus
/usr/lib/systemd/system/tac_plus.service
/usr/lib/firewalld/services/tacacs.xml
%changelog
