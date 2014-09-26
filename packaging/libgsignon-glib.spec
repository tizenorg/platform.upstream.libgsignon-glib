#define dbus bus type to use [p2p, session, system]
%define dbus_type p2p

Name:       libgsignon-glib
Summary:    SSO framework: GLib API 
Version:    2.3.0
Release:    0
Group:      Security/Accounts
License:    LGPL-2.1
Source:     %{name}-%{version}.tar.gz
Source1:    %{name}.manifest
URL:        https://01.org/gsso
Requires:         dbus-1
Requires:         gsignon
Requires:         gsignond-plugin-oauth
Requires:         gsignond-plugin-sasl
Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:    pkgconfig
BuildRequires:    pkgconfig(check)
BuildRequires:    pkgconfig(glib-2.0)
BuildRequires:    pkgconfig(gobject-2.0)
BuildRequires:    pkgconfig(gio-2.0)

%description
GLib API for the SSO framework.


%package devel
Summary:    Dev files for %{name}
Group:      SDK/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Development files for %{name}.


%package doc
Summary:    Doc files for %{name}
Group:      SDK/Documentation
Requires:   %{name}-devel = %{version}-%{release}

%description doc
Documentation files for %{name}.


%prep
%setup -q -n %{name}-%{version}
cp %{SOURCE1} .


%build
%reconfigure --enable-dbus-type=%{dbus_type}
%__make %{?_smp_mflags}


%install
rm -rf %{buildroot}
%make_install


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%manifest %{name}.manifest
%doc AUTHORS ChangeLog NEWS README
%license COPYING
%{_libdir}/%{name}.so.*


%files devel
%defattr(-,root,root,-)
%manifest %{name}.manifest
%{_includedir}/%{name}/*.h
%{_libdir}/%{name}.so
%{_libdir}/pkgconfig/%{name}.pc
%{_bindir}/gsso-example


%files doc
%defattr(-,root,root,-)
%{_datadir}/gtk-doc/html/%{name}/*