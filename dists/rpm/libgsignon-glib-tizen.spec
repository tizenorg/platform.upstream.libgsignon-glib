#define dbus bus type to use [p2p, session, system]
%define dbus_type p2p

Name:       libgsignon-glib
Summary:    GLib API for the SSO framework
Version:    2.0.1
Release:    1
Group:      System/Libraries
License:    LGPL
Source:	    %{name}-%{version}.tar.gz
Requires: dbus-1
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  pkgconfig(check)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gobject-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  gobject-introspection

%description
%{summary}.


%package devel
Summary:    Development files for %{name}
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
%{summary}.


%prep
%setup -q -n %{name}-%{version}
if [ -f = "gtk-doc.make" ]
then
rm gtk-doc.make
fi
touch gtk-doc.make
autoreconf -f -i


%build
%configure --enable-dbus-type=%{dbus_type}
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
%make_install


%post -p /sbin/ldconfig


%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING ChangeLog INSTALL NEWS README
%{_libdir}/%{name}.so.*


%files devel
%defattr(-,root,root,-)
%{_includedir}/%{name}/*.h
%{_libdir}/%{name}.so
%{_libdir}/pkgconfig/%{name}.pc
%{_datadir}/gtk-doc/html/%{name}/*

