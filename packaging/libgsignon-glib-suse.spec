#define dbus bus type to use [p2p, session, system]
%define dbus_type session

Name:       libgsignon-glib
Summary:    GLib API for the SSO framework
Version:    2.0.0
Release:    1
Group:      System/Libraries
License:    LGPL
Source:	    %{name}-%{version}.tar.gz
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  pkgconfig(gtk-doc)
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
gtkdocize
autoreconf -f -i


%build
%configure \
	--enable-gtk-doc \
	--enable-gtk-doc-html \
	--enable-python \
	--enable-dbus-type=%{dbus_type}
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
%{_libdir}/%{name}.la
%{_libdir}/pkgconfig/%{name}.pc
%{_libdir}/girepository-1.0/gSignon-1.0.typelib
%{_datadir}/gir-1.0/gSignon-1.0.gir
#%{_datadir}/vala/vapi/gsignon.vapi
%{_datadir}/gtk-doc/html/%{name}/*


%changelog
* Mon Feb 11 2013 Jussi Laako <jussi.laako@linux.intel.com> - 2.0
- Refresh for the libgsignon-glib

