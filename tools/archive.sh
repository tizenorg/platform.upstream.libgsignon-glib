#!/bin/sh
#
git archive --format=tar --prefix=libgsignon-glib-2.0.0/ -o ../libgsignon-glib-2.0.0.tar master
bzip2 ../libgsignon-glib-2.0.0.tar
mv ../libgsignon-glib-2.0.0.tar.bz2 ~/rpmbuild/SOURCES/

