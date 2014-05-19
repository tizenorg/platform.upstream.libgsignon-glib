## Process this file with automake to produce Makefile.in

bin_PROGRAMS = gsso-example

gsso_example_SOURCES = gsso-example.c
gsso_example_CPPFLAGS = \
	-I$(top_srcdir) \
	$(DEPS_CFLAGS)
gsso_example_LDADD = \
	$(DEPS_LIBS) \
	$(top_builddir)/libgsignon-glib/libgsignon-glib.la
