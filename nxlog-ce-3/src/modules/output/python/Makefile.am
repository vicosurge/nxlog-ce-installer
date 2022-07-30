if HAVE_PYTHON

om_python_LTLIBRARIES	  = om_python.la
om_python_la_SOURCES	  = om_python.c om_python.h
om_python_la_LDFLAGS	  = -module -no-undefined -avoid-version
om_python_la_LIBADD	  = $(top_builddir)/src/modules/extension/python/libnxpython.la
om_python_la_CFLAGS	  = $(PYTHON_CFLAGS) -I$(top_srcdir)/src/modules/extension/python
om_python_la_DEPENDENCIES = $(top_builddir)/src/modules/extension/python/libnxpython.la
om_pythondir		  = $(NX_MODULEDIR)/output

$(top_builddir)/src/modules/extension/python/libnxpython.la:
	cd $(top_builddir)/src/modules/extension/python && $(MAKE)


endif
