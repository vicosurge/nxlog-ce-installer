if HAVE_PYTHON

im_python_LTLIBRARIES	= im_python.la
im_python_la_SOURCES	= im_python.c im_python.h
im_python_la_LDFLAGS	= -module -no-undefined -avoid-version
im_python_la_LIBADD	= $(top_builddir)/src/modules/extension/python/libnxpython.la
im_python_la_CFLAGS	= $(PYTHON_CFLAGS)
im_python_la_DEPENDENCIES   = $(top_builddir)/src/modules/extension/python/libnxpython.la
im_pythondir		= $(NX_MODULEDIR)/input

$(top_builddir)/src/modules/extension/python/libnxpython.la:
	cd $(top_builddir)/src/modules/extension/python && $(MAKE)

endif
