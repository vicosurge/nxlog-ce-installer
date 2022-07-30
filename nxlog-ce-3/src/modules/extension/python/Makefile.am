if HAVE_PYTHON

# Python C-library
xm_python_lib_LTLIBRARIES   = libpynxlog.la
libpynxlog_la_SOURCES	    = xm_python_lib.c
libpynxlog_la_CFLAGS	    = $(PYTHON_CFLAGS)

libpynxlog_la_LDFLAGS	    = -module -no-undefined -avoid-version
libpynxlog_la_LIBADD	    = $(LIBNX) $(PYTHON_LIBS)

if WIN32
.libs/libpynxlog.pyd: libpynxlog.la
	   -rm -f .libs/libpynxlog.pyd & cp .libs/libpynxlog.dll .libs/libpynxlog.pyd

endif
xm_python_libdir	    = $(NX_MODULEDIR)/extension/python

#Shared NXlog lib
noinst_LTLIBRARIES	= libnxpython.la
libnxpython_la_SOURCES	= libnxpython.c libnxpython.h
#-DPYMODULEP_DIR=\"$(NX_MODULEDIR)/extension/python\"
libnxpython_la_CFLAGS	= $(PYTHON_CFLAGS) \
			  -DPYMODULE_DIR=\"$(NX_MODULEDIR)/extension/python\" \
			  -DPYTESTMOD_DIR=\"../src/modules/extension/python/.libs\" \
			  -DPYTESTMODP_DIR=\"../src/modules/extension/python\"

libnxpython_la_LIBADD	  = $(LIBNX) $(PYTHON_LIBS)
#libnxpythondir           = $(NX_MODULEDIR)/extension/python

xm_python_LTLIBRARIES	    = xm_python.la
xm_python_la_BUILTSOURCES   = expr-xm_python-funcproc.c expr-xm_python-funcproc.h
xm_python_la_SOURCES	    = xm_python.c xm_python.h xm_python_funcproc_cb.c \
			      $(xm_python_la_BUILTSOURCES) xm_python-api.xml
xm_python_la_LDFLAGS	    = -module -no-undefined -avoid-version
xm_python_la_LIBADD	    = $(LIBNX) libnxpython.la
xm_python_la_CFLAGS	    = $(PYTHON_CFLAGS)
xm_python_la_DEPENDENCIES   = libnxpython.la
xm_pythondir		    = $(NX_MODULEDIR)/extension

EXTRA_DIST		= xm_python-api.xml $(xm_python_la_BUILTSOURCES)
MAINTAINERCLEANFILES	+= $(xm_python_la_BUILTSOURCES)

dist_pynxlog_DATA = nxlog/__init__.py
pynxlogdir = $(NX_MODULEDIR)/extension/python/nxlog

if WIN32
pydwin_DATA = .libs/libpynxlog.pyd
pydwindir= $(NX_MODULEDIR)/extension/python
endif


endif

expr-xm_python-funcproc.c expr-xm_python-funcproc.h &: $(top_srcdir)/src/utils/codegen.pl xm_python-api.xml
	-$(top_srcdir)/src/utils/codegen.pl $(srcdir)/xm_python-api.xml

