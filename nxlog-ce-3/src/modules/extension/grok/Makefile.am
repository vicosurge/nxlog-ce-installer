xm_grok_LTLIBRARIES     = xm_grok.la
xm_grok_la_SOURCES	= xm_grok.c xm_grok.h grok.c grok.h xm_grok_funcproc_cb.c $(xm_grok_la_BUILTSOURCES)
xm_grok_la_LDFLAGS	= -module -no-undefined -avoid-version
xm_grokdir		= $(NX_MODULEDIR)/extension
xm_grok_la_LIBADD	= $(LIBNX) $(PCRE_LIBS) $(top_builddir)/src/common/libnx_la-filepath.lo
xm_grok_CFLAGS		= $(PCRE_CFLAGS)

xm_grok_la_BUILTSOURCES		= expr-xm_grok-funcproc.c expr-xm_grok-funcproc.h
expr-xm_grok-funcproc.c: $(top_builddir)/src/utils/codegen.pl xm_grok-api.xml
	-$(top_builddir)/src/utils/codegen.pl xm_grok-api.xml
expr-xm_grok-funcproc.h: $(top_builddir)/src/utils/codegen.pl xm_grok-api.xml
	-$(top_builddir)/src/utils/codegen.pl xm_grok-api.xml

EXTRA_DIST		= xm_grok-api.xml $(xm_grok_la_BUILTSOURCES)
MAINTAINERCLEANFILES	+= $(xm_grok_la_BUILTSOURCES)
