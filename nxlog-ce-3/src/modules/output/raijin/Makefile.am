om_raijin_LTLIBRARIES	= om_raijin.la
om_raijin_la_SOURCES	= om_raijin.c om_raijin.h
om_raijin_la_LDFLAGS	= -module -no-undefined -avoid-version
om_raijin_la_LIBADD	= $(LIBNX) $(top_builddir)/src/common/libnxssl.la \
			  $(top_srcdir)/src/modules/extension/json/libjson.la

om_raijin_la_DEPENDENCIES	= $(top_srcdir)/src/modules/extension/json/libjson.la

om_raijindir		= $(NX_MODULEDIR)/output

$(top_srcdir)/src/modules/extension/json/libjson.la:
	cd $(top_srcdir)/src/modules/extension/json && $(MAKE)