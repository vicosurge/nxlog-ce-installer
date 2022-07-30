if HAVE_PERL
om_perl_LTLIBRARIES	= om_perl.la
om_perl_la_SOURCES	= om_perl.c om_perl.h
BUILT_SOURCES		= $(top_srcdir)/src/modules/extension/perl/ppport.h
om_perl_la_LDFLAGS	= -module -no-undefined -avoid-version
om_perl_la_LIBADD	= $(top_srcdir)/src/modules/extension/perl/libnxperl.la $(PERL_LIBS)
om_perl_la_CFLAGS	= $(PERL_CFLAGS) -I $(top_srcdir)/src/modules/extension/perl
om_perldir		= $(NX_MODULEDIR)/output
om_perl_la_DEPENDENCIES	= $(top_srcdir)/src/modules/extension/perl/libnxperl.la

$(top_srcdir)/src/modules/extension/perl/ppport.h:
	cd $(top_srcdir)/src/modules/extension/perl && $(MAKE)

$(top_srcdir)/src/modules/extension/perl/libnxperl.la:
	cd $(top_srcdir)/src/modules/extension/perl && $(MAKE)

endif
MAINTAINERCLEANFILES	+= $(om_perl_la_BUILTSOURCES)
