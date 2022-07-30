if HAVE_PERL
im_perl_LTLIBRARIES	= im_perl.la
im_perl_la_SOURCES	= im_perl.c im_perl.h
BUILT_SOURCES		= $(top_srcdir)/src/modules/extension/perl/ppport.h
im_perl_la_LDFLAGS	= -module -no-undefined -avoid-version
im_perl_la_LIBADD	= $(top_srcdir)/src/modules/extension/perl/libnxperl.la $(PERL_LIBS)
im_perl_la_CFLAGS	= $(PERL_CFLAGS) -I $(top_srcdir)/src/modules/extension/perl
im_perldir		= $(NX_MODULEDIR)/input
im_perl_la_DEPENDENCIES	= $(top_srcdir)/src/modules/extension/perl/libnxperl.la

$(top_srcdir)/src/modules/extension/perl/ppport.h:
	cd $(top_srcdir)/src/modules/extension/perl && $(MAKE)

$(top_srcdir)/src/modules/extension/perl/libnxperl.la:
	cd $(top_srcdir)/src/modules/extension/perl && $(MAKE)

endif
MAINTAINERCLEANFILES	+= $(im_perl_la_BUILTSOURCES)
