if HAVE_SYSTEMD

im_systemd_LTLIBRARIES	= im_systemd.la
im_systemd_la_SOURCES	= im_systemd.c im_systemd_record.c
im_systemd_la_LDFLAGS	= -module -no-undefined -avoid-version
im_systemd_la_LIBADD     = -lsystemd
im_systemddir		= $(NX_MODULEDIR)/input
dist_pkgdata_DATA	= im_systemd-fields.xml

endif
