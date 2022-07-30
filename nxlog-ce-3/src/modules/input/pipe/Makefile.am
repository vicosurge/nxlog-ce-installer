if BUILD_IM_PIPE

im_pipe_LTLIBRARIES	= im_pipe.la
im_pipe_la_SOURCES	= im_pipe.c
im_pipe_la_LDFLAGS	= -module -no-undefined -avoid-version
im_pipe_la_LIBADD	= $(LIBNX) $(top_builddir)/src/common/libnx_la-fileperms.lo
im_pipedir		= $(NX_MODULEDIR)/input

endif