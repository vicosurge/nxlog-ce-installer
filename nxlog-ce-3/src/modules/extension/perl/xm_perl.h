/*
 * This file is part of the nxlog log collector tool.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 * License:
 * Copyright (C) 2012 by Botond Botyanszki
 * This library is free software; you can redistribute it and/or modify
 * it under the same terms as Perl itself, either Perl version 5.8.5 or,
 * at your option, any later version of Perl 5 you may have available.
 */

#ifndef __NX_XM_PERL_H
#define __NX_XM_PERL_H

#define USE_ITHREADS

#include "libnxperl.h"

#include "../../../common/types.h"
#include <EXTERN.h>
#include <perl.h>

// mingw hack (experimental)
#if defined(PERL_IMPLICIT_SYS) && defined(__MINGW32__)
# undef longjmp
# undef setjmp
#  ifdef _WIN64
#   define setjmp(BUF) _setjmp((BUF), __builtin_frame_address (0))
#  else
#   define setjmp(BUF) _setjmp3((BUF), NULL)
#  endif
#endif

#endif	/* __NX_XM_PERL_H */
