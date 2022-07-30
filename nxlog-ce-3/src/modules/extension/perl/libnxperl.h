#ifndef __NX_LIBNXPERL_H
#define __NX_LIBNXPERL_H


#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>


void nx_perl_initialize_library(pTHX_ nx_module_t *module);
void nx_perl_shutdown_library(pTHX_ nx_module_t *module);

typedef void (nx_perl_set_read_timer_func_t)(nx_module_t *module, int delay);

#endif /* __NX_LIBNXPERL_H */
