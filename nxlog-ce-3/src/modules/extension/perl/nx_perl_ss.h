#ifndef NX_PERL_SS_H
#define NX_PERL_SS_H


#include "../../../common/types.h"
#include <EXTERN.h>
#include <perl.h>

void nx_perl_ss_begin();
void nx_perl_ss_end();

void nx_perl_global_init();
void nx_perl_global_shutdown();

typedef struct nx_perl_config_t
{
    char * perlcode;
    char * run;
    PerlInterpreter *perl_interpreter;
    nx_event_t *event;

} nx_perl_config_t;

void nx_perl_config(nx_module_t *module, const char *default_fun_name);
void nx_perl_module_init(nx_module_t * module);
void nx_perl_module_shutdown(nx_module_t * module);

#endif // NX_PERL_SS_H
