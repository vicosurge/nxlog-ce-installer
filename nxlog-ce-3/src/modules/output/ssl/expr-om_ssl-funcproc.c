/* Automatically generated from om_ssl-api.xml by codegen.pl */
#include "expr-om_ssl-funcproc.h"


/* PROCEDURES */

// reconnect

nx_expr_proc_t nx_api_declarations_om_ssl_procs[] = {
 {
   { .next = NULL, .prev = NULL },
   NULL,
   "reconnect",
   NX_EXPR_FUNCPROC_TYPE_PRIVATE,
   nx_expr_proc__om_ssl_reconnect,
   0,
   NULL,
   NULL,
 },
};

nx_module_exports_t nx_module_exports_om_ssl = {
	0,
	NULL,
	1,
	nx_api_declarations_om_ssl_procs,
};
