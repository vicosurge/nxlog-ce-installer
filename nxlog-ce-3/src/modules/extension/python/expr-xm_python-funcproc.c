/* Automatically generated from ./xm_python-api.xml by codegen.pl */
#include "expr-xm_python-funcproc.h"


/* PROCEDURES */

// call
const char *nx_expr_proc__xm_python_call_string_argnames[] = {
    "subroutine", 
};
nx_value_type_t nx_expr_proc__xm_python_call_string_argtypes[] = {
    NX_VALUE_TYPE_STRING, 
};
// python_call
const char *nx_expr_proc__xm_python_python_call_string_argnames[] = {
    "function", 
};
nx_value_type_t nx_expr_proc__xm_python_python_call_string_argtypes[] = {
    NX_VALUE_TYPE_STRING, 
};

nx_expr_proc_t nx_api_declarations_xm_python_procs[] = {
 {
   { .next = NULL, .prev = NULL },
   NULL,
   "call",
   NX_EXPR_FUNCPROC_TYPE_PUBLIC,
   nx_expr_proc__xm_python_call,
   1,
   nx_expr_proc__xm_python_call_string_argnames,
   nx_expr_proc__xm_python_call_string_argtypes,
 },
 {
   { .next = NULL, .prev = NULL },
   NULL,
   "python_call",
   NX_EXPR_FUNCPROC_TYPE_GLOBAL,
   nx_expr_proc__xm_python_python_call,
   1,
   nx_expr_proc__xm_python_python_call_string_argnames,
   nx_expr_proc__xm_python_python_call_string_argtypes,
 },
};

nx_module_exports_t nx_module_exports_xm_python = {
	0,
	NULL,
	2,
	nx_api_declarations_xm_python_procs,
};
