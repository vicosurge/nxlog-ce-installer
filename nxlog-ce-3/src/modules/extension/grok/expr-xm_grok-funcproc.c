/* Automatically generated from xm_grok-api.xml by codegen.pl */
#include "expr-xm_grok-funcproc.h"


/* FUNCTIONS */

// match_grok
const char *nx_expr_func__match_grok_string_argnames[] = {
    "pattern", 
};
nx_value_type_t nx_expr_func__match_grok_string_argtypes[] = {
    NX_VALUE_TYPE_STRING, 
};
// match_grok
const char *nx_expr_func__match_grok_string_string_argnames[] = {
    "field", "pattern", 
};
nx_value_type_t nx_expr_func__match_grok_string_string_argtypes[] = {
    NX_VALUE_TYPE_STRING, NX_VALUE_TYPE_STRING, 
};

nx_expr_func_t nx_api_declarations_xm_grok_funcs[] = {
 {
   { .next = NULL, .prev = NULL },
   NULL,
   "match_grok",
   NX_EXPR_FUNCPROC_TYPE_GLOBAL,
   nx_expr_func__match_grok,
   NX_VALUE_TYPE_BOOLEAN,
   1,
   nx_expr_func__match_grok_string_argnames,
   nx_expr_func__match_grok_string_argtypes,
 },
 {
   { .next = NULL, .prev = NULL },
   NULL,
   "match_grok",
   NX_EXPR_FUNCPROC_TYPE_GLOBAL,
   nx_expr_func__match_grok,
   NX_VALUE_TYPE_BOOLEAN,
   2,
   nx_expr_func__match_grok_string_string_argnames,
   nx_expr_func__match_grok_string_string_argtypes,
 },
};


/* PROCEDURES */

// match_grok
const char *nx_expr_proc__match_grok_string_argnames[] = {
    "pattern", 
};
nx_value_type_t nx_expr_proc__match_grok_string_argtypes[] = {
    NX_VALUE_TYPE_STRING, 
};
// match_grok
const char *nx_expr_proc__match_grok_string_string_argnames[] = {
    "field", "pattern", 
};
nx_value_type_t nx_expr_proc__match_grok_string_string_argtypes[] = {
    NX_VALUE_TYPE_STRING, NX_VALUE_TYPE_STRING, 
};

nx_expr_proc_t nx_api_declarations_xm_grok_procs[] = {
 {
   { .next = NULL, .prev = NULL },
   NULL,
   "match_grok",
   NX_EXPR_FUNCPROC_TYPE_GLOBAL,
   nx_expr_proc__match_grok,
   1,
   nx_expr_proc__match_grok_string_argnames,
   nx_expr_proc__match_grok_string_argtypes,
 },
 {
   { .next = NULL, .prev = NULL },
   NULL,
   "match_grok",
   NX_EXPR_FUNCPROC_TYPE_GLOBAL,
   nx_expr_proc__match_grok,
   2,
   nx_expr_proc__match_grok_string_string_argnames,
   nx_expr_proc__match_grok_string_string_argtypes,
 },
};

nx_module_exports_t nx_module_exports_xm_grok = {
	2,
	nx_api_declarations_xm_grok_funcs,
	2,
	nx_api_declarations_xm_grok_procs,
};
