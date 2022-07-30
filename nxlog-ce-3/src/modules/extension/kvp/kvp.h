/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#ifndef __NX_KVP_H
#define __NX_KVP_H

#include "../../../common/types.h"
#include "../../../common/logdata.h"
#include "../../../common/module.h"

#define NX_KVP_MAX_FIELDS 150

typedef enum nx_kvp_quote_method_t
{
    NX_KVP_QUOTE_METHOD_ALL = 1,
    NX_KVP_QUOTE_METHOD_DELIMITER,
    NX_KVP_QUOTE_METHOD_NONE,
} nx_kvp_quote_method_t;

typedef struct nx_kvp_ctx_t
{
    char kvdelimiter;
    char kvpdelimiter;
    char keyquotechar;
    char valquotechar;
    char escapechar;
    nx_kvp_quote_method_t quote_method;
    boolean escape_control;
    boolean detectnumericvalues;
    boolean include_hidden_fields;
} nx_kvp_ctx_t;

void nx_kvp_ctx_init(nx_kvp_ctx_t *ctx);
void nx_kvp_parse(nx_logdata_t *logdata,
		  nx_kvp_ctx_t *ctx,
		  const char *src,
		  size_t srclen,
		  const char *prefix);
nx_string_t *nx_logdata_to_kvp(nx_kvp_ctx_t *ctx, nx_logdata_t *logdata);
void nx_kvp_ctx_set_fields(nx_kvp_ctx_t *ctx, char *fields);
void nx_kvp_ctx_set_types(nx_kvp_ctx_t *ctx, char *types);

#endif /* __NX_KVP_H */
