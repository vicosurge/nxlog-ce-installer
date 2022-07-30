/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#include <apr_lib.h>
#include <stdlib.h>
#include <stdio.h>

#include "error_debug.h"
#include "exception.h"
#include "str.h"
#include "alloc.h"

#define NX_LOGMODULE NX_LOGMODULE_CORE

static uint32_t _string_limit = NX_STRING_DEFAULT_LIMIT;

#define nx_string_size_error(ex_throw, len, limit) \
    if(ex_throw){throw_msg("oversized string (%u), limit is %u bytes", len, limit);}\
    else{log_warn("truncating oversized string (%u) to StringLimit (%u)", len, limit);}

void nx_string_set_limit(uint32_t limit)
{
    if ( (limit > 512) && (limit < 1024*1024*1024) )
    {
	_string_limit = limit;
    }
    else
    {
	throw_msg("bogous string limit: %u", limit);
    }
}



uint32_t nx_string_get_limit()
{
    return ( _string_limit );
}



/*
 * Frees only dynamic part of the string, not itself
 */
void nx_string_kill(nx_string_t *string)
{
    ASSERT(string != NULL);
    
    if ( string->flags & NX_STRING_FLAG_CONST )
    {
	return;
    }
    if ( string->buf != NULL )
    {
	free(string->buf);
	string->buf = NULL;
    }
}



/*
 * Free the whole structure including dynamic parts
 */
void nx_string_free(nx_string_t *string)
{
    ASSERT(string != NULL);

    nx_string_kill(string);
    free(string);
}



nx_string_t *nx_string_new()
{
    nx_string_t *retval;

    retval = malloc(sizeof(nx_string_t));
    retval->buf = malloc(NX_STRING_DEFAULT_SIZE);
    *(retval->buf) = '\0';
    retval->bufsize = NX_STRING_DEFAULT_SIZE;
    retval->len = 0;
    retval->flags = 0;

    return ( retval );
}



static nx_string_t *_nx_string_new_size(size_t len, boolean ex_throw)
{
    nx_string_t *retval;

    if ( len == 0 )
    {
	return ( nx_string_new() );
    }

    if ( len > _string_limit )
    {
	nx_string_size_error(ex_throw, len, _string_limit);
	len = _string_limit;
    }

    retval = malloc(sizeof(nx_string_t));
    retval->buf = malloc(len);
    *(retval->buf) = '\0';
    retval->bufsize = (uint32_t) len;
    retval->len = 0;
    retval->flags = 0;

    return ( retval );
}

nx_string_t *nx_string_new_size(size_t len)
{
    return _nx_string_new_size(len, FALSE);
}

nx_string_t *nx_string_new_size_throw(size_t len)
{
    return _nx_string_new_size(len, TRUE);
}


static nx_string_t *_nx_string_create(const char *src, int len, boolean ex_throw)
{
    nx_string_t *retval;

    ASSERT(src != NULL);

    if ( len < 0 )
    {
	len = (int) strlen(src);
    }
    if ( len > (int) _string_limit )
    {
	nx_string_size_error(ex_throw, (size_t)len, _string_limit);
	len = (int)_string_limit;
    }

    retval = malloc(sizeof(nx_string_t));
    ASSERT(retval);
    retval->buf = malloc((size_t) len + 1);
    ASSERT(retval->buf);
    retval->bufsize = (uint32_t) len + 1;
    retval->len = (uint32_t) len;
    retval->flags = 0;
    memcpy(retval->buf, src, (size_t) len);
    retval->buf[len] = '\0';

    return ( retval );
}


nx_string_t *nx_string_create(const char *src, int len)
{
    return _nx_string_create(src, len, FALSE);
}


nx_string_t *nx_string_create_throw(const char *src, int len)
{
    return _nx_string_create(src, len, TRUE);
}


static nx_string_t *_nx_string_create_owned(char *src, int len, boolean ex_throw)
{
    nx_string_t *retval;

    ASSERT(src != NULL);

    if ( len < 0 )
    {
	len = (int) strlen(src);
    }
    if ( len > (int) _string_limit )
    {
	nx_string_size_error(ex_throw, (size_t)len, _string_limit);
	len = (int)_string_limit;
    }

    retval = malloc(sizeof(nx_string_t));
    retval->buf = src;
    retval->bufsize = (uint32_t) len + 1;
    retval->len = (uint32_t) len;
    retval->flags = 0;

    return ( retval );
}



nx_string_t *nx_string_create_owned(char *src, int len)
{
    return _nx_string_create_owned(src, len, FALSE);
}



nx_string_t *nx_string_create_owned_throw(char *src, int len)
{
    return _nx_string_create_owned(src, len, TRUE);
}



nx_string_t *nx_string_init_const(nx_string_t *dst, const char *src)
{
    ASSERT(dst != NULL);
    ASSERT(src != NULL);

    dst->buf = (char *)src;
    dst->len = (uint32_t) strlen(src);
    dst->bufsize = 0;
    dst->flags = NX_STRING_FLAG_CONST;

    return ( dst );
}



static void ensure_size(nx_string_t *dst, size_t len, boolean ex_throw)
{
    apr_size_t newsize;
    
    if ( dst->bufsize > len )
    {
	return;
    }

    if ( len > _string_limit )
    {
	nx_string_size_error(ex_throw, len, _string_limit);
	len = _string_limit;
    }

    if ( dst->bufsize < 1024 )
    {
	newsize = dst->bufsize * 2;
    }
    else
    {
	newsize = (dst->bufsize * 3) / 2;
	if ( newsize > _string_limit )
	{
	    newsize = _string_limit;
	}
    }
    if ( newsize <= len )
    {
	newsize = len;
    }

    ASSERT(dst->buf != NULL);

    dst->buf = realloc(dst->buf, dst->bufsize + len);
    ASSERT(dst->buf != NULL);
    dst->bufsize += (uint32_t) len;
}



static void _nx_string_ensure_size(nx_string_t *str, size_t len, boolean ex_throw)
{
    ASSERT(str != NULL);
    ASSERT(len > 0);

    ensure_size(str, len, ex_throw);
}


void nx_string_ensure_size(nx_string_t *str, size_t len)
{
    _nx_string_ensure_size(str, len, FALSE);
}


void nx_string_ensure_size_throw(nx_string_t *str, size_t len)
{
    _nx_string_ensure_size(str, len, TRUE);
}



static void set_len(nx_string_t *dst, size_t len, boolean ex_throw)
{
    if ( (dst->bufsize > 1024) && (dst->bufsize > len) )
    {
	if (len >= _string_limit)
	{
	    nx_string_size_error(ex_throw, len, _string_limit);
	    len = _string_limit;
	}
	free(dst->buf);
	dst->buf = malloc(len);
	ASSERT(dst->buf);
	dst->bufsize = (uint32_t) len;
	dst->flags = 0;
	dst->len = 0;
	dst->buf[dst->len] = '\0';
    }
    else if ( dst->bufsize <= len )
    {
	ensure_size(dst, len, ex_throw);
    }
}



/*
 * srclen is -1 to calculate with strlen
 * dst must be initialized
 */

static nx_string_t *_nx_string_append(nx_string_t *dst, const char *src, int srclen, boolean ex_throw)
{
    ASSERT(dst != NULL);
    ASSERT(src != NULL);
    ASSERT(!(dst->flags & NX_STRING_FLAG_CONST));

    if ( srclen < 0 )
    {
	srclen = (int) strlen(src);
    }
    else if ( srclen == 0 )
    {
	return ( dst );
    }

    ensure_size(dst, dst->len + (size_t) srclen + 1, ex_throw);

    // calculate new sizes
    if (dst->len + (uint32_t) srclen >= dst->bufsize)
	{
	srclen = (int)(dst->bufsize - dst->len - 1);
	}

        memcpy(dst->buf + dst->len, src, (apr_size_t) srclen);
	dst->len += (uint32_t) srclen;

    ASSERT(dst->len < dst->bufsize);
	dst->buf[dst->len] = '\0';

    return ( dst );
}



nx_string_t *nx_string_append(nx_string_t *dst, const char *src, int srclen)
{
    return _nx_string_append(dst, src, srclen, FALSE);
}



nx_string_t *nx_string_append_throw(nx_string_t *dst, const char *src, int srclen)
{
    return _nx_string_append(dst, src, srclen, TRUE);
}



static nx_string_t *_nx_string_prepend(nx_string_t *dst, const char *src, int srclen, boolean ex_throw)
{
    ASSERT(dst != NULL);
    ASSERT(src != NULL);
    ASSERT(!(dst->flags & NX_STRING_FLAG_CONST));

    if ( srclen < 0 )
    {
	srclen = (int) strlen(src);
    }
    else if ( srclen == 0 )
    {
	return ( dst );
    }

    ensure_size(dst, dst->len + (size_t) srclen + 1, ex_throw);

    // calculate new sizes
    if ((uint32_t)srclen < dst->bufsize)
	{
	if ((uint32_t)srclen + dst->len >= dst->bufsize)
	    {
	    dst->len = dst->bufsize - (uint32_t)srclen - 1;
	}
	    }
	    else
	    {
	dst->len = 0;
	srclen = (int)(dst->bufsize) - 1;
	    }

    memmove(dst->buf + srclen, dst->buf, (apr_size_t) dst->len);
    memcpy(dst->buf, src, (apr_size_t) srclen);
    dst->len += (uint32_t) srclen;

    ASSERT(dst->len < dst->bufsize);
	    dst->buf[dst->len] = '\0';

    return ( dst );
	}



nx_string_t *nx_string_prepend(nx_string_t *dst, const char *src, int srclen)
{
    return _nx_string_prepend(dst, src, srclen, FALSE);
    }



nx_string_t *nx_string_prepend_throw(nx_string_t *dst, const char *src, int srclen)
    {
    return _nx_string_prepend(dst, src, srclen, TRUE);
}



static nx_string_t *_nx_string_set(nx_string_t *dst, const char *src, int srclen, boolean ex_throw)
{
    ASSERT(dst != NULL);
    ASSERT(src != NULL);
    ASSERT(!(dst->flags & NX_STRING_FLAG_CONST));

    if ( srclen < 0 )
    {
	srclen = (int) strlen(src);
    }

    set_len(dst, (size_t) srclen + 1, ex_throw);
    if ( srclen > 0 )
    {
	memcpy(dst->buf, src, (apr_size_t) srclen);
    }
    dst->len = (uint32_t) srclen;
    dst->buf[dst->len] = '\0';

    return ( dst );
}


nx_string_t *nx_string_set(nx_string_t *dst, const char *src, int srclen)
{
    return _nx_string_set(dst, src, srclen, FALSE);
}


nx_string_t *nx_string_set_throw(nx_string_t *dst, const char *src, int srclen)
{
    return _nx_string_set(dst, src, srclen, TRUE);
}



nx_string_t *nx_string_clone(const nx_string_t *str)
{
    nx_string_t *retval;
    uint32_t len;

    ASSERT(str != NULL);
    ASSERT(str->buf != NULL);
    
    len = str->len;
    if ( len > _string_limit )
    {
	log_warn("truncating oversized string (%u) to StringLimit (%u) in nx_string_clone()", len, _string_limit);
	len = _string_limit - 1;
    }
    retval = _nx_string_new_size(len + 1, TRUE);
    retval->flags = 0;
    retval->len = len;
    memcpy(retval->buf, str->buf, len);
    retval->buf[len] = '\0';

    return ( retval );
}



nx_string_t *nx_string_sprintf(nx_string_t 	*str,
			       const char	*fmt,
			       ...)
{
    int len;
    va_list ap;
    nx_string_t *retval;

    va_start(ap, fmt);
    len = apr_vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if ( str != NULL )
    {
	retval = str;
	set_len(str, (size_t) len + 1, TRUE);
    }
    else
    {
	retval = nx_string_new_size_throw((size_t) len + 1);
    }
    va_start(ap, fmt);
    ASSERT(apr_vsnprintf(retval->buf, (apr_size_t) len + 1, fmt, ap) == len);
    va_end(ap);
    retval->len = (uint32_t) len;

    return ( retval );
}



nx_string_t *nx_string_sprintf_append(nx_string_t 	*str,
				      const char	*fmt,
				      ...)
{
    int len;
    va_list ap;

    ASSERT(str != NULL);
    va_start(ap, fmt);
    len = apr_vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if ( str->len + (size_t) len + 1 > _string_limit )
    {
	len = (int) _string_limit - 1;
	if ( str->len < (uint32_t) len )
	{
	    log_warn("string limit (%u) exceeded while trying to append", _string_limit);
	}
    }

    ensure_size(str, str->len + (size_t) len + 1, TRUE);
    
    va_start(ap, fmt);
    ASSERT(apr_vsnprintf(str->buf + str->len, (apr_size_t) len + 1, fmt, ap) == len);
    va_end(ap);
    str->len += (uint32_t) len;

    return ( str );
}


uint32_t nx_string_replace(nx_string_t *str, uint32_t pos, uint32_t len, const char *to, int n)
{
    int to_len;

    if ( pos >= str->len )
    {
	return str->len;
    }

    if ( pos + len > str->len )
    {
        len = str->len - pos;
    }
    to_len = (n == -1) ? (int) strlen(to) : n;

    ASSERT(to_len >= 0);

    if ( str->len >= _string_limit - 1 )
    {
	// this avoids printing too much limit errors in ensure_size(),
	// it's not possible to append anyway, so just don't do anything
	return (str->len);
    }
    uint32_t new_size = str->len - len + (uint32_t)to_len;
    ensure_size(str, new_size + 1, TRUE); // including trailing zero

    memmove(str->buf + pos + to_len, str->buf + pos + len, str->len - pos - len + 1); // including trailing zero
    if ( to_len > 0 )
    {
	memcpy(str->buf + pos, to, (size_t) to_len);
    }
    str->len = new_size;
    return pos + (uint32_t)to_len;
}


nx_string_t *nx_string_escape(nx_string_t *str)
{
    size_t i;

    ASSERT(str != NULL);

    for ( i = 0; i < str->len; i++ )
    {
	if ( !(str->buf[i] & 0x80) )
	{
	    switch ( str->buf[i] )
	    {
		case '\0':
		case '\\':
		case '\'':
		case '"':
		    if ( str->bufsize <= str->len + 1 )
		    {
			ensure_size(str, str->len + 2, TRUE);
		    }
		    memmove(str->buf + i + 1, str->buf + i, str->len - i);
		    str->buf[i] = '\\';
		    (str->len)++;
		    str->buf[str->len] = '\0';
		    i++;
		    break;
		case '\n':
		    if ( str->bufsize <= str->len + 1 )
		    {
			ensure_size(str, str->len + 2, TRUE);
		    }
		    memmove(str->buf + i + 2, str->buf + i + 1, str->len - i - 1);
		    str->buf[i] = '\\';
		    str->buf[i + 1] = 'n';
		    (str->len)++;
		    str->buf[str->len] = '\0';
		    i++;
		    break;
		case '\r':
		    if ( str->bufsize <= str->len + 1 )
		    {
			ensure_size(str, str->len + 2, TRUE);
		    }
		    memmove(str->buf + i + 2, str->buf + i + 1, str->len - i - 1);
		    str->buf[i] = '\\';
		    str->buf[i + 1] = 'r';
		    (str->len)++;
		    str->buf[str->len] = '\0';
		    i++;
		    break;
		case '\t':
		    if ( str->bufsize <= str->len + 1 )
		    {
			ensure_size(str, str->len + 2, TRUE);
		    }
		    memmove(str->buf + i + 2, str->buf + i + 1, str->len - i - 1);
		    str->buf[i] = '\\';
		    str->buf[i + 1] = 't';
		    (str->len)++;
		    str->buf[str->len] = '\0';
		    i++;
		    break;
		case '\b':
		    if ( str->bufsize <= str->len + 1 )
		    {
			ensure_size(str, str->len + 2, TRUE);
		    }
		    memmove(str->buf + i + 2, str->buf + i + 1, str->len - i - 1);
		    str->buf[i] = '\\';
		    str->buf[i + 1] = 'b';
		    (str->len)++;
		    str->buf[str->len] = '\0';
		    i++;
		    break;
		default:
		    break;
	    }
	}
    }

    return ( str );
}


/* return the new length */
size_t nx_string_unescape_c(char *str)
{
    size_t i;
    size_t len;

    ASSERT(str != NULL);

    len = strlen(str);
    for ( i = 0; str[i] != '\0'; i++ )
    {
	if ( str[i] == '\\' )
	{
	    switch ( str[i + 1] )
	    {
		case '\\':
		    memmove(str + i + 1, str + i + 2, len - i - 1);
		    len--;
		    break;
		case '"':
		    memmove(str + i, str + i + 1, len - i);
		    len--;
		    break;
		case 'n':
		    str[i] = '\n';
		    memmove(str + i + 1, str + i + 2, len - i - 1);
		    len--;
		    break;
		case 'r':
		    str[i] = '\r';
		    memmove(str + i + 1, str + i + 2, len - i - 1);
		    len--;
		    break;
		case 't':
		    str[i] = '\t';
		    memmove(str + i + 1, str + i + 2, len - i - 1);
		    len--;
		    break;
		case 'b':
		    str[i] = '\b';
		    memmove(str + i + 1, str + i + 2, len - i - 1);
		    len--;
		    break;
		case 'x':
		case 'X':
		    if ( apr_isxdigit(str[i + 2]) && apr_isxdigit(str[i + 3]) )
		    {
			int c = 0;
			if ( (str[i + 2] >= '0') && (str[i + 2] <= '9') )
			{
			    c = str[i + 2] - '0';
			}
			else if ( (str[i + 2] >= 'a') && (str[i + 2] <= 'f') )
			{
			    c = str[i + 2] - 'a' + 10;
			}
			else if ( (str[i + 2] >= 'A') && (str[i + 2] <= 'F') )
			{
			    c = str[i + 2] - 'A' + 10;
			}
			c *= 16;

			if ( (str[i + 3] >= '0') && (str[i + 3] <= '9') )
			{
			    c += str[i + 3] - '0';
			}
			else if ( (str[i + 3] >= 'a') && (str[i + 3] <= 'f') )
			{
			    c += str[i + 3] - 'a' + 10;
			}
			else if ( (str[i + 3] >= 'A') && (str[i + 3] <= 'F') )
			{
			    c += str[i + 3] - 'A' + 10;
			}
			str[i] = (char) c;
			memmove(str + i + 1, str + i + 4, len - i - 3);
		    }
		    len -= 3;
		    break;
		default:
		    break;
	    }
	}
    }

    return ( len );
}



/**
 * Escapes the following json characters: ", \\, /, \b, \f, \n, \r, \t
 * plus invalid UTF-8 characters.
 */
nx_string_t *nx_string_escape_json(nx_string_t *str)
{
    uint32_t i;
    char u_sequence[7];

    nx_string_validate_utf8(str, TRUE, FALSE);

    for ( i = 0; i < str->len; i ++ )
    {
	// Skip UTF-8 chars:
	if ( str->buf[i] & 0x80 )
	{
	    continue;
	}
	switch ( str->buf[i] )
	{
	    case '"':
	        i = nx_string_replace(str, i, 1, "\\\"", 2) - 1;
		break;
	    case '\\':
		i = nx_string_replace(str, i, 1, "\\\\", 2) - 1;
		break;
	    case '/':
		i = nx_string_replace(str, i, 1, "\\/", 2) - 1;
		break;
	    case '\b':
		i = nx_string_replace(str, i, 1, "\\b", 2) - 1;
		break;
	    case '\f':
		i = nx_string_replace(str, i, 1, "\\f", 2) - 1;
		break;
	    case '\n':
		i = nx_string_replace(str, i, 1, "\\n", 2) - 1;
		break;
	    case '\r':
		i = nx_string_replace(str, i, 1, "\\r", 2) - 1;
		break;
	    case '\t':
		i = nx_string_replace(str, i, 1, "\\t", 2) - 1;
		break;
	    default:
	        if ( ((uint8_t) str->buf[i]) <= 0x1F )
	        {
	            // replace with '\u00XX
	            apr_snprintf(u_sequence, 7, "\\u00%02x", (uint8_t)str->buf[i]);
	            i = nx_string_replace(str, i, 1, u_sequence, 6) - 1;
	        }
		break;
	}

    }

    return str;
}



/**
 * Unscapes the following json characters: ", \\, /, \b, \f, \n, \r, \t.
 */

static int _nx_string_hex_to_digit(unsigned int *val, const unsigned char *hex)
{
    unsigned int i;

    for ( i = 0; i < 4; ++i )
    {
        unsigned char c = hex[i];

        if ( (c >= '0') && (c <= '9') )
        {
            c -= '0';
        }
        else if ( (c >= 'a') && (c <= 'f') )
        {
            c = c - 'a' + 10;
        }
        else if ( (c >= 'A') && (c <= 'F') )
        {
            c = c - 'A' + 10;
        }
        else
        {
            return -1;
        }

        *val = (*val << 4) | c;
    }

    return 0;
}

static int _nx_string_UTF32_to_UTF8(unsigned int codepoint, char *utf8Buf)
{
    if ( codepoint < 0x80 )
    {
        utf8Buf[0] = (char) codepoint;
        utf8Buf[1] = 0;
        return 1;
    }
    else if ( codepoint < 0x0800 )
    {
        utf8Buf[0] = (char) ((codepoint >> 6) | 0xC0);
        utf8Buf[1] = (char) ((codepoint & 0x3F) | 0x80);
        utf8Buf[2] = 0;
        return 2;
    }
    else if ( codepoint < 0x10000 )
    {
        utf8Buf[0] = (char) ((codepoint >> 12) | 0xE0);
        utf8Buf[1] = (char) (((codepoint >> 6) & 0x3F) | 0x80);
        utf8Buf[2] = (char) ((codepoint & 0x3F) | 0x80);
        utf8Buf[3] = 0;
        return 3;
    }
    else if ( codepoint < 0x200000 )
    {
        utf8Buf[0] =(char) ((codepoint >> 18) | 0xF0);
        utf8Buf[1] =(char) (((codepoint >> 12) & 0x3F) | 0x80);
        utf8Buf[2] =(char) (((codepoint >> 6) & 0x3F) | 0x80);
        utf8Buf[3] =(char) ((codepoint & 0x3F) | 0x80);
        utf8Buf[4] = 0;
        return 4;
    }
    else
    {
        utf8Buf[0] = '?';
        utf8Buf[1] = 0;
        return 1;
    }
}

nx_string_t *nx_string_unescape_json(nx_string_t *str)
{
    size_t i;

    ASSERT(str != NULL);

    for ( i = 0; str->buf[i] != '\0'; i++ )
    {
        if ( str->buf[i] == '\\' )
        {
            switch ( str->buf[i + 1] )
            {
                case '"':
                    str->buf[i] = '"';
                    memmove(str->buf + i + 1, str->buf + i + 2,
                            str->len - i - 1);
                    str->len--;
                    break;
                case '\\':
                    str->buf[i] = '\\';
                    memmove(str->buf + i + 1, str->buf + i + 2,
                            str->len - i - 1);
                    str->len--;
                    break;
                case '/':
                    str->buf[i] = '/';
                    memmove(str->buf + i + 1, str->buf + i + 2,
                            str->len - i - 1);
                    str->len--;
                    break;
                case 'b':
                    str->buf[i] = '\b';
                    memmove(str->buf + i + 1, str->buf + i + 2,
                            str->len - i - 1);
                    str->len--;
                    break;
                case 'f':
                    str->buf[i] = '\f';
                    memmove(str->buf + i + 1, str->buf + i + 2,
                            str->len - i - 1);
                    str->len--;
                    break;
                case 'n':
                    str->buf[i] = '\n';
                    memmove(str->buf + i + 1, str->buf + i + 2,
                            str->len - i - 1);
                    str->len--;
                    break;
                case 't':
                    str->buf[i] = '\t';
                    memmove(str->buf + i + 1, str->buf + i + 2,
                            str->len - i - 1);
                    str->len--;
                    break;
                case 'r':
                    str->buf[i] = '\r';
                    memmove(str->buf + i + 1, str->buf + i + 2,
                            str->len - i - 1);
                    str->len--;
                    break;
                case 'u':
                {
                    char utf8Buf[5];
                    const char *unescaped = "?";
                    unsigned int codepoint = 0;
                    size_t end_pos = i, start_pos = i, unescaped_len = 0;

                    if ( (end_pos + 5) >= str->len )
                    {
                        break;
                    }

                    // points to first digit in \uXXXX
                    end_pos += 2;

                    if ( _nx_string_hex_to_digit(&codepoint, (unsigned char *) (str->buf + end_pos)) != 0 )
                    {
                        // keep string as is
                        break;
                    }

                    // points to last digit in \uXXXX
                    end_pos += 3;

                    // check if this is a lead surrogate
                    // (codepoint >= 0xD800) && (codepoint <= 0xDBFF)
                    if ( (codepoint & 0xFC00) == 0xD800 )
                    {
                        if ( (end_pos + 6 < str->len) && (str->buf[end_pos + 1] == '\\') && (str->buf[end_pos + 2] == 'u') )
                        {
                            unsigned int surrogate = 0;

                            // points to first digit in \uXXXX
                            end_pos += 3;

                            // check if this is a trail surrogate
                            // (surrogate >= 0xDC00) && (surrogate <= 0xDFFF)
                            if ( (_nx_string_hex_to_digit(&surrogate, (unsigned char *) (str->buf + end_pos)) == 0) &&
                                 ((surrogate & 0xFC00) == 0xDC00) )
                            {
                                // points to last digit in \uXXXX
                                end_pos += 3;

                                codepoint =
                                    (((codepoint & 0x3F) << 10) |
                                     ((((codepoint >> 6) & 0xF) + 1) << 16) |
                                     (surrogate & 0x3FF));
                            }
                            else
                            {
                                // Missing or invalid trail surrogate
                                // Replace lead surrogate sequence with 0xFFFD ('?')
                                end_pos -= 3;
                                codepoint = 0xFFFD;
                            }
                        }
                        else
                        {
                            // Missing trail surrogate
                            // Replace lead surrogate sequence with 0xFFFD ('?')
                            codepoint = 0xFFFD;
                        }
                    }
                    else if ( (codepoint & 0xFC00) == 0xDC00 )
                    {
                        // Missing lead surrogate
                        codepoint = 0xFFFD;
                    }

                    unescaped_len = _nx_string_UTF32_to_UTF8(codepoint, utf8Buf);
                    unescaped = utf8Buf;

                    memcpy(str->buf + i, unescaped, unescaped_len);

                    // points to the last "unescaped" character in original str,
                    i += unescaped_len - 1;
                    memmove(str->buf + i + 1, str->buf + end_pos + 1, str->len - end_pos);
                    str->len -= end_pos - start_pos - unescaped_len + 1;
                    break;
                }
                default:
                    break;
            }
        }
    }

    return str;
}



/**
 * Finds the next UTF-8 character in the string after p.
 */

char *nx_utf8_find_next_char(char *p,
			     char *end)
{
    ASSERT(p != NULL);

    if ( *p )
    {
	if ( end )
	{
	    for ( ++p; p < end && (*p & 0xc0) == 0x80; ++p );
	}
	else
	{
	    for ( ++p; (*p & 0xc0) == 0x80; ++p );
	}
    }
    return ( ((p == end) ? NULL : p) );
}



/**
 * Check if a utf-8 character is valid
 */

boolean nx_utf8_is_valid_char(const char *src,
			      int32_t length)
{
    char a;
    const char *srcptr = src + length;

    ASSERT(src != NULL);
    ASSERT(length >= 0);

    switch ( length )
    {
	default:
	    return ( FALSE );
	case 4:
	    if ( ((a = (*--srcptr)) < 0x80) || (a > 0xBF) )
	    {
		return ( FALSE );
	    }
	case 3:
	    if ( ((a = (*--srcptr)) < 0x80) || (a > 0xBF) )
	    {
		return ( FALSE );
	    }
	case 2:
	    if ( (a = (*--srcptr)) > 0xBF )
	    {
		return ( FALSE );
	    }

	    switch ( *src )
	    {
		case 0xE0:
		    if ( a < 0xA0 )
		    {
			return ( FALSE );
		    }
		    break;
		case 0xED:
		    if ( a > 0x9F )
		    {
			return ( FALSE );
		    }
		    break;
		case 0xF0:
		    if ( a < 0x90 )
		    {
			return ( FALSE );
		    }
		    break;
		case 0xF4:
		    if ( a > 0x8F )
		    {
			return ( FALSE );
		    }
		    break;
		default:
		    if ( a < 0x80 )
		    {
			return ( FALSE );
		    }
	    }

	case 1:
	    if ( (*src >= 0x80) && (*src < 0xC2) )
	    {
		    return ( FALSE );
	    }
    }
    if ( *src > 0xF4 )
    {
	return ( FALSE );
    }
    return ( TRUE );
}

#define NX_UNICODE_LAST_CHAR 0x10ffff
#define NX_UNICODE_SUR_HIGH_START 0xD800
#define NX_UNICODE_SUR_LOW_END 0xDFFF

static const int32_t _nx_trailing_bytes_for_utf8[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,0,0
};

static const uint32_t _nx_offsets_from_utf8[6] = { 0x00000000UL, 0x00003080UL, 0x000E2080UL, 
						   0x03C82080UL, 0xFA082080UL, 0x82082080UL };


/**
 * Gets pointer to next UTF-8 character in the string after current character.
 * (_nx_trailing_bytes_for_utf8[ch] + 1) gives a number of bytes of the current
 * UTF-8 character, where 'ch' is the first byte of the current character.
 */

#define nx_utf8_next_char(p) (char *)((p) + _nx_trailing_bytes_for_utf8[(int32_t )(*p)] + 1)


boolean nx_string_validate_utf8(nx_string_t *str, boolean needfix, boolean throw)
{
    char *srcptr, *srcend;
    int32_t bytestoread;
    uint32_t chr;
    char *dstptr = NULL;
    boolean valid = TRUE;

    ASSERT(str != NULL);

    srcend = str->buf + str->len;
    srcptr = str->buf;

    while ( srcptr < srcend )
    {
	chr = 0;
	bytestoread = _nx_trailing_bytes_for_utf8[(int32_t) *srcptr];

    	if ( srcptr + bytestoread + 1 > srcend )
	{
	    if ( throw == TRUE )
	    {
		throw_msg("incomplete utf-8 byte sequence at end of input at pos %lld",
			  (long long int) (srcptr - str->buf));
	    }
	    else
	    {
		if ( needfix == TRUE )
		{
		    valid = FALSE;

		    dstptr = srcptr;
		    srcptr = nx_utf8_find_next_char(srcptr, srcend);
		    if ( srcptr == NULL )
		    {
			while ( dstptr < srcend )
			{
			    *dstptr++ = '?';
			}
			break;
		    }
		    else
		    {
			while ( dstptr < srcptr )
			{
			    *dstptr++ = '?';
			}
			continue;
		    }
		}
		else
		{
		    return ( FALSE );
		}
	    }
	}

	if ( nx_utf8_is_valid_char(srcptr, bytestoread + 1) == FALSE )
	{
	    if ( throw == TRUE )
	    {
		throw_msg("invalid utf-8 byte sequence at end of input at pos %lld",
			  (long long int) (srcptr - str->buf));
	    }
	    else
	    {
		if ( needfix == TRUE )
		{
		    valid = FALSE;

		    dstptr = srcptr;
		    srcptr = nx_utf8_find_next_char(srcptr, srcend);
		    if ( srcptr == NULL )
		    {
			while ( dstptr < srcend )
			{
			    *dstptr++ = '?';
			}
			break;
		    }
		    else
		    {
			while ( dstptr < srcptr )
			{
			    *dstptr++ = '?';
			}
			continue;
		    }
		}
		else
		{
		    return ( FALSE );
		}
	    }
	}

	switch ( bytestoread )
	{
	    case 5:
		chr += *srcptr++;
		chr <<= 6;
	    case 4:
		chr += *srcptr++;
		chr <<= 6;
	    case 3:
		chr += *srcptr++;
		chr <<= 6;
	    case 2:
		chr += *srcptr++;
		chr <<= 6;
	    case 1:
		chr += *srcptr++;
		chr <<= 6;
	    case 0:
		chr += *srcptr++;
		break;
	    default :
		nx_panic("invalid value in bytestoread (%d)", bytestoread);
	}

	chr -= _nx_offsets_from_utf8[bytestoread];

	if ( chr <= NX_UNICODE_LAST_CHAR )
	{
	    if ( ((chr >= NX_UNICODE_SUR_HIGH_START) && (chr <= NX_UNICODE_SUR_LOW_END))
		 || (chr == 0xFFFE) || (chr == 0xFFFF) )
	    {
		if ( throw == TRUE )
		{
		    throw_msg("invalid utf-8 byte sequence at pos %d",
			      (int) (srcptr - bytestoread - 1 - str->buf));
		}
		else
		{
		    if ( needfix == TRUE )
		    {
			valid = FALSE;

			dstptr = srcptr - bytestoread - 1;

			srcptr = nx_utf8_find_next_char(srcptr, srcend);
			if ( srcptr == NULL )
			{
			    while ( dstptr < srcend )
			    {
				*dstptr++ = '?';
			    }
			    break;
			}
			else
			{
			    while ( dstptr < srcptr )
			    {
				*dstptr++ = '?';
			    }
			    continue;
			}
		    }
		    else
		    {
			return ( FALSE );
		    }
		}
	    }
	}
	else
	{
	    if ( throw == TRUE )
	    {
		throw_msg("invalid utf-8 byte sequence at pos %d",
			  (int) (srcptr - bytestoread - 1 - str->buf));
	    }
	    else
	    {
		if ( needfix == TRUE )
		{
		    valid = FALSE;
		    dstptr = srcptr - bytestoread - 1;

		    srcptr = nx_utf8_find_next_char(srcptr, srcend);
		    if ( srcptr == NULL )
		    {
			while ( dstptr < srcend )
			{
			    *dstptr++ = '?';
			}
			break;
		    }
		    else
		    {
			while ( dstptr < srcptr )
			{
			    *dstptr++ = '?';
			}
			continue;
		    }
		}
		else
		{
		    return ( FALSE );
		}
	    }
	}
    }

    return ( valid );
}



nx_string_t *nx_string_strip_crlf(nx_string_t *str)
{
    ASSERT(str != NULL);

    if ( str->len > 0 )
    {
	if ( str->buf[str->len - 1] == APR_ASCII_LF )
	{
	    str->buf[str->len - 1] = '\0';
	    (str->len)--;
	    if ( str->len > 0 )
	    {
		if ( str->buf[str->len - 1] == APR_ASCII_CR )
		{
		    str->buf[str->len - 1] = '\0';
		    (str->len)--;
		}
	    }
	}
    }

    return ( str );
}
