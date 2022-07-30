/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Roman Avkhadeev
 */

#include <Python.h>

#ifdef gid_t
# undef gid_t
#endif

#ifdef uid_t
# undef uid_t
#endif

#include <frameobject.h>
#include <string.h>
#include <apr_env.h>
#include <libgen.h>

#include "../../../common/types.h"
#include "../../../common/exception.h"
#include "../../../common/error_debug.h"
#include "../../../core/ctx.h"

#include "libnxpython.h"

#define NX_LOGMODULE NX_LOGMODULE_MODULE

//#define DEBUG_REFCNT_BUILD

#ifdef DEBUG_REFCNT_BUILD

#define _LOG_PYREF(x,s) log_info("IN %s:%d %s, %s: %ld", __FILE__, __LINE__, (s), #x, Py_REFCNT(x))
#define LOG_Py_DECREF(x) _LOG_PYREF(x, "V"); Py_DECREF(x)
#define LOG_Py_INCREF(x) _LOG_PYREF(x, "^"); Py_INCREF(x)
#define LOG_Py_XDECREF(x) _LOG_PYREF(x, "V"); Py_XDECREF(x)

#else

#define LOG_Py_DECREF(x) Py_DECREF(x)
#define LOG_Py_INCREF(x) Py_INCREF(x)
#define LOG_Py_XDECREF(x) Py_XDECREF(x)

#endif

#define NX_PYTHON_REFCOUNTER_NAME "xm_python_counter"
#define NX_PYTHON_GLOBAL_THREADSTATE "xm_python_global_state"

typedef struct script_info_t
{
    char *dir;
    char *name;
} script_info_t;

boolean split_python_scriptname(apr_pool_t *mp,
				const char *full_path,
				script_info_t *info)
{
    char *cdirname;
    char *dir_name;
    char *cname;
    char *name;
    size_t name_len;
    char *pos = NULL;

    info->dir = NULL;
    info->name = NULL;

    if ( (full_path == NULL) || (strlen(full_path) == 0) )
    {
	return FALSE;
    }

    cdirname = apr_pstrdup(mp, full_path);
    dir_name = dirname(cdirname);

    cname = apr_pstrdup(mp, full_path);
    name = basename(cname);
    name_len = strlen(name);

    if ( name_len < 4 )
    {
	return FALSE;
    }

    for ( pos = name + name_len - 1; pos >= name; --pos )
    {
	if ( strncmp(pos, ".", 1) == 0 )
	{
	    if ( (strlen(pos) == 3) &&
		 (strncmp(pos, ".py", 3) == 0) )
	    {
		info->dir = apr_pstrdup(mp, dir_name);
		info->name = apr_pstrndup(mp, name, (apr_size_t) (pos - name));
		return TRUE;
	    }
	}
    }

    return FALSE;
}

static char* set_python_env(apr_pool_t * mp, const char * script_path)
{
    apr_array_header_t *array;
    char * liststr;

    array = apr_array_make(mp, 4, sizeof(const char*));

    ASSERT(array != NULL);

    char *pythonpath = NULL;
    apr_env_get(&pythonpath, "PYTHONPATH", mp);
    if ( pythonpath != NULL )
    {
	log_debug("found PYTHONPATH is '%s'", pythonpath);
	*(const char **)apr_array_push(array) = pythonpath;
    }

    *(const char **)apr_array_push(array) = script_path;
    *(const char **)apr_array_push(array) = PYMODULE_DIR;
//    *(const char **)apr_array_push(array) = PYMODULEP_DIR;
    *(const char **)apr_array_push(array) = PYTESTMOD_DIR;
    *(const char **)apr_array_push(array) = PYTESTMODP_DIR;

    CHECKERR_MSG(apr_filepath_list_merge(&liststr, array, mp),
		"Couldn't merge path");

    log_debug("Search PyNxlog libraries at %s", liststr);

    // for linux:
    CHECKERR_MSG(apr_env_set("PYTHONPATH", liststr, mp),
                 "Couldn't set PYTHONPATH env");
    return liststr;
}

static nx_string_t * print_tb_frame(PyFrameObject * frame, int level)
{
    ASSERT(frame != NULL);

    if (frame->f_code == NULL
            || frame->f_code->co_name == NULL
            || frame->f_code->co_filename == NULL)
    {
        return NULL;
    }

    PyObject *tmp1 = PyObject_Str(frame->f_code->co_name);
    PyObject *tmp2 = PyObject_Str(frame->f_code->co_filename);
    PyObject *tmp3 = PyUnicode_AsEncodedString(tmp1, "utf-8", "replace");
    PyObject *tmp4 = PyUnicode_AsEncodedString(tmp2, "utf-8", "replace");
    LOG_Py_DECREF(tmp1);
    LOG_Py_DECREF(tmp2);
    nx_string_t *ret = nx_string_sprintf(NULL, "#%d in %s (...) at: %s:%d\n",
					 level,
					 PyBytes_AsString(tmp3),
					 PyBytes_AsString(tmp4),
					 PyCode_Addr2Line(frame->f_code, frame->f_lasti));
    LOG_Py_DECREF(tmp3);
    LOG_Py_DECREF(tmp4);
    return ret;
}

static void dump_traceback(PyTracebackObject * tb)
{
    PyFrameObject * frame;
    nx_string_t * str_frame;
    int level;

    level = 0;

    if (tb == NULL)
        return;

    // forward (looking for last frame)
    while (tb->tb_next) {
        tb = tb->tb_next;
    }

    for (frame = tb->tb_frame;
         frame != NULL;
         frame = frame->f_back, level ++)
    {
        str_frame = print_tb_frame(frame, level);
        if (str_frame)
        {
            log_error("%s", str_frame->buf);
            nx_string_free(str_frame);
        }
    }
}

void nx_python_log_err(void)
{

    PyObject * py_type;
    PyObject * py_value;
    PyObject * py_traceback;
    PyObject * py_repr = NULL;
    PyObject * py_enc_repr = NULL;

    PyErr_Fetch(&py_type, &py_value, &py_traceback);

    if ( py_type != NULL )
    {
        Py_DECREF(py_type) ;
    }
    if ( py_value != NULL )
    {
        py_repr = PyObject_Repr(py_value);
	if ( py_repr == NULL )
	{
	    // for debugging purpose
	    log_error("Python ERROR: PyObject_Repr(py_value) returned NULL in 'nx_python_log_err()'");
	}
	else
	{
	    py_enc_repr = PyUnicode_AsEncodedString(py_repr, "utf-8", "replace");
	    log_error("Python ERROR: %s", PyBytes_AsString(py_enc_repr));
	}
        Py_XDECREF(py_repr);
        Py_DECREF(py_value);
	Py_XDECREF(py_enc_repr);
    }
    if ( py_traceback != NULL )
    {
        dump_traceback((PyTracebackObject*)py_traceback);
        Py_DECREF(py_traceback) ;

    }
}

static boolean _is_init(void)
{
    nx_ctx_t *ctx;
    int * counter;

    ctx = nx_ctx_get();
    ASSERT(ctx != NULL);
    counter = nx_ctx_data_get(ctx, NX_PYTHON_REFCOUNTER_NAME);

    return (counter != NULL) && ((*counter) > 0);
}

static void _inc_init(void)
{
    nx_ctx_t *ctx;
    int * counter;

    ctx = nx_ctx_get();
    ASSERT(ctx != NULL);

    counter = (int *) nx_ctx_data_get(ctx, NX_PYTHON_REFCOUNTER_NAME);
    if (counter == NULL)
    {
        counter = apr_pcalloc(ctx->pool, sizeof(*counter));
        nx_ctx_data_set(ctx, NX_PYTHON_REFCOUNTER_NAME, counter);
    }
    (*counter) ++;
}

static int _dec_init(void)
{
    nx_ctx_t *ctx;
    int * counter;

    ctx = nx_ctx_get();
    ASSERT(ctx != NULL);

    counter = (int *) nx_ctx_data_get(ctx, NX_PYTHON_REFCOUNTER_NAME);

    ASSERT(counter != NULL);
    (*counter) --;

    return (*counter);
}

static void nx_python_global_init(void)
{
    if (!_is_init())
    {
        // Global init
        Py_InitializeEx(0);

	// GIL acquired
	PyEval_InitThreads();
	nx_ctx_data_set(nx_ctx_get(), NX_PYTHON_GLOBAL_THREADSTATE, PyThreadState_Get());
    }
    else
    {
	// acquire GIL (+ restore global state)
	PyEval_RestoreThread((PyThreadState *) nx_ctx_data_get(nx_ctx_get(), NX_PYTHON_GLOBAL_THREADSTATE));
    }
    _inc_init();
}

static void nx_python_finalize_global(void)
{
    if (_dec_init() == 0)
    {
	// acquire GIL (+ restore global state)
	PyEval_RestoreThread((PyThreadState *) nx_ctx_data_get(nx_ctx_get(), NX_PYTHON_GLOBAL_THREADSTATE));
#if (PY_MAJOR_VERSION > 3) || ((PY_MAJOR_VERSION == 3) && (PY_MINOR_VERSION >= 6))
	int status = Py_FinalizeEx();
	if ( status != 0 )
	{
	    log_error("Py_FinalizeEx() error returned.");
	}
#else
	Py_Finalize();
#endif
    }
}

void nx_python_init_iomodule (nx_python_conf_t * conf,
                              const char * pythoncode,
                              const char * func,
                              PyObject **callable)
{
    nx_exception_t e;

    ASSERT(conf != NULL);
    ASSERT(pythoncode != NULL);
    ASSERT(func != NULL);
    ASSERT(callable != NULL);

    nx_python_begin_section(conf);

    try
    {
        *callable = PyObject_GetAttrString(conf->py_code, func);
        if (!*callable || !PyCallable_Check(*callable))
        {
            Py_XDECREF(*callable);
            throw_msg("'%s' func not found!", func);
        }
        Py_INCREF(*callable);
    }
    catch(e)
    {
        nx_python_log_err();
        nx_python_end_section(conf);
        nx_python_finalize(conf);
        *callable = NULL;
        rethrow(e);
    }
    nx_python_end_section(conf);
}


nx_python_conf_t *nx_python_conf_new(apr_pool_t * mp)
{
    nx_python_conf_t * conf;

    ASSERT(mp != NULL);

    conf = apr_pcalloc(mp, sizeof(nx_python_conf_t));

    return conf;
}

void nx_python_dump_list(PyObject * list)
{
    ASSERT(list != NULL);

    Py_INCREF(list);
    PyObject * key;
    ssize_t iter;
    ssize_t len = PyList_Size(list);
    log_info("DUMP list: ");
    for (iter = 0; iter < len; iter ++)
    {
        key = PyList_GetItem(list, iter);
        Py_INCREF(key);

	PyObject *tmp1 = PyObject_Str(key);
	PyObject *tmp2 = PyUnicode_AsEncodedString(tmp1, "utf-8", "replace");
	log_info("%s", PyBytes_AsString(tmp2));
	Py_DECREF(tmp1);
	Py_DECREF(tmp2);
        Py_DECREF(key);
    }
    log_info("DONE");
    Py_DECREF(list);
}


void nx_python_begin_section(nx_python_conf_t * conf)
{
    PyThreadState *thread_state;

    ASSERT(conf != NULL);

    if ( conf->py_interpreter == NULL )
    {
        // probably init error
        throw_msg("Python interpreter not initialized; please see previous errors");
    }

    ASSERT(apr_threadkey_private_get((void **) &thread_state, conf->thread_state_key) == APR_SUCCESS);
    if ( thread_state == NULL )
    {
	// create new PyThreadState
	thread_state = PyThreadState_New(conf->py_interpreter);
	ASSERT(apr_threadkey_private_set(thread_state, conf->thread_state_key) == APR_SUCCESS);
    }
    ASSERT(thread_state != NULL);

    // set thread state and acquire GIL
    PyEval_RestoreThread(thread_state);
}



void nx_python_end_section(nx_python_conf_t * conf)
{
    PyThreadState *thread_state;

    ASSERT(conf != NULL);
    ASSERT(conf->py_interpreter != NULL);

    ASSERT(apr_threadkey_private_get((void **) &thread_state, conf->thread_state_key) == APR_SUCCESS);
    ASSERT(thread_state != NULL);

    // reset thread state and release GIL
    PyEval_SaveThread();
}



void nx_python_finalize(nx_python_conf_t * conf)
{
    ASSERT(conf != NULL);
    ASSERT(conf->py_interpreter != NULL);

    nx_python_begin_section(conf);

    Py_XDECREF(conf->py_module_instance);
    Py_XDECREF(conf->py_code);
    Py_XDECREF(conf->py_module);

    nx_python_end_section(conf);

    // PyInterpreterState_Clear segfaults if there is no current thread state, but it
    // also fails if one of the sub-interpreter's thread states is used by a thread,
    // so we select the global thread state into the current thread.
    // Technically, it's not ok to use PyEval_RestoreThread to restore the global (or
    // any other) thread state into a different thread (the debug version of CPython
    // would complain about this), but we don't have any other choice here
    // (nx_python_finalize_global() does this too).
    PyEval_RestoreThread((PyThreadState *) nx_ctx_data_get(nx_ctx_get(), NX_PYTHON_GLOBAL_THREADSTATE));

    // destroys all thread states for this interpreter
    PyInterpreterState_Clear(conf->py_interpreter);

    // destroys the interpreter
    PyInterpreterState_Delete(conf->py_interpreter);

    conf->py_interpreter = NULL;

    // release GIL
    PyEval_ReleaseLock();

    nx_python_finalize_global();

#ifndef WIN32
    // it looks like python spoils SIGINT handler even if we use Py_InitializeEx(0)
    // but we can use SIGTERM's handler to set as SIGINT's
    struct sigaction sigterm;
    sigaction(SIGTERM, NULL, &sigterm);
    sigaction(SIGINT, &sigterm, NULL);
#endif
}

void nx_python_init(nx_module_t * module, nx_python_conf_t * conf, const char * pythoncode)
{
    script_info_t info = {0};
    PyObject * py_module_init_args;
    PyObject * py_module_init_args_param;
    PyObject * volatile py_module_class = NULL;
    nx_exception_t e;
    char * path;
    PyThreadState *thread_state;

    ASSERT(module != NULL);
    ASSERT(conf != NULL);
    ASSERT(pythoncode != NULL);

    boolean res = split_python_scriptname(module->pool, pythoncode, &info);
    if ( res == FALSE )
    {
	throw_msg("Invalid 'PythonCode' path '%s' : missing '.py' file extension", pythoncode);
    }

    CHECKERR_MSG(apr_filepath_merge(&path, NULL, info.dir, APR_FILEPATH_TRUENAME, module->pool),
                 "Could not get default dir");

    log_debug("Loading PYTHON script: dir=%s, module=%s",
	      path,
	      info.name);
    char *py_path = set_python_env(module->pool, path);

    ASSERT(conf->thread_state_key == NULL);
    ASSERT(apr_threadkey_private_create(&(conf->thread_state_key), NULL, module->pool) == APR_SUCCESS);

    nx_python_global_init();

    // create new sub-interpreter for current module
    if ( (thread_state = Py_NewInterpreter()) == NULL )
    {
	throw_msg("Couldn't create python interpreter");
    }

    // save interpreter for later use
    ASSERT(thread_state->interp != NULL);
    conf->py_interpreter = thread_state->interp;

    // save PyThreadState for current thread
    ASSERT(apr_threadkey_private_set(thread_state, conf->thread_state_key) == APR_SUCCESS);

    // set as current thread state
    PyThreadState_Swap(thread_state);

    try
    {
#ifdef WIN32
	// on linux it didn't work
	ASSERT(py_path != NULL);
	nx_string_t *py_append = nx_string_create("import sys\nsys.path.append('", -1);
	nx_string_append_throw(py_append, py_path, -1);
	nx_string_append_throw(py_append, "')\n", -1);
	PyRun_SimpleString(py_append->buf);
	nx_string_free(py_append);
#endif

	log_debug("calling PyImport_ImportModule()");
        // Load lib module
        conf->py_module = PyImport_ImportModule("nxlog");
        if (!conf->py_module)
        {
            throw_msg("Couldn't load PYTHON module from %s", pythoncode);
        }
        Py_INCREF(conf->py_module);

        // Load script
        conf->py_code = PyImport_ImportModule(info.name);
        if (conf->py_code == NULL)
        {
            throw_msg("Couldn't import python module '%s'", info.name);
        }
        Py_INCREF(conf->py_code);

        switch (module->type)
        {
            case NX_MODULE_TYPE_INPUT:
                py_module_class = PyObject_GetAttrString(conf->py_module, "InputModule");
                break;
            case NX_MODULE_TYPE_OUTPUT:
                py_module_class = PyObject_GetAttrString(conf->py_module, "OutputModule");
                break;
            case NX_MODULE_TYPE_EXTENSION:
                py_module_class = PyObject_GetAttrString(conf->py_module, "ExtensionModule");
                break;
            case NX_MODULE_TYPE_PROCESSOR:
            default:
                break;
        }

        if ( (py_module_class == NULL) || (PyType_Check(py_module_class) != 1) )
        {
            throw_msg("init python module class error");
	}

	py_module_init_args_param = PyCapsule_New(module, "module", NULL);
	py_module_init_args = Py_BuildValue("(O)", py_module_init_args_param);
	LOG_Py_XDECREF(py_module_init_args_param);

	// new instance
	conf->py_module_instance = PyType_GenericNew((PyTypeObject *)py_module_class, py_module_init_args, NULL);
	int instance_check = PyObject_IsInstance(conf->py_module_instance, py_module_class);

        if ( (conf->py_module_instance == NULL) || (instance_check != 1) )
        {
            throw_msg("init python module instance not created");
        }

	// init instance
	ASSERT(0 == Py_TYPE(conf->py_module_instance)->tp_init(conf->py_module_instance, py_module_init_args, NULL));

        Py_INCREF(conf->py_module_instance);
	LOG_Py_XDECREF(py_module_init_args);

    }
    catch (e)
    {
        nx_python_log_err();
	nx_python_end_section(conf);
        nx_python_finalize(conf);
        rethrow(e);
    }

    // GIL release
    nx_python_end_section(conf);
}
