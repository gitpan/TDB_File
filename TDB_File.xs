#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <sys/types.h>
#include <tdb.h>

/* for debugging.. */
#if defined (__GNUC__) && defined (__i386__)
# define stop() __asm__("int    $0x03\n")
#else
# define stop() #error "gdb break op unknown on this arch"
#endif

static int
delete_key_cb(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA data, void *state)
{
	return tdb_delete(tdb, key);
}

static SV *log_func_cb_sv = Nullsv;
static void
log_func_cb(TDB_CONTEXT *tdb, int level, const char *fmt, ...)
{
	va_list	ap;
	bool	false = FALSE;
	int count;
	SV *	sv;
	dSP;
	dXSTARG;

	if (!SvOK(log_func_cb_sv)) return;

	va_start(ap, fmt);

	ENTER;
	SAVETMPS;

	sv = NEWSV(777, 0);
	sv_vsetpvfn(sv, fmt, strlen(fmt), &ap, NULL, 0, &false);

	PUSHMARK(SP);
	XPUSHi(level);
	XPUSHs(sv_2mortal(sv));
	PUTBACK;

	count = call_sv(log_func_cb_sv, G_VOID|G_DISCARD);

	if (count != 0)
		croak("log_func_cb: expected 0 values from callback %p, got %d\n",
		      log_func_cb_sv, count);

	FREETMPS;
	LEAVE;

	va_end(ap);
}

static int
traverse_cb(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA data, void *status)
{
	dSP;
	SV *	coderef = status;
	SV *	retval;
	int	count;
	int	ret;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(key.dptr, key.dsize)));
	XPUSHs(sv_2mortal(newSVpv(data.dptr, data.dsize)));
	PUTBACK;

	count = call_sv(coderef, G_SCALAR);

	SPAGAIN;

	if (count != 1)
		croak("tdb_traverse callback returned %d args\n", count);

	retval = POPs;
	ret = !SvTRUE(retval);

	PUTBACK;
	FREETMPS;
	LEAVE;

	return ret;
}

static double
constant_TDB_N(char *name, int len, int arg)
{
    if (5 + 1 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[5 + 1]) {
    case 'L':
	if (strEQ(name + 5, "OLOCK")) {	/* TDB_N removed */
#ifdef TDB_NOLOCK
	    return TDB_NOLOCK;
#else
	    goto not_there;
#endif
	}
    case 'M':
	if (strEQ(name + 5, "OMMAP")) {	/* TDB_N removed */
#ifdef TDB_NOMMAP
	    return TDB_NOMMAP;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_TDB_I(char *name, int len, int arg)
{
    if (5 + 1 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[5 + 1]) {
    case 'S':
	if (strEQ(name + 5, "NSERT")) {	/* TDB_I removed */
#ifdef TDB_INSERT
	    return TDB_INSERT;
#else
	    goto not_there;
#endif
	}
    case 'T':
	if (strEQ(name + 5, "NTERNAL")) {	/* TDB_I removed */
#ifdef TDB_INTERNAL
	    return TDB_INTERNAL;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_TDB_ERR_N(char *name, int len, int arg)
{
    if (9 + 1 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[9 + 1]) {
    case 'E':
	if (strEQ(name + 9, "OEXIST")) {	/* TDB_ERR_N removed */
	    enum TDB_ERROR ret = TDB_ERR_NOEXIST;
	    return ret;
	}
    case 'L':
	if (strEQ(name + 9, "OLOCK")) {		/* TDB_ERR_N removed */
	    return (enum TDB_ERROR)TDB_ERR_NOLOCK;
	}
    }
    errno = EINVAL;
    return 0;
}

static double
constant_TDB_E(char *name, int len, int arg)
{
    if (5 + 3 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[5 + 3]) {
    case 'C':
	if (strEQ(name + 5, "RR_CORRUPT")) {	/* TDB_E removed */
	    return TDB_ERR_CORRUPT;
	}
    case 'E':
	if (strEQ(name + 5, "RR_EXISTS")) {	/* TDB_E removed */
	    return TDB_ERR_EXISTS;
	}
    case 'I':
	if (strEQ(name + 5, "RR_IO")) {		/* TDB_E removed */
	    return TDB_ERR_IO;
	}
    case 'L':
	if (strEQ(name + 5, "RR_LOCK")) {	/* TDB_E removed */
	    return TDB_ERR_LOCK;
	}
    case 'N':
	if (!strnEQ(name + 5,"RR_N", 4))
	    break;
	return constant_TDB_ERR_N(name, len, arg);
    case 'O':
	if (strEQ(name + 5, "RR_OOM")) {	/* TDB_E removed */
	    return TDB_ERR_OOM;
	}
    }
    errno = EINVAL;
    return 0;
}

static double
constant_TDB_C(char *name, int len, int arg)
{
    switch (name[5 + 0]) {
    case 'L':
	if (strEQ(name + 5, "LEAR_IF_FIRST")) {	/* TDB_C removed */
#ifdef TDB_CLEAR_IF_FIRST
	    return TDB_CLEAR_IF_FIRST;
#else
	    goto not_there;
#endif
	}
    case 'O':
	if (strEQ(name + 5, "ONVERT")) {	/* TDB_C removed */
#ifdef TDB_CONVERT
	    return TDB_CONVERT;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant(char *name, int len, int arg)
{
    errno = 0;
    if (0 + 4 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[0 + 4]) {
    case 'C':
	if (!strnEQ(name + 0,"TDB_", 4))
	    break;
	return constant_TDB_C(name, len, arg);
    case 'D':
	if (strEQ(name + 0, "TDB_DEFAULT")) {	/*  removed */
#ifdef TDB_DEFAULT
	    return TDB_DEFAULT;
#else
	    goto not_there;
#endif
	}
    case 'E':
	if (!strnEQ(name + 0,"TDB_", 4))
	    break;
	return constant_TDB_E(name, len, arg);
    case 'I':
	if (!strnEQ(name + 0,"TDB_", 4))
	    break;
	return constant_TDB_I(name, len, arg);
    case 'M':
	if (strEQ(name + 0, "TDB_MODIFY")) {	/*  removed */
#ifdef TDB_MODIFY
	    return TDB_MODIFY;
#else
	    goto not_there;
#endif
	}
    case 'N':
	if (!strnEQ(name + 0,"TDB_", 4))
	    break;
	return constant_TDB_N(name, len, arg);
    case 'R':
	if (strEQ(name + 0, "TDB_REPLACE")) {	/*  removed */
#ifdef TDB_REPLACE
	    return TDB_REPLACE;
#else
	    goto not_there;
#endif
	}
    case 'S':
	if (strEQ(name + 0, "TDB_SUCCESS")) {	/*  removed */
	    return TDB_SUCCESS;
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

typedef int mone_on_fail;

MODULE = TDB_File		PACKAGE = TDB_File		PREFIX = tdb_


double
constant(sv,arg)
    PREINIT:
	STRLEN		len;
    INPUT:
	SV *		sv
	char *		s = SvPV(sv, len);
	int		arg
    CODE:
	RETVAL = constant(s,len,arg);
    OUTPUT:
	RETVAL


mone_on_fail
tdb_chainlock(tdb, key)
	TDB_CONTEXT *	tdb
	TDB_DATA	key

void
tdb_chainunlock(tdb, key)
	TDB_CONTEXT *	tdb
	TDB_DATA	key

void
tdb_DESTROY(tdb)
	TDB_CONTEXT *	tdb
    CODE:
	if (tdb) tdb_close(tdb);
	/* ignores failure (which probably leaks) */

mone_on_fail
tdb_delete(tdb, key)
	TDB_CONTEXT *	tdb
	TDB_DATA	key
    ALIAS:
	DELETE = 1

void
tdb_CLEAR(tdb)
	TDB_CONTEXT *	tdb
    CODE:
	tdb_traverse(tdb, delete_key_cb, NULL);

void
tdb_dump_all(tdb)
	TDB_CONTEXT *	tdb

enum TDB_ERROR
tdb_error(tdb)
	TDB_CONTEXT *	tdb

const char *
tdb_errorstr(tdb)
	TDB_CONTEXT *	tdb

int
tdb_exists(tdb, key)
	TDB_CONTEXT *	tdb
	TDB_DATA	key
    ALIAS:
	EXISTS = 1

TDB_DATA
tdb_fetch(tdb, key)
	TDB_CONTEXT *	tdb
	TDB_DATA	key
    ALIAS:
	FETCH = 1

TDB_DATA
tdb_firstkey(tdb)
	TDB_CONTEXT *	tdb
    ALIAS:
	FIRSTKEY = 1

mone_on_fail
tdb_lockall(tdb)
	TDB_CONTEXT *	tdb

mone_on_fail
tdb_lockkeys(tdb, ...)
	TDB_CONTEXT *	tdb
    PREINIT:
	TDB_DATA *	keys;
	int		i;
	int		number;
    CODE:
	number = items - 1;
	New(777, keys, number, TDB_DATA);
	for (i = 0; i < number; i++) {
		STRLEN	len;
		keys[i].dptr = SvPV(ST(i+1), len);
		keys[i].dsize = len;
	}
	RETVAL = tdb_lockkeys(tdb, number, keys);
	Safefree(keys);
    OUTPUT:
	RETVAL

void
tdb_logging_function(tdb, arg1)
	TDB_CONTEXT *	tdb
	SV *		arg1
    CODE:
	if (log_func_cb_sv == Nullsv)
		log_func_cb_sv = newSVsv(arg1);
	else
		SvSetSV(log_func_cb_sv, arg1);
	tdb_logging_function(tdb, log_func_cb);

TDB_DATA
tdb_nextkey(tdb, key)
	TDB_CONTEXT *	tdb
	TDB_DATA	key
    ALIAS:
	NEXTKEY = 1

TDB_CONTEXT *
tdb_open(class, name, tdb_flags = TDB_DEFAULT, open_flags = O_RDWR|O_CREAT, mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH, hash_size = 0, log_fn = Nullsv)
	char *	class
	char *	name
	int	hash_size
	int	tdb_flags
	int	open_flags
	mode_t	mode
	SV *	log_fn
    ALIAS:
	TIEHASH = 1
    CODE:
	if (log_fn == Nullsv)
		RETVAL = tdb_open(name, hash_size, tdb_flags, open_flags, mode);
	else /* items == 7 */ {
		if (log_func_cb_sv == Nullsv)
			log_func_cb_sv = newSVsv(log_fn);
		else
			SvSetSV(log_func_cb_sv, log_fn);
		RETVAL = tdb_open_ex(name, hash_size, tdb_flags,
				     open_flags, mode, log_func_cb);
	}
	if (!RETVAL) XSRETURN_UNDEF;
    OUTPUT:
	RETVAL

void
tdb_printfreelist(tdb)
	TDB_CONTEXT *	tdb

mone_on_fail
tdb_reopen(tdb)
	TDB_CONTEXT *	tdb
    POSTCALL:
	/* tdb_reopen frees the TDB_CONTEXT on failure,
	 * so set scalar value to 0 to avoid double free on DESTROY */
	if (RETVAL == -1)
		sv_setiv((SV*)SvRV(ST(0)), 0);
		

# FIXME: if this fails, we need to undef $tdb or something
# .. which we can't do - cos we don't know where it failed :(
# maybe reimplement this ourselves?
mone_on_fail
tdb_reopen_all()

mone_on_fail
tdb_store(tdb, key, dbuf, flag = TDB_REPLACE)
	TDB_CONTEXT *	tdb
	TDB_DATA	key
	TDB_DATA	dbuf
	int		flag
    ALIAS:
	STORE = 1

int
tdb_traverse(tdb, fn = &PL_sv_undef)
	TDB_CONTEXT *	tdb
	SV *		fn
    CODE:
	if (SvOK(fn))
		RETVAL = tdb_traverse(tdb, traverse_cb, fn);
	else
		RETVAL = tdb_traverse(tdb, NULL, NULL);
	if (RETVAL == -1) XSRETURN_UNDEF;
    OUTPUT:
	RETVAL

void
tdb_unlockall(tdb)
	TDB_CONTEXT *	tdb

void
tdb_unlockkeys(tdb)
	TDB_CONTEXT *	tdb
