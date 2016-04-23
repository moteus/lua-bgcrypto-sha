#ifndef _LZUTILS_H_9B43D914_9652_4E22_9A43_8073502BF3F4_
#define _LZUTILS_H_9B43D914_9652_4E22_9A43_8073502BF3F4_

#include "lua.h"
#include "lauxlib.h"

#ifndef LUTL_EXPORT
#  ifdef DLL_IMPORT
#    ifdef _WIN32
#      if defined( _MSC_VER ) || defined ( __INTEL_COMPILER )
#        define LUTL_EXPORT     __declspec( dllimport )
#      elif defined( __GNUC__ )
#        define LUTL_EXPORT     __declspec( __dllimport__ )
#      else
#         define LUTL_EXPORT
#      endif
#    else
#      define LUTL_EXPORT
#    endif
#  else
#    ifdef _WIN32
#      if defined( _MSC_VER ) || defined ( __INTEL_COMPILER )
#        define LUTL_EXPORT     __declspec( dllexport )
#      elif defined( __GNUC__ )
#        define LUTL_EXPORT     __declspec( __dllexport__ )
#      else
#         define LUTL_EXPORT
#      endif
#    else
#       define LUTL_EXPORT
#    endif
#  endif
#endif

#if LUA_VERSION_NUM >= 502 // lua 5.2

#ifndef lua_objlen
#  define lua_objlen      lua_rawlen
#endif

int   luaL_typerror (lua_State *L, int narg, const char *tname);

#ifndef luaL_register
void luaL_register (lua_State *L, const char *libname, const luaL_Reg *l);
#endif

#ifndef lua_equal
#  define lua_equal(L,idx1,idx2) lua_compare(L,(idx1),(idx2),LUA_OPEQ)
#endif

#else                      // lua 5.1

// functions form lua 5.2

# define lua_absindex(L, i) (((i)>0)?(i):((i)<=LUA_REGISTRYINDEX?(i):(lua_gettop(L)+(i)+1)))

void  lua_rawgetp   (lua_State *L, int index, const void *p);
void  lua_rawsetp   (lua_State *L, int index, const void *p);
void  luaL_setfuncs  (lua_State *L, const luaL_Reg *l, int nup);

#endif

int   lutil_newmetatablep (lua_State *L, const void *p);
void  lutil_getmetatablep (lua_State *L, const void *p);
void  lutil_setmetatablep (lua_State *L, const void *p);

#define lutil_newudatap(L, TTYPE, TNAME) (TTYPE *)lutil_newudatap_impl(L, sizeof(TTYPE), TNAME)
int   lutil_isudatap      (lua_State *L, int ud, const void *p);
void *lutil_checkudatap   (lua_State *L, int ud, const void *p);
int   lutil_createmetap   (lua_State *L, const void *p, const luaL_Reg *methods, int nup);

void *lutil_newudatap_impl     (lua_State *L, size_t size, const void *p);

#endif

