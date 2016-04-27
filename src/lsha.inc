#ifndef LSHA_INC_FIRST
#define LSHA_INC_FIRST

#include "lua.h"
#include "sha1.h"
#include "sha2.h"
#include "hmac.h"
#include "l52util.h"
#include <assert.h>
#include <memory.h>

#define FLAG_TYPE      unsigned char
#define FLAG_DESTROYED (FLAG_TYPE)1 << 0
#define FLAG_OPEN      (FLAG_TYPE)1 << 1
#define FLAG_DECRYPT   (FLAG_TYPE)1 << 2

#define CTX_FLAG(ctx, f) (ctx->flags & FLAG_##f)

static int fail(lua_State *L, const char *msg){
  lua_pushnil(L);
  lua_pushstring(L, msg);
  return 2;
}

static int pass(lua_State *L){
  lua_pushboolean(L, 1);
  return 1;
}

/* return [ buffer[be], buffer[en] ] */
static const char* correct_range(lua_State *L, int idx, size_t *size){
  if(lua_islightuserdata(L, idx)){
    /* (ud, [offset=1,] size) */
    const char *input = (const char*)lua_touserdata(L, idx);
    int of, sz;

    if(lua_isnumber(L, idx + 1) && lua_isnumber(L, idx + 2)){
      of = lua_tointeger(L, idx + 1);
      sz = lua_tointeger(L, idx + 2);
      lua_remove(L, idx + 1);
      lua_remove(L, idx + 1);
    }
    else{
      of = 1;
      sz = luaL_checkinteger(L, idx + 1);
      lua_remove(L, idx + 1);
    }

    luaL_argcheck(L, of >  0, idx+1, "invalid offset");
    luaL_argcheck(L, sz >= 0, idx+2, "invalid size"  );

    *size = sz;
    return input + of - 1;
  }

  else{
    /* (str, [be=1[, size=(#str-be+1)]]) */
    size_t len; const char *input = luaL_checklstring(L, idx, &len);
    int be, sz;
    if(lua_isnumber(L, idx+1)){
      be = lua_tointeger(L, idx+1);
      lua_remove(L, idx+1);
      luaL_argcheck(L, be > 0, idx+1, "invalid begin index");
    }else be = 1;

    if(lua_isnumber(L, idx+1)){
      sz = lua_tointeger(L, idx+1);
      lua_remove(L, idx+1);
      luaL_argcheck(L, sz >= 0, idx+2, "invalid size");
    }else sz = len;

    if((size_t)be > len){
      *size = 0;
      return input;
    }

    len = len - be + 1;

    if((size_t)sz > len) sz = len;

    *size = sz;
    return input + be - 1;
  }
}

static const char* opt_correct_range(lua_State *L, int idx, size_t *size){
  if( lua_isstring(L, idx) || lua_islightuserdata(L, idx) )
    return correct_range(L, idx, size);
  return NULL;
}

static const char HEX_DIGEST[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

#endif

#define CAT2_IMPL(A, B) A ## B
#define CAT2(A, B) CAT2_IMPL(A, B)

#define CAT3_IMPL(A, B, C) A ## B ## C
#define CAT3(A, B, C) CAT3_IMPL(A, B, C)

#define CAT4_IMPL(A, B, C, D) A ## B ## C ## D
#define CAT4(A, B, C, D) CAT4_IMPL(A, B, C, D)

#define CAT5_IMPL(A, B, C, D, E) A ## B ## C ## D ## E
#define CAT5(A, B, C, D, E) CAT5_IMPL(A, B, C, D, E)

#define SHA_NAME_BASE(P, N) CAT4(P, L_SHA_MODE_BASE, _, N)
#define SHA_NAME(P, N) CAT4(P, L_SHA_MODE, _, N)
#define HMAC_NAME(P, N) CAT5(P, _sha, L_SHA_MODE, _, N)

#define QSTR_IMPL(A) #A

#define QSTR(A) QSTR_IMPL(A)

#define L_SHA_NAME "SHA " QSTR(L_SHA_MODE) "context"

#define L_HMAC_NAME "HMAC SHA " QSTR(L_SHA_MODE) "context"

//{ SHA

static void SHA_NAME(l_sha,push_hex)(lua_State *L, unsigned char buffer[]){
  int i;
  char tmp[2 * SHA_NAME(SHA, DIGEST_SIZE)];
  for(i = 0; i < SHA_NAME(SHA, DIGEST_SIZE); ++i){
    unsigned char c = buffer[i];
    tmp[(i<<1) + 1] = HEX_DIGEST[( c     & 0x0F)];
    tmp[(i<<1)    ] = HEX_DIGEST[((c>>4) & 0x0F)];
  }
  lua_pushlstring(L, tmp, 2 * SHA_NAME(SHA, DIGEST_SIZE));
}

static const char * SHA_NAME(L_SHA, CTX) = L_SHA_NAME;

typedef struct SHA_NAME(l_sha, ctx_tag){
  FLAG_TYPE flags;
  SHA_NAME_BASE(sha, ctx) ctx[1];
} SHA_NAME(l_sha,ctx);

static SHA_NAME(l_sha,ctx) *SHA_NAME(l_get_sha,at) (lua_State *L, int i) {
  SHA_NAME(l_sha,ctx) *ctx = (SHA_NAME(l_sha,ctx) *)lutil_checkudatap (L, i, SHA_NAME(L_SHA,CTX));
  luaL_argcheck (L, ctx != NULL, 1, L_SHA_NAME " expected");
  luaL_argcheck (L, !(ctx->flags & FLAG_DESTROYED), 1, L_SHA_NAME " is destroyed");
  return ctx;
}

static int SHA_NAME(l_sha,new)(lua_State *L){
  SHA_NAME(l_sha,ctx) *ctx = lutil_newudatap(L, SHA_NAME(l_sha,ctx), SHA_NAME(L_SHA,CTX));
  memset(ctx, 0, sizeof(SHA_NAME(l_sha,ctx)));

  SHA_NAME(sha,begin)(ctx->ctx);

  return 1;
}

static int SHA_NAME(l_sha,clone)(lua_State *L){
  SHA_NAME(l_sha,ctx) *src = (SHA_NAME(l_sha,ctx) *)lutil_checkudatap (L, 1, SHA_NAME(L_SHA,CTX));
  SHA_NAME(l_sha,ctx) *dst = lutil_newudatap(L, SHA_NAME(l_sha,ctx), SHA_NAME(L_SHA,CTX));
  memset(dst, 0, sizeof(SHA_NAME(l_sha,ctx)));

  memcpy(dst->ctx, src->ctx, sizeof(SHA_NAME_BASE(sha,ctx)));

  return 1;
}

static int SHA_NAME(l_sha,tostring)(lua_State *L){
  SHA_NAME(l_sha,ctx) *ctx = (SHA_NAME(l_sha,ctx) *)lutil_checkudatap (L, 1, SHA_NAME(L_SHA,CTX));
  lua_pushfstring(L, L_SHA_NAME " (%s): %p",
    CTX_FLAG(ctx, DESTROYED)?"destroy":"open",
    ctx
  );
  return 1;
}

static int SHA_NAME(l_sha,destroy)(lua_State *L){
  SHA_NAME(l_sha,ctx) *ctx = (SHA_NAME(l_sha,ctx) *)lutil_checkudatap (L, 1, SHA_NAME(L_SHA,CTX));
  luaL_argcheck (L, ctx != NULL, 1, L_SHA_NAME " expected");

  if(ctx->flags & FLAG_DESTROYED) return 0;

  ctx->flags |= FLAG_DESTROYED;
  return 0;
}

static int SHA_NAME(l_sha,destroyed)(lua_State *L){
  SHA_NAME(l_sha,ctx) *ctx = (SHA_NAME(l_sha,ctx) *)lutil_checkudatap (L, 1, SHA_NAME(L_SHA,CTX));
  luaL_argcheck (L, ctx != NULL, 1, L_SHA_NAME " expected");
  lua_pushboolean(L, ctx->flags & FLAG_DESTROYED);
  return 1;
}

static int SHA_NAME(l_sha,update)(lua_State *L){
  SHA_NAME(l_sha,ctx) *ctx = SHA_NAME(l_get_sha,at)(L, 1);
  size_t len; const unsigned char *data = (unsigned char *)correct_range(L, 2, &len);

  SHA_NAME(sha,hash)(data, len, ctx->ctx);

  lua_settop(L, 1);
  return 1;
}

static int SHA_NAME(l_sha,reset)(lua_State *L){
  SHA_NAME(l_sha,ctx) *ctx = SHA_NAME(l_get_sha,at)(L, 1);

  SHA_NAME(sha,begin)(ctx->ctx);

  lua_settop(L, 1);
  return 1;
}

static int SHA_NAME(l_sha,digest)(lua_State *L){
  SHA_NAME(l_sha,ctx) *ctx = SHA_NAME(l_get_sha,at)(L, 1);
  unsigned char buffer[SHA_NAME(SHA,DIGEST_SIZE)];
  SHA_NAME_BASE(sha,ctx) sctx[1];

  { /*last chunk*/
    size_t len; const unsigned char *data = (unsigned char *)opt_correct_range(L, 2, &len);
    if(data){
      SHA_NAME(sha,hash)(data, len, ctx->ctx);
      lua_remove(L, 2);
    }
  }

  memcpy(&sctx[0], &ctx->ctx[0], sizeof(SHA_NAME_BASE(sha,ctx)));

  SHA_NAME(sha,end)(buffer, sctx);

  if(lua_toboolean(L, 2)){ /* as text */
    SHA_NAME(l_sha,push_hex)(L, buffer);
    return 1;
  }

  lua_pushlstring(L, (char*)buffer, SHA_NAME(SHA,DIGEST_SIZE));
  return 1;
}

static int SHA_NAME(l_sha,hash)(lua_State *L){
  SHA_NAME_BASE(sha,ctx) ctx[1];
  unsigned char buffer[SHA_NAME(SHA,DIGEST_SIZE)];
  size_t len; const unsigned char *data = (unsigned char *)correct_range(L, 1, &len);

  SHA_NAME(sha,begin)(ctx);

  SHA_NAME(sha,hash)(data, len, ctx);

  SHA_NAME(sha,end)(buffer, ctx);

  if(lua_toboolean(L, 2)){ /* as text */
    SHA_NAME(l_sha,push_hex)(L, buffer);
    return 1;
  }

  lua_pushlstring(L, (char*)buffer, SHA_NAME(SHA,DIGEST_SIZE));
  return 1;
}

static const struct luaL_Reg SHA_NAME(l_sha, meth)[] = {
  {"__gc",       SHA_NAME(l_sha,destroy)     },
  {"__tostring", SHA_NAME(l_sha,tostring)    },
  {"destroy",    SHA_NAME(l_sha,destroy)     },
  {"destroyed",  SHA_NAME(l_sha,destroyed)   },
  {"update",     SHA_NAME(l_sha,update)      },
  {"digest",     SHA_NAME(l_sha,digest)      },
  {"reset",      SHA_NAME(l_sha,reset)       },
  {"clone",      SHA_NAME(l_sha,clone)       },

  {NULL, NULL}
};

//}

//{ HMAC

#define L_HMAC_HASH_ID CAT2(HMAC_SHA, L_SHA_MODE)

static const char * HMAC_NAME(L_HMAC, CTX) = L_HMAC_NAME;

typedef struct HMAC_NAME(l_hmac,ctx_tag){
  FLAG_TYPE flags;
  hmac_ctx ctx[1];
} HMAC_NAME(l_hmac,ctx);

static HMAC_NAME(l_hmac,ctx) *HMAC_NAME(l_get_hmac,at) (lua_State *L, int i) {
  HMAC_NAME(l_hmac,ctx) *ctx = (HMAC_NAME(l_hmac,ctx) *)lutil_checkudatap (L, i, HMAC_NAME(L_HMAC,CTX));
  luaL_argcheck (L, ctx != NULL, 1, L_HMAC_NAME " expected");
  luaL_argcheck (L, !(ctx->flags & FLAG_DESTROYED), 1, L_HMAC_NAME " is destroyed");
  return ctx;
}

static int HMAC_NAME(l_hmac,new)(lua_State *L){
  HMAC_NAME(l_hmac,ctx) *ctx = lutil_newudatap(L, HMAC_NAME(l_hmac,ctx), HMAC_NAME(L_HMAC,CTX));
  size_t len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 1, &len);

  memset(ctx, 0, sizeof(HMAC_NAME(l_hmac,ctx)));

  hmac_sha_begin(L_HMAC_HASH_ID, ctx->ctx);
  hmac_sha_key(key, len, ctx->ctx);

  return 1;
}

static int HMAC_NAME(l_hmac,clone)(lua_State *L){
  HMAC_NAME(l_hmac,ctx) *src = (HMAC_NAME(l_hmac,ctx) *)lutil_checkudatap (L, 1, HMAC_NAME(L_HMAC,CTX));
  HMAC_NAME(l_hmac,ctx) *dst = lutil_newudatap(L, HMAC_NAME(l_hmac,ctx), HMAC_NAME(L_HMAC,CTX));
  memset(dst, 0, sizeof(HMAC_NAME(l_hmac,ctx)));

  memcpy(dst->ctx, src->ctx, sizeof(hmac_ctx));

  return 1;
}

static int HMAC_NAME(l_hmac,tostring)(lua_State *L){
  HMAC_NAME(l_hmac,ctx) *ctx = (HMAC_NAME(l_hmac,ctx) *)lutil_checkudatap (L, 1, HMAC_NAME(L_HMAC,CTX));
  lua_pushfstring(L, L_HMAC_NAME " (%s): %p",
    CTX_FLAG(ctx, DESTROYED)?"destroy":"open",
    ctx
  );
  return 1;
}

static int HMAC_NAME(l_hmac,destroy)(lua_State *L){
  HMAC_NAME(l_hmac,ctx) *ctx = (HMAC_NAME(l_hmac,ctx) *)lutil_checkudatap (L, 1, HMAC_NAME(L_HMAC,CTX));
  luaL_argcheck (L, ctx != NULL, 1, L_HMAC_NAME " expected");

  if(ctx->flags & FLAG_DESTROYED) return 0;

  ctx->flags |= FLAG_DESTROYED;
  return 0;
}

static int HMAC_NAME(l_hmac,destroyed)(lua_State *L){
  HMAC_NAME(l_hmac,ctx) *ctx = (HMAC_NAME(l_hmac,ctx) *)lutil_checkudatap (L, 1, HMAC_NAME(L_HMAC,CTX));
  luaL_argcheck (L, ctx != NULL, 1, L_HMAC_NAME " expected");
  lua_pushboolean(L, ctx->flags & FLAG_DESTROYED);
  return 1;
}

static int HMAC_NAME(l_hmac,update)(lua_State *L){
  HMAC_NAME(l_hmac,ctx) *ctx = HMAC_NAME(l_get_hmac,at)(L, 1);
  size_t len; const unsigned char *data = (unsigned char *)correct_range(L, 2, &len);

  hmac_sha_data(data, len, ctx->ctx);

  lua_settop(L, 1);
  return 1;
}

static int HMAC_NAME(l_hmac,reset)(lua_State *L){
  HMAC_NAME(l_hmac,ctx) *ctx = HMAC_NAME(l_get_hmac,at)(L, 1);

  if(lua_gettop(L) > 1){
    size_t len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &len);
    hmac_sha_begin(L_HMAC_HASH_ID, ctx->ctx);
    hmac_sha_key(key, len, ctx->ctx);
  }
  else{
    /* This code based on implementation in `hmac.c` */
    /* Also it is important to does not call hmac_sha_end to this ctx*/
    unsigned char key[ sizeof(ctx->ctx->key) ];
    unsigned long klen = ctx->ctx->klen;
    memcpy(key, ctx->ctx->key, sizeof(ctx->ctx->key));

    hmac_sha_begin(L_HMAC_HASH_ID, ctx->ctx);
    memcpy(ctx->ctx->key, key, sizeof(ctx->ctx->key));
    ctx->ctx->klen = klen;
    if(klen == HMAC_IN_DATA){
      SHA_NAME(sha,begin)(&ctx->ctx->sha_ctx->CAT2(u_sha, L_SHA_MODE_BASE));
      hmac_sha_data(key, ctx->ctx->input_len, ctx->ctx);
    }
  }

  lua_settop(L, 1);
  return 1;
}

static int HMAC_NAME(l_hmac,digest)(lua_State *L){
  HMAC_NAME(l_hmac,ctx) *ctx = HMAC_NAME(l_get_hmac,at)(L, 1);
  unsigned char buffer[SHA_NAME(SHA, DIGEST_SIZE)];
  hmac_ctx sctx[1];

  { /*last chunk*/
    size_t len; const unsigned char *data = (unsigned char *)opt_correct_range(L, 2, &len);
    if(data){
      hmac_sha_data(data, len, ctx->ctx);
      lua_remove(L, 2);
    }
  }

  memcpy(&sctx[0], &ctx->ctx[0], sizeof(hmac_ctx));

  hmac_sha_end(buffer, sizeof(buffer), sctx);

  if(lua_toboolean(L, 2)){ /* as text */
    SHA_NAME(l_sha,push_hex)(L, buffer);
    return 1;
  }

  lua_pushlstring(L, (char*)buffer, sizeof(buffer));
  return 1;
}

static int HMAC_NAME(l_hmac,hash)(lua_State *L){
  hmac_ctx ctx[1];
  unsigned char buffer[SHA_NAME(SHA, DIGEST_SIZE)];
  size_t key_len;  const unsigned char *key  = (unsigned char *)luaL_checklstring(L, 1, &key_len);
  size_t data_len; const unsigned char *data = (unsigned char *)correct_range(L, 2, &data_len);

  hmac_sha_begin(L_HMAC_HASH_ID, ctx);
  hmac_sha_key(key, key_len, ctx);
  hmac_sha_data(data, data_len, ctx);
  hmac_sha_end(buffer, sizeof(buffer), ctx);

  if(lua_toboolean(L, 3)){ /* as text */
    SHA_NAME(l_sha,push_hex)(L, buffer);
    return 1;
  }

  lua_pushlstring(L, (char*)buffer, sizeof(buffer));
  return 1;
}

static const struct luaL_Reg HMAC_NAME(l_hmac, meth)[] = {
  {"__gc",       HMAC_NAME(l_hmac,destroy)     },
  {"__tostring", HMAC_NAME(l_hmac,tostring)    },
  {"destroy",    HMAC_NAME(l_hmac,destroy)     },
  {"destroyed",  HMAC_NAME(l_hmac,destroyed)   },
  {"update",     HMAC_NAME(l_hmac,update)      },
  {"digest",     HMAC_NAME(l_hmac,digest)      },
  {"reset",      HMAC_NAME(l_hmac,reset)       },
  {"clone",      HMAC_NAME(l_hmac,clone)       },

  {NULL, NULL}
};

//}

//{ PBKDF2

#define derive_key      CAT3(pbkdf2, _sha, L_SHA_MODE)

#if L_SHA_MODE_BASE != 1
# define HMAC_SHA1 CAT2(HMAC_SHA, L_SHA_MODE)
#endif

#include "pwd2key.c"

#if L_SHA_MODE_BASE != 1
# undef HMAC_SHA1
#endif

static int SHA_NAME(l_sha, pbkdf2)(lua_State *L){
  unsigned char buffer[512];

  size_t pwd_len;  const unsigned char *pwd  = (unsigned char *)luaL_checklstring(L, 1, &pwd_len );
  size_t salt_len; const unsigned char *salt = (unsigned char *)luaL_checklstring(L, 2, &salt_len);
  unsigned int iter    = (unsigned int) luaL_checkinteger(L, 3);
  unsigned int key_len = (unsigned int) luaL_checkinteger(L, 4);
  unsigned char *key = buffer;

  if(key_len > sizeof(buffer)){
    key = (unsigned char *)malloc(key_len);
    if(!key){
      lua_pushstring(L, "malloc error");
      return lua_error(L);
    }
  }

  derive_key(pwd, pwd_len, salt, salt_len, iter, key, key_len);

  lua_pushlstring(L, (char*)key, key_len);

  if(key != buffer){
    free(key);
  }

  return 1;
}

#undef derive_key

//}

static const struct luaL_Reg SHA_NAME(l_sha,lib)[] = {
  {"new",    SHA_NAME(l_sha, new)    },
  {"digest", SHA_NAME(l_sha, hash)   },
  {"pbkdf2", SHA_NAME(l_sha, pbkdf2) },
  {NULL, NULL}
};

static const struct luaL_Reg HMAC_NAME(l_hmac,lib)[] = {
  {"new",    HMAC_NAME(l_hmac, new)  },
  {"digest", HMAC_NAME(l_hmac, hash) },
  {NULL, NULL}
};

LUTL_EXPORT int CAT2(luaopen_bgcrypto_sha, L_SHA_MODE) (lua_State*L){
  int top = lua_gettop(L);
  lutil_createmetap(L, SHA_NAME(L_SHA, CTX), SHA_NAME(l_sha,meth),0);
  lutil_createmetap(L, HMAC_NAME(L_HMAC, CTX), HMAC_NAME(l_hmac,meth),0);
  lua_settop(L, top);

  lua_newtable(L);
  luaL_setfuncs(L, SHA_NAME(l_sha,lib), 0);
  lua_newtable(L);
  luaL_setfuncs(L, HMAC_NAME(l_hmac,lib), 0);
  lua_pushnumber(L, SHA_NAME(SHA,DIGEST_SIZE)); lua_setfield(L, -2, "DIGEST_SIZE");
  lua_pushnumber(L, SHA_NAME(SHA,BLOCK_SIZE)); lua_setfield(L, -2,  "BLOCK_SIZE");
  lua_setfield(L, -2, "hmac");

  lua_pushnumber(L, SHA_NAME(SHA,DIGEST_SIZE)); lua_setfield(L, -2, "DIGEST_SIZE");

  lua_pushnumber(L, SHA_NAME(SHA,BLOCK_SIZE)); lua_setfield(L, -2,  "BLOCK_SIZE");

  assert(lua_gettop(L) == (top+1));
  return 1;
}


#undef L_HMAC_HASH_ID

#undef L_SHA_NAME
#undef CAT2
#undef CAT2_IMPL
#undef CAT3
#undef CAT3_IMPL
#undef CAT4
#undef CAT4_IMPL
#undef CAT5
#undef CAT5_IMPL
#undef SHA_NAME_BASE
#undef SHA_NAME
#undef QSTR_IMPL
#undef QSTR

