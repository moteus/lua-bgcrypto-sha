#define L_SHA_MODE 1
#define L_SHA_MODE_BASE 1
#include "lsha.inc"
#undef L_SHA_MODE_BASE
#undef L_SHA_MODE

#define L_SHA_MODE 224
#define L_SHA_MODE_BASE 224
#include "lsha.inc"
#undef L_SHA_MODE_BASE
#undef L_SHA_MODE

#define L_SHA_MODE 256
#define L_SHA_MODE_BASE 256
#include "lsha.inc"
#undef L_SHA_MODE_BASE
#undef L_SHA_MODE

#define L_SHA_MODE 384
#define L_SHA_MODE_BASE 384
#include "lsha.inc"
#undef L_SHA_MODE_BASE
#undef L_SHA_MODE

#define L_SHA_MODE 512
#define L_SHA_MODE_BASE 512
#include "lsha.inc"
#undef L_SHA_MODE_BASE
#undef L_SHA_MODE

#define L_SHA_MODE 512_128
#define L_SHA_MODE_BASE 512
#include "lsha.inc"
#undef L_SHA_MODE_BASE
#undef L_SHA_MODE

#define L_SHA_MODE 512_192
#define L_SHA_MODE_BASE 512
#include "lsha.inc"
#undef L_SHA_MODE_BASE
#undef L_SHA_MODE

#define L_SHA_MODE 512_224
#define L_SHA_MODE_BASE 512
#include "lsha.inc"
#undef L_SHA_MODE_BASE
#undef L_SHA_MODE

#define L_SHA_MODE 512_256
#define L_SHA_MODE_BASE 512
#include "lsha.inc"
#undef L_SHA_MODE_BASE
#undef L_SHA_MODE

LUTL_EXPORT int luaopen_bgcrypto_sha(lua_State*L){
  lua_newtable(L);
  luaopen_bgcrypto_sha1  (L);     lua_setfield(L, -2, "sha1"  );
  luaopen_bgcrypto_sha224(L);     lua_setfield(L, -2, "sha224");
  luaopen_bgcrypto_sha256(L);     lua_setfield(L, -2, "sha256");
  luaopen_bgcrypto_sha384(L);     lua_setfield(L, -2, "sha384");
  luaopen_bgcrypto_sha512(L);     lua_setfield(L, -2, "sha512");
  luaopen_bgcrypto_sha512_128(L); lua_setfield(L, -2, "sha512_128");
  luaopen_bgcrypto_sha512_192(L); lua_setfield(L, -2, "sha512_192");
  luaopen_bgcrypto_sha512_224(L); lua_setfield(L, -2, "sha512_224");
  luaopen_bgcrypto_sha512_256(L); lua_setfield(L, -2, "sha512_256");

  return 1;
}
