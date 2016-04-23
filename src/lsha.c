// #define SHA_1
// #define SHA_224 
// #define SHA_256
// #define SHA_384
// #define SHA_512

#define L_SHA_MODE 1
#include "lsha.inc"
#undef L_SHA_MODE

#define L_SHA_MODE 224
#include "lsha.inc"
#undef L_SHA_MODE

#define L_SHA_MODE 256
#include "lsha.inc"
#undef L_SHA_MODE

#define L_SHA_MODE 384
#include "lsha.inc"
#undef L_SHA_MODE

#define L_SHA_MODE 512
#include "lsha.inc"
#undef L_SHA_MODE

LUTL_EXPORT int luaopen_bgcrypto_sha(lua_State*L){
  lua_newtable(L);
  luaopen_bgcrypto_sha1  (L); lua_setfield(L, -2, "sha1"  );
  luaopen_bgcrypto_sha224(L); lua_setfield(L, -2, "sha224");
  luaopen_bgcrypto_sha256(L); lua_setfield(L, -2, "sha256");
  luaopen_bgcrypto_sha384(L); lua_setfield(L, -2, "sha384");
  luaopen_bgcrypto_sha512(L); lua_setfield(L, -2, "sha512");

  return 1;
}
