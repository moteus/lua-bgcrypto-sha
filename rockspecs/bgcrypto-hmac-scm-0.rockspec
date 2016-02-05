package = "bgcrypto-hmac"
version = "scm-0"

source = {
  url = "https://github.com/moteus/lua-bgcrypto-sha/archive/master.zip",
  dir = "lua-bgcrypto-sha-master",
}

description = {
  summary  = "Keyed-Hashing for Message Authentication",
  homepage = "https://github.com/moteus/bgcrypto-sha",
  detailed = [[Work with SHA1/SHA2/MD5/RIPEMD160/etc. hash algorithms.]];
  license = "MIT/X11",
}

dependencies = {
  "lua >= 5.1, < 5.4",
  -- "bit32",
}

build = {
  copy_directories = {},

  type = "builtin",

  modules = {
    ['bgcrypto.hmac']   = 'src/lua/hmac.lua'
  }
}

