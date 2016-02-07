package = "bgcrypto-lmd5"
version = "scm-0"

source = {
  url = "https://github.com/moteus/lua-bgcrypto-sha/archive/master.zip",
  dir = "lua-bgcrypto-sha-master",
}

description = {
  summary  = "Wraps digest implementation from `lmd5` library.",
  homepage = "https://github.com/moteus/bgcrypto-sha",
  detailed = [[Provide bgcrypto.digest interface and implement hmac/pbkdf2 functions.]];
  license = "MIT/X11",
}

dependencies = {
  "lua >= 5.1, < 5.4",
  "lmd5",
  "bgcrypto-hmac",
  "bgcrypto-pbkdf2",
}

build = {
  copy_directories = {},

  type = "builtin",

  modules = {
    ['bgcrypto.private.digest'] = 'src/lua/private/digest.lua',
    ['bgcrypto.md5']            = 'src/lua/md5.lua',
    ['bgcrypto.ripemd160']      = 'src/lua/ripemd160.lua',
  };
}

