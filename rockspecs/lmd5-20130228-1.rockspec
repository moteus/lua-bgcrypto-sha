package="lmd5"
version="20130228-1"

source = {
   url = "http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/5.1/lmd5.tar.gz",
   dir = "md5"
}

description = {
   summary = "A message digest library for Lua.",
   detailed = [[
      A message digest library for Lua based on OpenSSL.
      It supports MD2, MD4, MD5, SHA1, SHA2, RIPEMD160, MDC2.
   ]],
   homepage = "http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/#lmd5",
   license = "Public domain"
}

dependencies = {
   "lua ~> 5.1"
}

external_dependencies = {
  OPENSSL = {
   header = "openssl/opensslv.h"
  }
}



local function make_module()
  local result = {}
  local names = {
    --[['md2',]]'md4','md5','sha1','sha224','sha256','sha384','sha512','ripemd160'--[[,'mdc2']]
  }
  local UNAME = {
    --[['MD2',]]'MD4','MD5','SHA1','SHA224','SHA256','SHA384','SHA512','RIPEMD160'--[[,'MDC2']]
  }
  for i = 1, #names do
    local name = names[i]
    result[name] = {
      sources = {'lmd5.c'},
      defines = {'USE_' .. UNAME[i] .. '_OPENSSL'},
      incdirs = {'$(OPENSSL_INCDIR)'},
      libdirs = {'$(OPENSSL_LIBDIR)'},
      -- libraries = {'libeay32', 'ssleay32'}, -- windows
      libraries = {'crypto'}, -- *nix
    }
  end
  return result
end

build = {
   type = 'builtin',
   modules = make_module(),
}


