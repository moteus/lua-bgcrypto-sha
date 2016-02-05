package = "bgcrypto-sha"
version = "scm-0"

source = {
  url = "https://github.com/moteus/lua-bgcrypto-sha/archive/master.zip",
  dir = "lua-bgcrypto-sha-master",
}

description = {
  summary  = "SHA1/SHA2 digest library",
  homepage = "https://github.com/moteus/bgcrypto-sha",
  detailed = [[Binding to Dr Brian Gladman's implementation of SHA/HMAC algorithm.]];
  -- license = "MIT/X11",
}

dependencies = {
  "lua >= 5.1, < 5.4",
  -- "bit32",
}

local function make_module()
  local result = {}
  local names = {'sha1','sha224','sha256','sha384','sha512'}
  for i = 1, #names do
    local name = names[i]
    result['bgcrypto.' .. name] = {
      sources = {
        'src/l52util.c', 'src/sha/sha1.c', 'src/sha/sha2.c',
        'src/l' .. name ..'.c'
      },
      incdirs = {'src/sha'},
    }
  end
  return result
end

build = {
  copy_directories = {"test"},

  type = "builtin",

  platforms = {
    windows = { modules = {
      ['bgcrypto.sha1'  ] = { defines = {'DLL_EXPORT'} },
      ['bgcrypto.sha224'] = { defines = {'DLL_EXPORT'} },
      ['bgcrypto.sha256'] = { defines = {'DLL_EXPORT'} },
      ['bgcrypto.sha384'] = { defines = {'DLL_EXPORT'} },
      ['bgcrypto.sha512'] = { defines = {'DLL_EXPORT'} },
    }},
  },

  modules = make_module();
}

