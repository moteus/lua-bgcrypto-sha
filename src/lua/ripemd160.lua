-- Use `digest` library http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/install.html
local digest = require "bgcrypto.private.digest"
return digest('ripemd160')
