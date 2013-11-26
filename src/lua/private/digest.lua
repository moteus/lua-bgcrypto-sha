-- Use `digest` library http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/install.html

local hmac = require "bgcrypto.hmac"
local hmac_hash = hmac.digest
local hmac_new  = hmac.new

-- md5 / ripemd160
local function require_digest(ALGO)
  local ALGO       = require(ALGO)
  local BLOCK_SIZE = 64

  local function digest(msg, text)
    return ALGO.digest(msg, not text)
  end;

  local hash = {} do
  hash.__index = hash

  function hash_new_(self, ctx)
    local o = setmetatable({
      private_ = {
        ctx = assert(ctx);
      }
    },self)

    return o
  end

  function hash:new()
    return hash_new_(hash, ALGO.new())
  end

  function hash:clone()
    return hash_new_(hash, self.private_.ctx:clone())
  end

  function hash:reset()
    self.private_.ctx = ALGO.new()
  end

  function hash:destroy()
    if not self.private_ then return end
    self.private_.ctx = nil
    self.private_ = nil
  end

  function hash:destroyed()
    return not self.private_
  end

  function hash:update(value, i, size)
    if type(i) == 'number' then
      if type(size) ~= 'number' then
        size, text = #value, not not size
      end
      value = string.sub(value, i, i + size - 1)
    end

    return self.private_.ctx:update(value)
  end

  function hash:digest(value, i, size, text)
    if type(value) == 'string' then
      if type(i) ~= 'number' then text = not not i
      else
        if type(size) ~= 'number' then
          size, text = #value, not not size
        end
        value = string.sub(value, i, i + size - 1)
      end
      self.private_.ctx:update(value)
    else
      text = not not value
    end
    return self.private_.ctx:digest(not text)
  end

  end

  local HASH = {
    BLOCK_SIZE = BLOCK_SIZE;
    digest = digest;
    new    = function(...) return hash:new(...) end;
  }

  HASH.hmac = {
    digest = function(...) return hmac_hash(HASH, ...) end;
    new    = function(...) return hmac_new (HASH, ...) end;
  }

  return HASH
end

return require_digest
