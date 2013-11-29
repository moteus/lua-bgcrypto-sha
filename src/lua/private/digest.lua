-- Use `digest` library http://www.tecgraf.puc-rio.br/~lhf/ftp/lua/install.html

local hmac   = require "bgcrypto.hmac"
local pbkdf2 = require "bgcrypto.pbkdf2"
local hmac_hash = hmac.digest
local hmac_new  = hmac.new

local BLOCK_SIZE  = {
  md2       = 64,
  md4       = 64,
  md5       = 64,
  sha1      = 16,
  sha224    = 16,
  sha256    = 16,
  sha384    = 16,
  sha512    = 16,
  ripemd160 = 64,
}

local DIGEST_SIZE = {
  md2       = 16,
  md4       = 16,
  md5       = 16,
  sha1      = 20,
  sha224    = 28,
  sha256    = 32,
  sha384    = 48,
  sha512    = 64,
  ripemd160 = 20,
}

local function require_digest(ALGO)
  local BLOCK_SIZE  = assert(BLOCK_SIZE [ALGO])
  local DIGEST_SIZE = assert(DIGEST_SIZE[ALGO])
  local ALGO        = require(ALGO)

  local function digest(value, i, size, text)
    if type(i) ~= 'number' then text = not not i
    else
      if type(size) ~= 'number' then
        size, text = #value, not not size
      end
      assert(i > 0)
      assert(size >= 0)
      value = string.sub(value, i, i + size - 1)
    end

    return ALGO.digest(value, not text)
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
    return self
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

    local ok, err = self.private_.ctx:update(value)
    if ok then return self end
    return ok, err
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
    BLOCK_SIZE  = BLOCK_SIZE;
    DIGEST_SIZE = DIGEST_SIZE;
    digest = digest;
    new    = function(...) return hash:new(...) end;
  }

  HASH.pbkdf2 = function (...) return pbkdf2(HASH, ...) end

  HASH.hmac = {
    BLOCK_SIZE  = BLOCK_SIZE;
    DIGEST_SIZE = DIGEST_SIZE;
    digest = function(...) return hmac_hash(HASH, ...) end;
    new    = function(...) return hmac_new (HASH, ...) end;
  }

  return HASH
end

return require_digest
