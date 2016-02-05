local bit = require "bgcrypto.private.bit"

local sbyte = string.byte
local schar = string.char
local sgsub = string.gsub
local ssub  = string.sub
local srep  = string.rep
local bxor  = bit.bxor

local function hmac_xor(str, b)
  return sgsub(str, '.', function(ch)
    return schar(bxor(sbyte(ch), b))
  end)
end

local function hmac_key(hash, key)
  if #key > hash.BLOCK_SIZE then key = hash.digest(key) end
  key = key .. srep('\0', hash.BLOCK_SIZE - #key)
  return key, hmac_xor(key, 54), hmac_xor(key, 92)
end

local function hmac_hash(hash, key, value, i, size, text)
  local key, ipad, opad = hmac_key(hash, key)

  if type(i) ~= 'number' then text = not not i
  else
    if type(size) ~= 'number' then
      size, text = #value, not not size
    end
    value = ssub(value, i, i + size - 1)
  end

  return hash.digest( opad .. hash.digest(ipad .. value), text)
end

local hmac = {} do 
hmac.__index = hmac

function hmac:new(hash, key)
  assert(type(key) == 'string')
  local o = setmetatable({
    private_ = {
      hash = hash;
      hctx = hash.new();
    }
  },self)
  o:reset(key)
  return o
end

function hmac:clone()
  local o = setmetatable({
    private_ = {
      hash = self.private_.hash;
      hctx = self.private_.hctx:clone();
      ipad = self.private_.ipad;
      opad = self.private_.opad;
    }
  },hmac)

  return o
end

function hmac:reset(key)
  local hash = self.private_.hash
  local hctx = self.private_.hctx

  if key then
    key, self.private_.ipad, self.private_.opad = hmac_key(hash, key)
  end

  hctx:reset()
  hctx:update(assert(self.private_.ipad))

  return self
end

function hmac:update(chunk, i, size)
  self.private_.hctx:update(chunk, i, size)
  return self
end

function hmac:digest(chunk, text)
  if type(chunk) ~= 'string' then text, chunk = chunk end
  if chunk then self:update(chunk) end

  local hash = self.private_.hash
  local hctx = self.private_.hctx
  local opad = self.private_.opad
  return hash.digest(opad .. hctx:digest(), text)
end

function hmac:destroy()
  if not self.private_ then return end
  self.private_.hctx:destroy()
  self.private_ = nil
end

function hmac:destroyed()
  return not not self.private_
end

end

return {
  new    = function(...) return hmac:new(...) end;
  digest = hmac_hash;
}
