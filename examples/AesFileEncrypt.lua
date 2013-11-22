local aes  = require "bgcrypto.aes"
local sha1 = require "bgcrypto.sha1"

local function rand_bytes(n)
  local t = {}
  for i=1, n do
    table.insert(t, string.char(math.random(256) - 1))
  end
  return table.concat(t)
end

local AesFileEncrypt = {}
AesFileEncrypt.__index = AesFileEncrypt

local AES_MODES = {
  [1] = { key  = 16; salt =  8; mac  = 10};
  [2] = { key  = 24; salt = 12; mac  = 10};
  [3] = { key  = 32; salt = 16; mac  = 10};
}

local PWD_VER_LENGTH = 2

local KEYING_ITERATIONS = 1000

---
--
function AesFileEncrypt:new()
  local o = setmetatable({
    private_ = {}
  }, self)
  return o
end

---
-- @tparam number mode 1/2/3
-- @tparam string pwd up to 128 bytes
-- @tparam[opt] string salt depend on AES encrypt mode.
-- @treturt string salt
-- @treturt string passert verification code
function AesFileEncrypt:open(mode, pwd, salt)
  self.private_.mode = assert(AES_MODES[mode], 'unknown mode: ' .. mode)

  assert(not self.private_.salt, "alrady opened")

  salt = salt or rand_bytes(self.private_.mode.salt)
  assert(#salt == self.private_.mode.salt, 'Expected: ' .. self.private_.mode.salt .. ' got: ' .. #salt )
  self.private_.salt = salt

  local key_len = self.private_.mode.key
  local key     = sha1.pbkdf2(pwd, salt, KEYING_ITERATIONS, 2 * key_len + PWD_VER_LENGTH)

  local aes_key = key:sub(1, key_len)
  local mac_key = key:sub(1 + key_len,  2 * key_len)
  local pwd_ver = key:sub(1 + 2 * key_len, 2 * key_len + PWD_VER_LENGTH)

  local mac     = sha1.hmac.new(mac_key)
  local encrypt = aes.ctr_encrypter()
  encrypt:set_inc_mode("fi") -- firward increment
  encrypt:open(aes_key, '\1' .. ('\0'):rep(aes.BLOCK_SIZE - 1))

  self.private_.mac     = mac
  self.private_.encrypt = encrypt
  self.private_.last_fn = self.encrypt

  return salt, pwd_ver
end

function AesFileEncrypt:encrypt(chunk)
  self.private_.last_fn = self.encrypt

  local enc = self.private_.encrypt:write(chunk)
  self.private_.mac:update(enc)
  if self.private_.writer then
    return self.private_.writer(enc)
  end
  return enc
end

function AesFileEncrypt:decrypt(chunk)
  self.private_.last_fn = self.decrypt

  self.private_.mac:update(chunk)
  local dec = self.private_.encrypt:write(chunk)
  if self.private_.writer then
    return self.private_.writer(dec)
  end
  return dec
end

--- Write last portion of data
-- @tparam[opt] string chunk
-- @treturt string message authentication code
-- @treturt string last portion of data
function AesFileEncrypt:close(chunk)
  if chunk then
    chunk = self.private_.last_fn(chunk)
  end

  local mac = self.private_.mac:digest()

  self.private_.mac:destroy()
  self.private_.encrypt:destroy()

  self.private_.mac, self.private_.encrypt = nil

  return mac:sub(1, self.private_.mode.mac), chunk
end

function AesFileEncrypt:destroy()
  if self:opened() then
    self:close()
  end
  self.private_ = nil
end

function AesFileEncrypt:opened()
  return not not self.private_.encrypt
end

function AesFileEncrypt:destroyed()
  return not self.private_
end

---
--
function AesFileEncrypt:set_writer(writer, ctx)
  if writer == nil then
    self.private_.writer = nil
  elseif type(writer) == 'function' then
    if ctx ~= nil then
      self.private_.writer = function(...)
        return writer(ctx, ...)
      end
    else
      self.private_.writer = writer
    end
  else
    local write = assert(writer.write)
    self.private_.writer = function(...)
      return write(writer, ...)
    end
  end
  return self
end

---
--
function AesFileEncrypt:get_writer()
  return self.private_.writer
end

do -- self test

local function H(t, b, e)
  local str = ''
  for i = b or 1, e or #t do
    str = str .. (string.char(t[i]))
  end
  return str
end

local function hex_to_str(str)
  return (string.gsub(str, ".", function(p)
    return (string.format("%.2x", string.byte(p)))
  end))
end

local function test_AesFileEncrypt()
  local pwd    = "123456"
  local salt   = H{0x5D,0x9F,0xF9,0xAE,0xE6,0xC5,0xC9,0x19,0x42,0x46,0x88,0x3E,0x06,0x9D,0x1A,0xA6}
  local pver   = "9aa9"
  local data   = "11111111111111111111\r\n22222222222222222222"
  local mac    = "eb048021e72f5e2a7db3"
  local etalon = "91aa63f0cb2b92479f89c32eb6b875b8c7d487aa7a8cb3705a5d8d276d6a2e8fc7cad94cc28ed0ad123e"

  local fenc = AesFileEncrypt:new()

  local edata = {}
  fenc:set_writer(table.insert, edata)

  local salt, pwd_ver = fenc:open(3, pwd, salt)
  fenc:encrypt(data)
  local mac_ = fenc:close()
  edata = table.concat(edata)
  assert(mac == hex_to_str(mac_), 'Expected: `' .. mac ..'` got: `' .. hex_to_str(mac_) .. '`')
  assert(etalon == hex_to_str(edata), 'Expected: `' .. etalon ..'` got: `' .. hex_to_str(edata) .. '`')
end

function AesFileEncrypt.self_test()
  test_AesFileEncrypt()
end

end

AesFileEncrypt.self_test()

return {
  new = function(...)
    return AesFileEncrypt:new(...)
  end;
  _VERSION = "0.0.1";
  version = function() return 0,0,1 end;
  AES128 = 1;
  AES192 = 2;
  AES256 = 3;
  AES128_SALT_LENGTH = AES_MODES[1].salt;
  AES192_SALT_LENGTH = AES_MODES[2].salt;
  AES256_SALT_LENGTH = AES_MODES[3].salt;
  AES128_MAC_LENGTH  = AES_MODES[1].mac;
  AES192_MAC_LENGTH  = AES_MODES[2].mac;
  AES256_MAC_LENGTH  = AES_MODES[3].mac;

}
