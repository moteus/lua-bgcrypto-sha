local bit    = require "bit32"

local sbyte   = string.byte
local schar   = string.char
local bxor    = bit.bxor

local function H(t, b, e)
  local str = ''
  for i = b or 1, e or #t do
    str = str .. (string.char(t[i]))
  end
  return str
end

local UNPACK_STR = {
  [20] = function(uu, str)
    uu[01], uu[02], uu[03], uu[04], uu[05], uu[06], uu[07], uu[08], uu[09], uu[10],
    uu[11], uu[12], uu[13], uu[14], uu[15], uu[16], uu[17], uu[18], uu[19], uu[20]
    = sbyte(str, 1, 20)
  end;
  [28] = function(uu, str)
    uu[01], uu[02], uu[03], uu[04], uu[05], uu[06], uu[07], uu[08], uu[09], uu[10],
    uu[11], uu[12], uu[13], uu[14], uu[15], uu[16], uu[17], uu[18], uu[19], uu[20],
    uu[21], uu[22], uu[23], uu[24], uu[25], uu[26], uu[27], uu[28]
    = sbyte(str, 1, 28)
  end;
  [32] = function(uu, str)
    uu[01], uu[02], uu[03], uu[04], uu[05], uu[06], uu[07], uu[08], uu[09], uu[10],
    uu[11], uu[12], uu[13], uu[14], uu[15], uu[16], uu[17], uu[18], uu[19], uu[20],
    uu[21], uu[22], uu[23], uu[24], uu[25], uu[26], uu[27], uu[28], uu[29], uu[30],
    uu[31], uu[32]
    = sbyte(str, 1, 32)
  end;
  [48] = function(uu, str)
    uu[01], uu[02], uu[03], uu[04], uu[05], uu[06], uu[07], uu[08], uu[09], uu[10],
    uu[11], uu[12], uu[13], uu[14], uu[15], uu[16], uu[17], uu[18], uu[19], uu[20],
    uu[21], uu[22], uu[23], uu[24], uu[25], uu[26], uu[27], uu[28], uu[29], uu[30],
    uu[31], uu[32], uu[33], uu[34], uu[35], uu[36], uu[37], uu[38], uu[39], uu[40],
    uu[41], uu[42], uu[43], uu[44], uu[45], uu[46], uu[47], uu[48]
    = sbyte(str, 1, 48)
  end;
  [64] = function(uu, str)
    uu[01], uu[02], uu[03], uu[04], uu[05], uu[06], uu[07], uu[08], uu[09], uu[10],
    uu[11], uu[12], uu[13], uu[14], uu[15], uu[16], uu[17], uu[18], uu[19], uu[20],
    uu[21], uu[22], uu[23], uu[24], uu[25], uu[26], uu[27], uu[28], uu[29], uu[30],
    uu[31], uu[32], uu[33], uu[34], uu[35], uu[36], uu[37], uu[38], uu[39], uu[40],
    uu[41], uu[42], uu[43], uu[44], uu[45], uu[46], uu[47], uu[48], uu[49], uu[50],
    uu[51], uu[52], uu[53], uu[54], uu[55], uu[56], uu[57], uu[58], uu[59], uu[60],
    uu[61], uu[62], uu[63], uu[64]
    = sbyte(str, 1, 64)
  end;
}

local function derive_key(hash, pwd, salt, iter, key_len)
  local DIGEST_SIZE = hash.DIGEST_SIZE
  local unpack_str  = assert(UNPACK_STR[DIGEST_SIZE])

  local key = {}
  local uu, ux = {}, {}, {}
  local n_blk = math.floor(1 + (key_len - 1) / DIGEST_SIZE)
  local c3 = hash.hmac.new(pwd)

  for i = 1, n_blk do
    for j = 1, DIGEST_SIZE do ux[j], uu[j] = 0 end
    uu[1], uu[2], uu[3], uu[4] = bit.rshift(i, 24), bit.rshift(i, 16), bit.rshift(i,  8), i

    c3:update(salt)
    for j = 1, iter do 
      for _, b in ipairs(uu) do c3:update(schar(b)) end
      local str = c3:digest()

      unpack_str(uu, str)

      for k = 1, #uu do ux[k] = bxor( ux[k], uu[k] ) end
      c3:reset(pwd)
    end

    for _, b in ipairs(ux) do
      table.insert(key, b)
      if #key >= key_len then
        return H(key)
      end
    end
  end
  return H(key)
end

return derive_key
