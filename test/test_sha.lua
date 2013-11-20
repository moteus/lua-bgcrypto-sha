local sha = {
  sha1   = require "bgcrypto.sha1";
  sha224 = require "bgcrypto.sha224";
  sha256 = require "bgcrypto.sha256";
  sha384 = require "bgcrypto.sha384";
  sha512 = require "bgcrypto.sha512";
}

local IS_LUA52 = _VERSION >= 'Lua 5.2'

local function HEX(str)
  return (string.gsub(str, "..", function(p)
    return (string.char(tonumber(p, 16)))
  end))
end

local function STR(str)
  return (string.gsub(str, ".", function(p)
    return (string.format("%.2x", string.byte(p)))
  end))
end

local SHA = {
  { msg = "", count = 1;
    {
      ["SHA-1"  ] = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      ["SHA-224"] = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
      ["SHA-256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      ["SHA-384"] = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
      ["SHA-512"] = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    }
  },
  { msg = "", count = 10;
    {
      ["SHA-1"  ] = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      ["SHA-224"] = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
      ["SHA-256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      ["SHA-384"] = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
      ["SHA-512"] = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    }
  },
  { msg = "abc", count = 1;
    {
      ["SHA-1"  ] = "a9993e364706816aba3e25717850c26c9cd0d89d",
      ["SHA-224"] = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
      ["SHA-256"] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      ["SHA-384"] = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
      ["SHA-512"] = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    }
  },
  { msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", count = 1;
    {
      ["SHA-1"  ] = "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
      ["SHA-224"] = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
      ["SHA-256"] = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      ["SHA-384"] = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
      ["SHA-512"] = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
    }
  },
  { msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", count = 1;
    {
      ["SHA-1"  ] = "a49b2446a02c645bf419f995b67091253a04a259",
      ["SHA-224"] = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3",
      ["SHA-256"] = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
      ["SHA-384"] = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
      ["SHA-512"] = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    }
  },
  { msg = "a", count = 1000000;
    {
      ["SHA-1"  ] = "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
      ["SHA-224"] = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
      ["SHA-256"] = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
      ["SHA-384"] = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
      ["SHA-512"] = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
    }
  },
  -- { msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", count = 16777216;
  --   {
  --     ["SHA-1"  ] = "7789f0c9ef7bfc40d93311143dfbe69e2017f592",
  --     ["SHA-224"] = "b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85",
  --     ["SHA-256"] = "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e",
  --     ["SHA-384"] = "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023",
  --     ["SHA-512"] = "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086",
  --   }
  -- },
}

-- rfc4231 and rfc2202
local HMAC = {
  { key = HEX"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    msg = HEX"4869205468657265", count = 1;
    {
      ["SHA-1"  ] = "b617318655057264e28bc0b6fb378c8ef146be00",
      ["SHA-224"] = "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
      ["SHA-256"] = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
      ["SHA-384"] = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
      ["SHA-512"] = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    },
  },
  { key = HEX"4a656665",
    msg = HEX"7768617420646f2079612077616e7420666f72206e6f7468696e673f", count = 1;
    {
      ["SHA-1"  ] = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
      ["SHA-224"] = "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
      ["SHA-256"] = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      ["SHA-384"] = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
      ["SHA-512"] = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    },
  },
  { key = HEX"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    msg = HEX"dd", count = 50;
    {
      ["SHA-1"  ] = "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
      ["SHA-224"] = "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
      ["SHA-256"] = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
      ["SHA-384"] = "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
      ["SHA-512"] = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    },
  },
  { key = HEX"0102030405060708090a0b0c0d0e0f10111213141516171819",
    msg = HEX"cd", count = 50;
    {
      ["SHA-1"  ] = "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
      ["SHA-224"] = "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
      ["SHA-256"] = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
      ["SHA-384"] = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
      ["SHA-512"] = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
    },
  },
  { key = HEX"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
    msg = HEX"546573742057697468205472756e636174696f6e", count = 1;
    {
      ["SHA-1"  ] = "4c1a03424b55e07fe7f27be1",
      ["SHA-224"] = "0e2aea68a90c8d37c988bcdb9fca6fa8",
      ["SHA-256"] = "a3b6167473100ee06e0c796c2955552b",
      ["SHA-384"] = "3abf34c3503b2a23a46efc619baef897",
      ["SHA-512"] = "415fad6271580a531d4179bc891d87a6",
    },
  },
  { key = (HEX"aa"):rep(80),
    msg = "Test Using Larger Than Block-Size Key - Hash Key First", count = 1;
    {
      ["SHA-1"  ] = "aa4ae5e15272d00e95705637ce8a3b55ed402112",
    },
  },
  { key = (HEX"aa"):rep(131),
    msg = "Test Using Larger Than Block-Size Key - Hash Key First", count = 1;
    {
      ["SHA-224"] = "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
      ["SHA-256"] = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
      ["SHA-384"] = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
      ["SHA-512"] = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    },
  },
  { key = (HEX"aa"):rep(80),
    msg = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", count = 1;
    {
      ["SHA-1"  ] = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
    },
  },
  { key = (HEX"aa"):rep(131),
    msg = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", count = 1;
    {
      ["SHA-224"] = "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
      ["SHA-256"] = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
      ["SHA-384"] = "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
      ["SHA-512"] = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    },
  },
}

local FN = {
  ["SHA-1"  ] = {new = sha.sha1.new,   digest = sha.sha1.digest,   hmac = sha.sha1.hmac,    };
  ["SHA-224"] = {new = sha.sha224.new, digest = sha.sha224.digest, hmac = sha.sha224.hmac,  };
  ["SHA-256"] = {new = sha.sha256.new, digest = sha.sha256.digest, hmac = sha.sha256.hmac,  };
  ["SHA-384"] = {new = sha.sha384.new, digest = sha.sha384.digest, hmac = sha.sha384.hmac,  };
  ["SHA-512"] = {new = sha.sha512.new, digest = sha.sha512.digest, hmac = sha.sha512.hmac,  };
}

for _, test in ipairs(SHA) do
  local msg    = assert(test.msg);
  local count  = test.count;

  io.write("msessage size " .. (#msg * count) .. ": \n")
  for algo, etalon in pairs(test[1]) do
    local digest = FN[algo].digest
    local new    = FN[algo].new
    if digest then 
      local hash 
      io.write("  " .. algo .. " - ")
  
      if count == 1 then -- do not try allocate big msg
        hash = digest(msg, true) assert(hash == etalon     )
        hash = digest(msg)       assert(hash == HEX(etalon))
      end

      local d = new()
      for i = 1, count do
        d:update(msg)
      end
      hash = d:digest(true) assert(hash == etalon, '\n    Exp: ' .. etalon .. '\n    Got: ' .. hash)
      hash = d:digest()     assert(hash == HEX(etalon))

      if count == 1 then
        d:reset()
        for i = 1, #msg do d:update((msg:sub(i,i))) end
        hash = d:digest(true) assert(hash == etalon     )
        hash = d:digest()     assert(hash == HEX(etalon))
      end
      d:destroy()
      io.write(" pass!\n")
    end
  end
end

for _, test in ipairs(HMAC) do
  local key    = assert(test.key);
  local msg    = assert(test.msg);
  local count  = test.count;

  io.write("msessage size " .. (#msg * count) .. " key size " .. #key .. " : \n")
  for algo, etalon in pairs(test[1]) do
    local digest = FN[algo].hmac.digest
    local new    = FN[algo].hmac.new
    if digest then 
      local hash 
      io.write("  HMAC-" .. algo .. " - ")
  
      if count == 1 then -- do not try allocate big msg
        hash = digest(key, msg, true) assert(hash:sub(1, #etalon)      == etalon     )
        hash = digest(key, msg)       assert(hash:sub(1, #HEX(etalon)) == HEX(etalon))
      end

      local d = new(key)
      for i = 1, count do
        d:update(msg)
      end
      hash = d:digest(true) assert(hash:sub(1, #etalon)      == etalon     )
      hash = d:digest()     assert(hash:sub(1, #HEX(etalon)) == HEX(etalon))

      if count == 1 then
        d:reset(key)
        for i = 1, #msg do d:update((msg:sub(i,i))) end
        hash = d:digest(true) assert(hash:sub(1, #etalon)      == etalon     )
        hash = d:digest()     assert(hash:sub(1, #HEX(etalon)) == HEX(etalon))
      end
      d:destroy()
      io.write(" pass!\n")
    end
  end
end
