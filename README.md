lua-bgcrypto-sha
================
[![Build Status](https://travis-ci.org/moteus/lua-bgcrypto-sha.png?branch=master)](https://travis-ci.org/moteus/lua-bgcrypto-sha)
[![Build status](https://ci.appveyor.com/api/projects/status/j060vyw45e5fohgb?svg=true)](https://ci.appveyor.com/project/moteus/lua-bgcrypto-sha)
[![Coverage Status](https://coveralls.io/repos/github/moteus/lua-bgcrypto-sha/badge.svg?branch=master)](https://coveralls.io/github/moteus/lua-bgcrypto-sha?branch=master)


## Digest API ##

### Digest.new() => Digest context

### Each MESSAGE can be present like

 * `message [,offset=1 [, size=<END OF MESSAGE>]]` if message is string 
 * `message [,offset=1], size` if message is raw pointer to memory (light userdata)

### Digest.digest(MESSAGE [, text = false]) => string

### Digest.pbkdf2(password, salt, iterations, key_length) => string

### digest:update(MESSAGE) => self

### digest:digest([MESSAGE ,] [text = false]) => self

### digest:reset() => self

### digest:clone() => self

## HMAC API ##

### Digest.hmac.new(key) => HMAC Context

### Digest.hmac.digest(key, MESSAGE[, text = false]) => string

### hmac:update(MESSAGE) => self

### hmac:digest([MESSAGE ,] [text = false]) => self

### hmac:reset([key]) => self

### hmac:clone() => self


## Usage ##

```Lua
local sha1 = require "bgcrypto.sha1"
local key = "\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11\11"
local msg = "The quick brown fox jumps over the lazy dog"

print(sha1.digest(msg, true))

print(sha1.hmac.digest(key, msg, true))

local ctx = sha1.new()
for i = 1, #msg do ctx:update(msg, i, 1) end
print(ctx:digest(true))

local ctx = sha1.hmac.new(key)
for i = 1, #msg do ctx:update(msg, i, 1) end
print(ctx:digest(true))

print(ctx:reset(key):update(msg:sub(1, 25)):digest(msg:sub(26), true))

print(string.format("%q", sha1.pbkdf2('secret', '123salt', 1000, 32)))
```


See [AesFileEncrypt](examples/AesFileEncrypt.lua) implementation using `lua-bgcrypto` library.

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/moteus/lua-bgcrypto-sha/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

