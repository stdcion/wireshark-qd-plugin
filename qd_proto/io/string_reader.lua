-- @file string_reader.lua
-- @brief Reads string form the buffer.
package.prepend_path(Dir.global_plugins_path())
local compact_reader = require("qd_proto.io.compact_reader")
local utils = require("qd_proto.utils")

local string_reader = {}

-- Reads 2-bytes Unicode code point.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @param first The first byte code point.
-- @return The Unicode code point.
local function read_utf2(stream, first)
    local second = stream:read_int8()
    local codepoint = bit.lshift(bit.band(first, 0x1F), 6)
    codepoint = bit.bor(codepoint, bit.band(second, 0x3F))
    return codepoint
end

-- Reads 3-bytes Unicode code point.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @param first The first byte code point.
-- @return The Unicode code point.
local function read_utf3(stream, first)
    local tail = stream:read_int16()
    local codepoint = bit.lshift(bit.band(first, 0x0F), 12)
    codepoint = bit.bor(codepoint, bit.rshift(bit.band(tail, 0x3F00), 2))
    codepoint = bit.bor(codepoint, bit.band(tail, 0x3F))
    return codepoint
end

-- Reads 4-bytes Unicode code point.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @param first The first byte code point.
-- @return The Unicode code point.
local function read_utf4(stream, first)
    local second = stream:read_int8()
    local tail = stream:read_int16()
    local codepoint = bit.lshift(bit.band(first, 0x07), 18)
    codepoint = bit.bor(codepoint, bit.lshift(bit.band(second, 0x3F), 12))
    codepoint = bit.bor(codepoint, bit.rshift(bit.band(tail, 0x3F00), 2))
    codepoint = bit.bor(codepoint, bit.band(tail, 0x3F))
    return codepoint
end

-- Reads Unicode code point in a UTF-8 format.
-- @note Overlong UTF-8 and CESU-8-encoded surrogates
--       are accepted and read without errors.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @return The Unicode code point.
local function read_utf_codepoint(stream)
    local c = stream:read_int8()
    if (c >= 0) then return c end
    if (bit.band(c, 0xE0) == 0xC0) then return read_utf2(stream, c) end
    if (bit.band(c, 0xF0) == 0xE0) then return read_utf3(stream, c) end
    if (bit.band(c, 0xF8) == 0xF0) then return read_utf4(stream, c) end
end

-- Reads a UTF-8 string from the data input.
-- @note The string in the buffer is stored in the following form:
--       [string_len(compact_int)] + [string].
--       The return value specifies start_pos, sizeof, and next_pos,
--       including the string_len field.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @return value - the read value,
--         range - represents the range of the buf
--                 where the value is stored.
function string_reader.read_utf8_str(stream)
    local start_pos = stream:get_current_pos()
    local range = nil
    local str = ""
    local str_len = compact_reader.read_compact_int(stream)
    if str_len ~= 0 then str = stream:read_bytes(str_len):raw() end

    range = stream:get_range(start_pos, stream:get_current_pos())
    return str, range
end

-- Reads a CESU-8 string from the data input.
-- @note The string in the buffer is stored in the following form:
--       [string_len(compact_int)] + [string].
--       The return value specifies start_pos, sizeof, and next_pos,
--       including the string_len field.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @return value - the read value,
--         range - represents the range of the buf
--                 where the value is stored.
function string_reader.read_cesu_str(stream)
    local start_pos = stream:get_current_pos()
    local range = nil
    local str = ""
    local str_len = compact_reader.read_compact_int(stream)
    for i = 1, str_len, 1 do
        str = str .. utils.codepoint_to_char(read_utf_codepoint(stream))
    end

    range = stream:get_range(start_pos, stream:get_current_pos())
    return str, range
end

return string_reader
