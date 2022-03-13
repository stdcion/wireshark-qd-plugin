-- @file string_reader.lua
-- @brief Reads string form the buffer.
-- Strings are encoded in CESU-8 format.
-- The Compatibility Encoding Scheme for UTF-16: 8-Bit (CESU-8)
-- is a variant of UTF-8 that is described in Unicode Technical Report #26.
-- A CESU-8 code point from the Basic Multilingual Plane (BMP),
-- i.e. a code point in the range U+0000 to U+FFFF, is encoded
-- in the same way as in UTF-8. A Unicode supplementary character,
-- i.e. a code point in the range U+10000 to U+10FFFF,
-- is first represented as a surrogate pair, like in UTF-16,
-- and then each surrogate code point is encoded in UTF-8.
package.prepend_path(Dir.global_plugins_path())
local utils = require("qd_proto.utils")
local compact_reader = require("qd_proto.io.compact_reader")

local string_reader = {}

-- Reads 2-bytes UTF-8 code point.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @param first The first byte of code point.
-- @return The UTF-8 code point.
local function read_utf2(stream, first)
    return bit.lshift(first, 8) + stream:read_bytes(1):uint()
end

-- Reads 3-bytes (4-bytes if this CESU-8) UTF-8 code point.
-- @note Overlong UTF-8 and CESU-8-encoded surrogates
--       are accepted and read without errors.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @param first The first byte of code point.
-- @return The UTF-8 code point.
local function read_utf3(stream, first)
    local input = {}
    input[1] = stream:read_uint8()
    input[2] = stream:read_uint8()

    -- CESU-8 strings will encode surrogate pairs using the byte sequence:
    -- ED [A0..BF] [80..BF] ED [B0..BF] [80..BF]
    -- Such a sequence of bytes cannot appear in any valid UTF-8 string,
    -- and are the only bytes allowed to appear in CESU-8 in excess of UTF-8.
    if (first == 0xED and input[1] >= 0x0A and input[1] <= 0xBF) then
        if (input[2] >= 0x80 and input[2] <= 0xBF) then
            -- Skips insignificant 0xED.
            stream:skip_bytes(1)

            -- Reads second surrogate pairs.
            input[3] = stream:read_uint8()
            input[4] = stream:read_uint8()

            -- Masks insignificant bits.
            input[1] = (bit.band(input[1], 0x0F) + 1) -- (top 5-bits minus one)
            input[2] = bit.band(input[2], 0x3F)
            input[3] = bit.band(input[3], 0x0F)
            input[4] = bit.band(input[4], 0x3F)

            -- Converts CESU-8 surrogate pairs to UTF-8 (4-bytes).
            -- ED       A0-AF    80-BF    ED       B0-BF    80-BF   (CESU-8)
            -- 11101101 1010aaaa 10bbbbbb 11101101 1011cccc 10dddddd
            -- F0-F4    80-BF    80-BF    80-BF    (UTF-8)
            -- 11110oaa 10aabbbb 10bbcccc 10dddddd (o is "overflow" bit)
            local utf8_arr = {}
            utf8_arr[1] = bit.bor(0xF0, bit.rshift(input[1], 2))
            utf8_arr[2] = bit.bor(0x80, bit.lshift(bit.band(input[1], 0x03), 4))
            utf8_arr[2] = bit.bor(utf8_arr[2], bit.rshift(input[2], 2))
            utf8_arr[3] = bit.bor(0x80, bit.lshift(bit.band(input[2], 0x03), 4))
            utf8_arr[3] = bit.bor(utf8_arr[3], input[3])
            utf8_arr[4] = bit.bor(0x80, input[4])

            -- Converts UTF-8 array to codepoint.
            local codepoint = 0
            for i = 1, 4, 1 do
                codepoint = bit.bor(codepoint,
                                    bit.lshift(utf8_arr[i], 32 - (i * 8)))
            end

            -- Returns UTF-8 codepoint (4-bytes).
            return codepoint
        end
    end

    -- Returns UTF-8 codepoint (3-bytes).
    return bit.lshift(first, 16) + bit.lshift(input[1], 8) + input[2]
end

-- Reads 4-bytes UTF-8 code point.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @param first The first byte of code point.
-- @return The UTF-8 code point.
local function read_utf4(stream, first)
    return bit.lshift(first, 24) + stream:read_bytes(3):uint()
end

-- Reads UTF-8 code point from the input stream.
-- @note Overlong UTF-8 and CESU-8-encoded surrogates
--       are accepted and read without errors.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @return The UTF-8 code point.
local function read_utf8_codepoint(stream)
    local c = stream:read_uint8()
    if (c <= 0x7F) then return c end
    if (bit.band(c, 0xE0) == 0xC0) then return read_utf2(stream, c) end
    if (bit.band(c, 0xF0) == 0xE0) then return read_utf3(stream, c) end
    if (bit.band(c, 0xF8) == 0xF0) then return read_utf4(stream, c) end
end

-- Reads an UTF-8 char from the input stream.
-- @note Overlong UTF-8 and CESU-8-encoded surrogates
--       are accepted and read without errors.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @return The UTF-8 char (1-4 bytes).
function string_reader.read_utf8_char(stream)
    local start_pos = stream:get_current_pos()
    local range = nil
    local char = utils.codepoint_to_char(read_utf8_codepoint(stream))

    range = stream:get_range(start_pos, stream:get_current_pos())
    return char, range
end

-- Reads an UTF-8 sequence from the input stream.
-- @note The string in the buffer is stored in the following form:
--       [string_len(compact_long)] + [string].
--       string_len can contain the length in characters or bytes.
--       The return range including the string_len field.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @param isLenInChar The flag determines what the length is measured in.
-- @return value - the read value,
--         range - represents the range of the buf
--                 where the value is stored.
function string_reader.read_utf8_sequence(stream, isLenInChar)
    local start_pos = stream:get_current_pos()
    local range = nil
    local str = ""
    -- Length in bytes or characters.
    local len = compact_reader.read_compact_long(stream)

    if (isLenInChar) then
        while (len > 0) do
            local codepoint = read_utf8_codepoint(stream)
            str = str .. utils.codepoint_to_char(codepoint)
            len = len - 1
        end
    else
        while (len > 0) do
            local remembered_pos = stream:get_current_pos()
            local codepoint = read_utf8_codepoint(stream)
            str = str .. utils.codepoint_to_char(codepoint)
            -- How many bytes have been read.
            len = len - (stream:get_current_pos() - remembered_pos)
        end
    end

    range = stream:get_range(start_pos, stream:get_current_pos())
    return str, range
end

-- Reads an UTF-8 string from the input stream.
-- @note The string in the buffer is stored in the following form:
--       [string_len(compact_long)] + [string].
--       string_len contain the length in bytes.
--       The return range including the string_len field.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @return value - the read value,
--         range - represents the range of the buf
--                 where the value is stored.
function string_reader.read_utf8_str(stream)
    return string_reader.read_utf8_sequence(stream, false)
end

-- Reads an UTF-8 characters array from the input stream.
-- @note The string in the buffer is stored in the following form:
--       [string_len(compact_long)] + [string].
--       string_len contain the length in characters.
--       The return range including the string_len field.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @return value - the read value,
--         range - represents the range of the buf
--                 where the value is stored.
function string_reader.read_utf8_char_arr(stream)
    return string_reader.read_utf8_sequence(stream, true)
end

-- Reads short UTF-8 (up to 4-character) string representation as int field.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @return value - the read value,
--         range - represents the range of the buf
--                 where the value is stored.
function string_reader.read_utf8_short_str(stream)
    local codepoint, range = compact_reader.read_compact_int(stream)
    return utils.codepoint_to_char(codepoint), range
end

-- Reads a byte array from the input stream.
-- @note The byte array in the buffer is stored in the following form:
--       [arr_len(compact_long)] + [arr].
--       arr_len contain the length in bytes.
--       The return range including the arr_len field.
-- @throws BufferOutOfRange.
-- @param stream Represents the input buffer.
-- @return value - the read value,
--         range - represents the range of the buf
--                 where the value is stored.
function string_reader.read_byte_array(stream)
    local start_pos = stream:get_current_pos()
    local range = nil
    local arr = {}
    local arr_len = compact_reader.read_compact_long(stream)
    if arr_len > 0 then arr = stream:read_bytes(arr_len):raw() end

    range = stream:get_range(start_pos, stream:get_current_pos())
    return arr, range
end

return string_reader
