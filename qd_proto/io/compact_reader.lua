-- @file compact_reader.lua
-- @brief Reads data in compact format form the buffer.
-- The Compact Format is a serialization format for integer numbers.
-- It uses encoding scheme with variable-length two's complement
-- big-endian format capable to encode 64-bits signed numbers.
-- The following table defines used serial format (the first byte is given
-- in bits with 'x' representing payload bit the remaining bytes are
-- given in bit count):
-- 0xxxxxxx     - for -64 to 64
-- 10xxxxxx  8x - for -8192 to 8192
-- 110xxxxx 16x - for -1048576 to 1048576
-- 1110xxxx 24x - for -134217728 to 134217728
-- 11110xxx 32x - for -17179869184 to 17179869184
-- 111110xx 40x - for -2199023255552 to 2199023255552
-- 1111110x 48x - for -281474976710656 to 281474976710656
-- 11111110 56x - for -36028797018963968 to 36028797018963968
-- 11111111 64x - for -9223372036854775808 to 9223372036854775808
package.prepend_path(Dir.global_plugins_path())
local utils = require("qd_proto.utils")

local compact_reader = {}

-- Gets the length in bytes of an compact format.
-- @param n The first byte in compact format.
-- @return The number of bytes.
function compact_reader.get_compact_len(n)
    if n < 0x80 then
        return 1
    elseif n < 0xC0 then
        return 2
    elseif n < 0xE0 then
        return 3
    elseif n < 0xF0 then
        return 4
    elseif n < 0xF8 then
        return 5
    elseif n < 0xFC then
        return 6
    elseif n < 0xFE then
        return 7
    elseif n < 0xFF then
        return 8
    else
        return 9
    end
end

-- Reads an integer value from the data input in a compact format.
-- @note If actual encoded value does not fit into an int (32-bit) data type,
--       then it is truncated to int value (only lower 32 bits are returned)
-- @param stream Represents the input buffer.
-- @return value - the read value,
--         range - represents the range of the buf
--                 where the value is stored.
function compact_reader.read_compact_int(stream)
    local start_pos = stream:get_current_pos()
    local range = nil
    local n = stream:read_uint8()
    local compact_len = compact_reader.get_compact_len(n)

    if compact_len == 1 then
        n = bit.lshift(n, 25)
        n = bit.arshift(n, 25)
    elseif compact_len == 2 then
        n = bit.lshift(n, 8)
        n = n + stream:read_uint8()
        n = bit.lshift(n, 18)
        n = bit.arshift(n, 18)
    elseif compact_len == 3 then
        n = bit.lshift(n, 16)
        n = n + stream:read_uint16()
        n = bit.lshift(n, 11)
        n = bit.arshift(n, 11)
    elseif compact_len == 4 then
        n = bit.lshift(n, 24)
        n = n + bit.lshift(stream:read_uint16(), 16)
        n = n + stream:read_uint8()
        n = bit.lshift(n, 4)
        n = bit.arshift(n, 4)
    else
        -- The encoded number is possibly out of range,
        -- some bytes have to be skipped.
        while bit.band(bit.lshift(n, 1), 0x10) ~= 0 do
            n = bit.lshift(n, 1)
            stream:skip_bytes(1)
        end
        n = stream:read_int32()
    end

    range = stream:get_range(start_pos, stream:get_current_pos())
    return n, range
end

-- Reads an long value from the data input in a compact format.
-- @param stream Represents the input buffer.
-- @return value - the read value,
--         range - represents the range of the buf
--                 where the value is stored.
function compact_reader.read_compact_long(stream)
    local start_pos = stream:get_current_pos()
    local range = nil
    local n = stream:read_uint8()
    local compact_len = compact_reader.get_compact_len(n)

    if (compact_len <= 4) then
        -- Moves position in buffer to compact_len.
        stream:set_current_pos(start_pos)
        n, range = compact_reader.read_compact_int(stream)
        n = utils.int_to_long(n)
        return n, range
    end

    if compact_len == 5 then
        n = bit.lshift(n, 29)
        n = bit.arshift(n, 29)
    elseif compact_len == 6 then
        n = bit.lshift(n, 8)
        n = n + stream:read_uint8()
        n = bit.lshift(n, 22)
        n = bit.arshift(n, 22)
    elseif compact_len == 7 then
        n = bit.lshift(n, 16)
        n = n + stream:read_uint16()
        n = bit.lshift(n, 15)
        n = bit.arshift(n, 15)
    elseif compact_len == 8 then
        n = stream:read_uint8()
        n = bit.lshift(n, 16)
        n = n + stream:read_uint16()
    else
        n = stream:read_uint32()
    end
    n = Int64(stream:read_uint32(), n)

    range = stream:get_range(start_pos, stream:get_current_pos())
    return n, range
end

return compact_reader
