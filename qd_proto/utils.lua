-- @file utils.lua
-- @brief Provides general utility functions for dissector.
local utils = {}

-- @brief Compact Format
-- The Compact Format is a serialization format for integer numbers.
-- It uses encoding scheme with variable-length two's complement
-- big-endian format capable to encode 64-bits signed numbers.
-- The following table defines used serial format (the first byte is given
-- in bits with 'x' representing payload bit; the remaining bytes are
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

-- Get the number of bytes it takes compact format.
-- @param n First byte in compact format.
-- @return Number of bytes.
function utils.get_compact_len(n)
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
-- @param buf Input buffer.
-- @param off Offset in input buffer.
-- @return value, size compact length in bytes - if read success;
--         nil, nil - if cannot read int value from buffer
--         (buffer is not long enough).
function utils.read_compact_int(buf, off)
    if (off >= buf:len()) then return nil; end
    local n = buf(off, 1):uint()
    local compact_len = utils.get_compact_len(n)
    local buf_len = buf:len() - off
    if (compact_len > buf_len) then return nil; end

    off = off + 1
    if compact_len == 1 then
        n = bit.lshift(n, 25)
        n = bit.arshift(n, 25)
    elseif compact_len == 2 then
        n = bit.lshift(n, 8)
        n = n + buf(off, 1):uint()
        n = bit.lshift(n, 18)
        n = bit.arshift(n, 18)
    elseif compact_len == 3 then
        n = bit.lshift(n, 16)
        n = n + buf(off, 2):uint()
        n = bit.lshift(n, 11)
        n = bit.arshift(n, 11)
    elseif compact_len == 4 then
        n = bit.lshift(n, 24)
        n = n + buf(off, 3):uint()
        n = bit.lshift(n, 4)
        n = bit.arshift(n, 4)
    else
        -- The encoded number is possibly out of range, some bytes have to be skipped.
        while bit.band(bit.lshift(n, 1), 0x10) ~= 0 do
            n = bit.lshift(n, 1)
            off = off + 1
        end
        n = buf(off, 4):int()
    end
    return n, compact_len
end

-- Reads an long value from the data input in a compact format.
-- @param buf Input buffer.
-- @param off Offset in input buffer.
-- @return value, size compact length in bytes - if read success;
--         nil, nil - if cannot read int value from buffer
--         (buffer is not long enough).
function utils.read_compact_long(buf, off)
    if (off >= buf:len()) then return nil; end
    local n = buf(off, 1):uint()
    local compact_len = utils.get_compact_len(n)
    local buf_len = buf:len() - off
    if (compact_len > buf_len) then return nil; end

    if (compact_len <= 4) then
        n = Int64(utils.read_compact_int(buf, off), 0)
        n = n:lshift(32)
        n = n:arshift(32)
        return n, compact_len
    end

    off = off + 1
    if compact_len == 5 then
        n = bit.lshift(n, 29)
        n = bit.arshift(n, 29)
    elseif compact_len == 6 then
        n = bit.lshift(n, 8)
        n = n + buf(off, 1):uint()
        off = off + 1
        n = bit.lshift(n, 22)
        n = bit.arshift(n, 22)
    elseif compact_len == 7 then
        n = bit.lshift(n, 16)
        n = n + buf(off, 2):uint()
        off = off + 2
        n = bit.lshift(n, 15)
        n = bit.arshift(n, 15)
    elseif compact_len == 8 then
        n = buf(off, 1):uint()
        off = off + 1
        n = bit.lshift(n, 16)
        n = n + buf(off, 2):uint()
        off = off + 2
    else
        n = buf(off, 4):uint()
        off = off + 4
    end
    n = Int64(n, 0)
    n = n:lshift(32) + buf(off, 4):int()
    return n, compact_len
end

-- Convert Enum table to String table.
-- @param enum Enum table.
-- @return String table.
function utils.enum_tbl_to_str_tbl(enum)
    local string = {}
    for name, num in pairs(enum) do string[num] = name end
    return string
end

-- Convert enum value to string.
-- @param enum Enum table.
-- @param val Value in enum table.
-- @return string - if convert success;
--         nil - if cannot convert.
function utils.enum_val_to_str(enum, val)
    return utils.enum_tbl_to_str_tbl(enum)[val]
end

-- Check string for empty.
-- @param str String.
-- @return true - if string is empty;
--         false - if string not empty.
function utils.is_empty_str(str) return str == nil or str == '' end

-- Extract filename form path.
-- @param path Path to file.
-- @return Filename.
function utils.get_filename(path)
    return path:match("^.+/(.+)$")
end

return utils
