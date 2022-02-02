-- @file utils.lua
-- @brief Provides general utility functions.
local utils = {}

-- @brief Compact Format.
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

-- Gets the length in bytes of an compact format.
-- @param n The first byte in compact format.
-- @return The number of bytes.
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
-- @param buf The input buffer.
-- @param off The offset in input buffer.
-- @return value, sizeof value - if reading is successful;
--         nil,   nil          - if cannot read int value from buffer
--         (buffer is not long enough).
function utils.read_compact_int(buf, off)
    if (off >= buf:len()) then return nil end
    local n = buf(off, 1):uint()
    local compact_len = utils.get_compact_len(n)
    local remainder_len = buf:len() - off
    if (compact_len > remainder_len) then return nil end

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
        -- The encoded number is possibly out of range,
        -- some bytes have to be skipped.
        while bit.band(bit.lshift(n, 1), 0x10) ~= 0 do
            n = bit.lshift(n, 1)
            off = off + 1
        end
        n = buf(off, 4):int()
    end
    return n, compact_len
end

-- Reads an long value from the data input in a compact format.
-- @param buf The input buffer.
-- @param off The offset in input buffer.
-- @return value, sizeof value - if reading is successful;
--         nil,   nil          - if cannot read int value from buffer
--         (buffer is not long enough).
function utils.read_compact_long(buf, off)
    if (off >= buf:len()) then return nil end
    local n = buf(off, 1):uint()
    local compact_len = utils.get_compact_len(n)
    local remainder_len = buf:len() - off
    if (compact_len > remainder_len) then return nil end

    if (compact_len <= 4) then
        -- Length and offset have been checked above.
        n = utils.int_to_long(n)
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
    n = Int64(buf(off, 4):uint(), n)
    return n, compact_len
end

-- Converts an int to a long.
-- @param val The integer num (32-bit signed).
-- @return The long num (64-bit signed).
function utils.int_to_long(val)
    val = Int64(val, 0)
    val = val:lshift(32)
    val = val:arshift(32)
    return val
end

-- Converts an enumeration table to a string table.
-- @param enum_table The enum table.
-- @return The string table.
function utils.enum_tbl_to_str_tbl(enum_table)
    local string_table = {}
    for name, num in pairs(enum_table) do string_table[num] = name end
    return string_table
end

-- Converts an enumeration value to a string.
-- @param enum_table The enum table.
-- @param val  The value in the enum table.
-- @return string - if the conversion was successful;
--         nil -    if not.
function utils.enum_val_to_str(enum_table, val)
    return utils.enum_tbl_to_str_tbl(enum_table)[val]
end

-- Appends the source table to the destination table.
-- @note The tables must have "numbered" keys.
-- @param dst The destination table.
-- @param src The source table.
function utils.append_to_table(dst, src)
    -- The first element has always index 1, not 0.
    local n = #dst + 1
    for _, field in pairs(src) do
        dst[n] = field
        n = n + 1
    end
end

-- Checks if a string is empty.
-- @param str The string.
-- @return true  - if the string is empty;
--         false - if the string not empty.
function utils.is_empty_str(str) return str == nil or str == '' end

-- Extracts a filename from a path.
-- @param path The path to the file.
-- @return The filename.
function utils.get_filename(path) return path:match("([^\\]-)$") end

return utils
