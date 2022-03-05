-- @file stream_reader.lua
-- @brief Reads some data types form the buffer.
local StreamReader = {}

-- Creates a new instance of the StreamReader class.
-- @param buf The The input buffer.
-- @param off The offset in input buffer.
function StreamReader:new(buf, off)
    -- #region Private

    local private = {}

    -- The input buffer.
    private.buf = buf
    -- Current offset in input buffer.
    private.off = off
    -- Compact reader functions.
    private.compact_reader = require("qd_proto.io.compact_reader")
    -- String reader functions.
    private.string_reader = require("qd_proto.io.string_reader")

    -- #endregion

    -- #region Public

    local public = {}

    -- Checks if the buffer is not empty.
    -- @return try - if the buffer is empty;
    --         false - if the buffer is not empty.
    function public:is_empty() return private.off == buf:len() end

    -- Gets the current position in the buffer.
    -- @return The current position.
    function public:get_current_pos() return private.off end

    -- Sets the current position in the buffer.
    -- @param pos The position to set.
    function public:set_current_pos(pos) private.off = pos end

    -- Skips some bytes from the buffer.
    -- @param count The number of bytes to skip.
    -- @throws BufferOutOfRange.
    function public:skip_bytes(count) public:read_bytes(count) end

    -- Returns range from start_pos to end_pos (excluding).
    -- @note [start_pos : end_pos)
    -- @param start_pos Starting position in the range.
    -- @param end_pos Ending position in the range (excluding).
    -- @throws BufferOutOfRange.
    -- @return range - represents the range from start_pos to end_pos.
    function public:get_range(start_pos, end_pos)
        local res = private.buf(start_pos, end_pos - start_pos)
        if res == nil then error("BufferOutOfRange") end
        return res
    end

    -- Reads bytes array from buf.
    -- @note The return value must be cast to the required type.
    -- @param count The number of bytes to read.
    -- @throws BufferOutOfRange.
    -- @return res - the byte array (same as range),
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_bytes(count)
        local res = private.buf(private.off, count)
        if res == nil then error("BufferOutOfRange") end
        private.off = private.off + count
        -- Result and range are the same.
        local range = res
        return res, range
    end

    -- Reads signed 8-bit value from buf.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_int8()
        local res, range = public:read_bytes(1)
        res = bit.arshift(bit.lshift(res:int(), 56), 56)
        return res, range
    end

    -- Reads unsigned 8-bit value from buf.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_uint8()
        local res, range = public:read_bytes(1)
        return res:uint(), range
    end

    -- Reads signed 16-bit value from buf.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_int16()
        local res, range = public:read_bytes(2)
        res = bit.arshift(bit.lshift(res:int(), 48), 48)
        return res, range
    end

    -- Reads unsigned 16-bit value from buf.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_uint16()
        local res, range = public:read_bytes(2)
        return res:uint(), range
    end

    -- Reads signed 32-bit value from buf.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_int32()
        local res, range = public:read_bytes(4)
        return res:int(), range
    end

    -- Reads unsigned 32-bit value from buf.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_uint32()
        local res, range = public:read_bytes(4)
        return res:uint(), range
    end

    -- Reads signed 64-bit value from buf.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_int64()
        local res, range = public:read_bytes(8)
        local high = res(0, 4)
        local low = res(4, 4)
        return Int64(low:uint(), high:uint()), range
    end

    -- Reads unsigned 64-bit value from buf.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_uint64()
        local res, range = public:read_bytes(8)
        local high = res(0, 4)
        local low = res(4, 4)
        return UInt64(low:uint(), high:uint()), range
    end

    -- #region Wrappers for easy of use.

    -- Reads an int value from a compact format.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_compact_int()
        local res, range = private.compact_reader.read_compact_int(self)
        return res, range
    end

    -- Reads an long value from a compact format.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_compact_long()
        local res, range = private.compact_reader.read_compact_long(self)
        return res, range
    end

    -- Reads a UTF-8 string.
    -- @note The string in the buffer is stored in the following form:
    --       [string_len(compact_int)] + [string].
    --       The return range including the string_len field.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_utf8_str()
        local res, range = private.string_reader.read_utf8_str(self)
        return res, range
    end

    -- Reads an CESU-8 string.
    -- @note The string in the buffer is stored in the following form:
    --       [string_len(compact_int)] + [string].
    --       The return range including the string_len field.
    -- @throws BufferOutOfRange.
    -- @return value - the read value,
    --         range - represents the range of the buf
    --                 where the value is stored.
    function public:read_cesu_str()
        local res, range = private.string_reader.read_cesu_str(self)
        return res, range
    end

    -- #endregion

    -- #endregion

    setmetatable(public, self)
    self.__index = self
    return public
end

return StreamReader
