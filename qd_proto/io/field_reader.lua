-- @file field_reader.lua
-- @brief Reads fields with a specific type from data packet.
package.prepend_path(Dir.global_plugins_path())
local data_struct = require("qd_proto.data_struct")
local decimal = require("qd_proto.format.decimal")
local wide_decimal = require("qd_proto.format.wide_decimal")

local field_reader = {}

-- Reads a field with a specific type from the input stream.
-- @param stream Represents the input buffer.
-- @param type The field type.
-- @throws BufferOutOfRange, FormatError.
-- @return res - value (same as range), nil if type void,
--         range - represents the range of the buf
--                 where the value is stored, nil if type void.
function field_reader.read_field(stream, type)
    local serialization = bit.band(type, data_struct.field_mask.SERIALIZATION)
    local representation = bit.band(type, data_struct.field_mask.REPRESENTATION)

    if (serialization == data_struct.field_type.VOID) then
        -- 0 here means that we're dealing with the field the server does not support.
        return nil, nil
    elseif (serialization == data_struct.field_base.BYTE) then
        return stream:read_int8()
    elseif (serialization == data_struct.field_base.UTF_CHAR) then
        return stream:read_utf8_char()
    elseif (serialization == data_struct.field_base.SHORT) then
        return stream:read_int16()
    elseif (serialization == data_struct.field_base.INT) then
        return stream:read_int32()
    elseif (serialization == data_struct.field_base.COMPACT_INT) then
        if (representation == data_struct.field_flag.DECIMAL) then
            local val, range = stream:read_compact_int()
            val = decimal.to_double(val)
            return val, range
        elseif (representation == data_struct.field_flag.SHORT_STRING) then
            return stream:read_utf8_short_str()
        elseif (representation == data_struct.field_flag.TIME_SECONDS) then
            return stream:read_compact_int()
        elseif (representation == data_struct.field_flag.TIME_MILLISECONDS) then
            return stream:read_compact_long()
        elseif (representation == data_struct.field_flag.TIME_NANOSECONDS) then
            return stream:read_compact_long()
        elseif (representation == data_struct.field_flag.SEQUENCE) then
            return stream:read_compact_int()
        elseif (representation == data_struct.field_flag.DATE) then
            return stream:read_compact_int()
        elseif (representation == data_struct.field_flag.LONG) then
            return stream:read_compact_long()
        elseif (representation == data_struct.field_flag.WIDE_DECIMAL) then
            local val, range = stream:read_compact_long()
            val = wide_decimal.to_double(val)
            return val, range
        else
            return stream:read_compact_int()
        end
    elseif (serialization == data_struct.field_base.BYTE_ARRAY) then
        if (representation == data_struct.field_flag.STRING) then
            return stream:read_utf8_str()
        else
            return stream:read_byte_array()
        end
    elseif (serialization == data_struct.field_base.UTF_CHAR_ARRAY) then
        return stream:read_utf8_char_arr()
    else
        error("FormatError: Field type not supported.")
    end
end

return field_reader
