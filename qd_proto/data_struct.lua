-- @file data_struct.lua
-- @brief Types and structures.
local data_struct = {}

-- List of QD message type.
data_struct.qd_type = {
    HEARTBEAT = 0,
    DESCRIBE_PROTOCOL = 1,
    DESCRIBE_RECORDS = 2,
    PART = 4,
    RAW_DATA = 5,
    TICKER_DATA = 10,
    TICKER_ADD_SUBSCRIPTION = 11,
    TICKER_REMOVE_SUBSCRIPTION = 12,
    STREAM_DATA = 15,
    STREAM_ADD_SUBSCRIPTION = 16,
    STREAM_REMOVE_SUBSCRIPTION = 17,
    HISTORY_DATA = 20,
    HISTORY_ADD_SUBSCRIPTION = 21,
    HISTORY_REMOVE_SUBSCRIPTION = 22,
    RMI_DESCRIBE_SUBJECT = 50,
    RMI_DESCRIBE_OPERATION = 51,
    RMI_REQUEST = 52,
    RMI_CANCEL = 53,
    RMI_RESULT = 54,
    RMI_ERROR = 55
}

-- Base field type.
data_struct.field_base = {
    VOID = 0,
    BYTE = 1,
    UTF_CHAR = 2,
    SHORT = 3,
    INT = 4,
    -- Ids 5-7 are reserved for future use.
    COMPACT_INT = 8,
    BYTE_ARRAY = 9,
    UTF_CHAR_ARRAY = 10
    -- Ids 11-15 are reserved for future use.
}

-- Field flag for type.
data_struct.field_flag = {
    -- Plain int as int field.
    INT = 0x00,
    -- Decimal representation as int field.
    DECIMAL = 0x10,
    -- Short (up to 4-character) string representation as int field.
    SHORT_STRING = 0x20,
    -- Time in seconds as integer field.
    TIME_SECONDS = 0x30,
    -- Sequence in this integer fields (with top 10 bits representing millis).
    SEQUENCE = 0x40,
    -- Day id in this integer field.
    DATE = 0x50,
    -- Plain long as two int fields.
    LONG = 0x60,
    -- WideDecimal representation as long field.
    WIDE_DECIMAL = 0x70,
    -- String representation as byte array (for ID_BYTE_ARRAY).
    STRING = 0x80,
    -- Time in millis as long field.
    TIME_MILLISECONDS = 0x90,
    -- Reserved for future use: time in nanoseconds as long field.
    TIME_NANOSECONDS = 0xA0,
    -- Custom serialized object as byte array (for ID_BYTE_ARRAY).
    CUSTOM_OBJECT = 0xE0,
    -- Serialized object as byte array (for ID_BYTE_ARRAY).
    SERIAL_OBJECT = 0xF0
}

-- List of field type.
data_struct.field_type = {
    VOID = data_struct.field_base.VOID,
    BYTE = data_struct.field_base.BYTE,
    UTF_CHAR = data_struct.field_base.UTF_CHAR,
    SHORT = data_struct.field_base.SHORT,
    INT = data_struct.field_base.INT,
    COMPACT_INT = data_struct.field_base.COMPACT_INT,
    BYTE_ARRAY = data_struct.field_base.BYTE_ARRAY,
    UTF_CHAR_ARRAY = data_struct.field_base.UTF_CHAR_ARRAY,
    DECIMAL = bit.bor(data_struct.field_base.COMPACT_INT,
                      data_struct.field_flag.DECIMAL),
    SHORT_STRING = bit.bor(data_struct.field_base.COMPACT_INT,
                           data_struct.field_flag.SHORT_STRING),
    TIME_SECONDS = bit.bor(data_struct.field_base.COMPACT_INT,
                           data_struct.field_flag.TIME_SECONDS),
    TIME_MILLISECONDS = bit.bor(data_struct.field_base.COMPACT_INT,
                                data_struct.field_flag.TIME_MILLISECONDS),
    TIME_NANOSECONDS = bit.bor(data_struct.field_base.COMPACT_INT,
                               data_struct.field_flag.TIME_NANOSECONDS),
    SEQUENCE = bit.bor(data_struct.field_base.COMPACT_INT,
                       data_struct.field_flag.SEQUENCE),
    DATE = bit.bor(data_struct.field_base.COMPACT_INT,
                   data_struct.field_flag.DATE),
    LONG = bit.bor(data_struct.field_base.COMPACT_INT,
                   data_struct.field_flag.LONG),
    WIDE_DECIMAL = bit.bor(data_struct.field_base.COMPACT_INT,
                           data_struct.field_flag.WIDE_DECIMAL),
    STRING = bit.bor(data_struct.field_base.BYTE_ARRAY,
                     data_struct.field_flag.STRING),
    CUSTOM_OBJECT = bit.bor(data_struct.field_base.BYTE_ARRAY,
                            data_struct.field_flag.CUSTOM_OBJECT),
    SERIAL_OBJECT = bit.bor(data_struct.field_base.BYTE_ARRAY,
                            data_struct.field_flag.SERIAL_OBJECT)
}

return data_struct
