-- @file fields.lua
-- @brief Provides fields for QD messages.
package.prepend_path("qd_proto")
local utils = require("utils")

local fields = {}

-- List of QD message type.
fields.message_type = {
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

-- List fields for Wireshark.
fields.qd = {
    msg_len = ProtoField.uint32("qd.msg_len", "Length", base.DEC),
    msg_type = ProtoField.uint8("qd.msg_type", "Type", base.DEC,
                                utils.enum_tbl_to_str_tbl(fields.message_type))
}

return fields
