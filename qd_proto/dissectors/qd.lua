-- @file qd.lua
-- @brief The QD message dissector.
package.prepend_path(Dir.global_plugins_path())
local utils = require("qd_proto.utils")
local dbg = require("qd_proto.dbg")

local qd = {}

-- List of QD message type.
qd.type = {
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

-- List of QD message fields.
qd.fields = {
    msg_len = ProtoField.uint32("qd.msg_len", "Length", base.DEC),
    msg_type = ProtoField.uint8("qd.msg_type", "Type", base.DEC,
                                utils.enum_tbl_to_str_tbl(qd.type))
}

-- Type of QD message.
local qd_message_type = {
    -- Message type num.
    val_uint = nil,
    -- String representation message type.
    val_str = nil
}

-- The QD message.
local qd_message = {
    -- Type of QD message.
    qd_message_type = nil,
    -- Buf range with QD message data.
    data = nil
}

-- The result dissection message.
local dissection_result = {
    -- QD full message length (sizeof compact_len + size data fields).
    --  0  - this not QD message;
    -- <0  - length input buffer not enough for assemble
    --       full QD message (negative num bytes, num which are missing);
    -- >0, - full length QD message.
    qd_full_msg_len = nil,
    -- QD message (may be nil).
    qd_message = nil,
    -- Subtree for display fields in Wireshark (may be nil).
    subtree = nil
}

-- Checks the length of the input buffer.
-- @param buf The input buffer.
-- @param off The offset in input buffer.
-- @return true  - if the buffer length and offset are correct;
--         false - if not.
local function check_input_buf_len(buf, off)
    return ((off < 0) or (off >= buf:len())) and false or true
end

-- Checks if the input buffer has been sliced/cut off.
-- @param buf The input buffer.
-- @param off The offset in input buffer.
-- @return true  - if the input buffer is whole;
--         false - if not.
local function check_input_buf_cut_off(buf, off)
    if ((buf:len() - off) ~= buf:reported_length_remaining(off)) then
        return false
    end
    return true
end

-- Reads compact length (sizeof message length) contained in buf.
-- @param buf The input buffer.
-- @param off The offset to compact length.
-- @return compact_len  - if the compact length can fit in the buffer;
--         nil          - if not.
local function read_compact_len(buf, off)
    local n = buf(off, 1):uint()
    local compact_len = utils.get_compact_len(n)
    local remainder_len = buf:len() - off
    if (compact_len > remainder_len) then return nil end
    return compact_len
end

-- Reads the message length contained in buf.
-- @param buf The input buffer.
-- @param off The offset to message length.
-- @return msg_len  - if the length of the message is successfully read;
--         nil      - if not.
local function read_msg_len(buf, off)
    local msg_len = utils.read_compact_int(buf, off)
    if (msg_len == nil or msg_len < 0) then return nil end
    return msg_len
end

-- Reads the message type contained in buf.
-- @param buf The input buffer.
-- @param off The offset to message length.
-- @return qd_message_type.
local function read_msg_type(buf, off)
    qd_message_type = {}
    qd_message_type.val_uint = buf(off, 1):uint()
    qd_message_type.val_str = utils.enum_val_to_str(qd.type,
                                                    qd_message_type.val_uint)
    return qd_message_type
end

-- Reads the full length of the received message.
-- @param buf The input buffer.
-- @param off The offset to message length.
-- @return qd_full_msg_len >  0, compact_len, msg_len,
--         qd_full_msg_len <= 0, nil, nil.
function qd.read_full_msg(buf, off)
    local result = check_input_buf_len(buf, off)
    if (result == false) then
        dbg.warn(dbg.file(), dbg.line(), "Bad input buffer length.")
        return 0
    end

    result = check_input_buf_cut_off(buf, off)
    if (result == false) then
        dbg.warn(dbg.file(), dbg.line(),
                 "Captured packet was shorter than original, can't reassemble.")
        return 0
    end

    local compact_len = read_compact_len(buf, off)
    if (compact_len == nil) then
        dbg.info(dbg.file(), dbg.line(),
                 "Not enough buffer length for get compact_len.")
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    local msg_len = read_msg_len(buf, off)
    if (msg_len == nil) then
        dbg.warn(dbg.file(), dbg.line(), "Bad message length.")
        return 0
    end

    local remainder_len = buf:len() - off
    local full_msg_len = compact_len + msg_len
    if (full_msg_len > remainder_len) then
        dbg.info(dbg.file(), dbg.line(), "Need more data for build message.")
        return -(full_msg_len - remainder_len)
    end

    return full_msg_len, compact_len, msg_len
end

-- Dissects the input message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param off The offset in input buffer
-- @param packet_info The packet information.
-- @param tree The tree for display fields in Wireshark.
-- @return dissection_result.
function qd.dissect(proto, tvb_buf, off, packet_info, tree)
    dissection_result = {}
    -- Reads full message length.
    local full_msg_len, compact_len, msg_len = qd.read_full_msg(tvb_buf, off)
    dissection_result.qd_full_msg_len = full_msg_len
    if (full_msg_len <= 0) then return dissection_result end

    -- Fill message length.
    local len_off = off
    local len_sizeof = compact_len
    local len = msg_len

    -- If the message length zero, then this HEARTBEAT.
    if (len == 0) then
        -- Fill tree.
        local subtree = tree:add(proto, tvb_buf(off, full_msg_len),
                                 "HEARTBEAT_ZERO_LENGTH")
        subtree:add(qd.fields.msg_len, tvb_buf(len_off, len_sizeof), len)
        subtree:add(qd.fields.msg_type, qd.type.HEARTBEAT)
        dissection_result.subtree = subtree
        return dissection_result
    end

    -- Gets the message type.
    local type_off = len_off + len_sizeof
    local type_sizeof = 1
    local type = read_msg_type(tvb_buf, type_off)
    if (utils.is_empty_str(type.val_str) == true) then
        dbg.error(dbg.file(), dbg.line(), "Unknown message type.")
        dissection_result.qd_full_msg_len = 0
        return dissection_result
    end

    -- Fill tree.
    local subtree = tree:add(proto, tvb_buf(off, full_msg_len), type.val_str)
    subtree:add(qd.fields.msg_len, tvb_buf(len_off, len_sizeof), len)
    subtree:add(qd.fields.msg_type, tvb_buf(type_off, type_sizeof),
                type.val_uint)

    -- Creating a QD message for subsequent dissectors.
    local data_off = type_off + type_sizeof
    local data_len = len - type_sizeof
    qd_message = {}
    qd_message.type = type
    qd_message.data = tvb_buf(data_off, data_len)

    -- Fill dissection result.
    dissection_result.qd_message = qd_message
    dissection_result.subtree = subtree
    return dissection_result
end

return qd
