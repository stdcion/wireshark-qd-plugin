-- @file qd.lua
-- @brief Dissector QD message.
package.prepend_path("../")
local utils = require("utils")
local fields = require("fields")
local dbg = require("dbg")

local qd = {}

-- Type of QD message.
local qd_message_type = {
    -- Message type num.
    val_uint = nil,
    -- String representation message type.
    val_str = nil
}

-- QD message.
local qd_message = {
    -- Type of QD message.
    qd_message_type = nil,
    -- Buf range with QD message data.
    data = nil
}

-- Result dissection message.
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

-- Check length input buffer.
-- @param buf Input buffer.
-- @param off Offset in input buffer.
-- @return true  - if buffer length and offset is correct;
--         false - if not.
local function check_input_buf_len(buf, off)
    return ((off < 0) or (off >= buf:len())) and false or true
end

-- Check if input buffer was sliced/cut-off.
-- @param buf Input buffer.
-- @param off Offset in input buffer.
-- @return true  - if input buffer whole;
--         false - if not.
local function check_input_buf_cut_off(buf, off)
    if ((buf:len() - off) ~= buf:reported_length_remaining(off)) then
        return false
    end
    return true
end

-- Read compact length (sizeof message length) contained in buf.
-- @param buf Input buffer.
-- @param off Offset to compact length.
-- @return compact_len  - if compact length may fit in buffer;
--         nil          - if not.
local function read_compact_len(buf, off)
    local n = buf(off, 1):uint()
    local compact_len = utils.get_compact_len(n)
    local remainder_len = buf:len() - off
    if (compact_len > remainder_len) then return nil end
    return compact_len
end

-- Read message length contained in buf.
-- @param buf Input buffer.
-- @param off Offset to message length.
-- @return msg_len  - if message length success read;
--         nil      - if not.
local function read_msg_len(buf, off)
    local msg_len = utils.read_compact_int(buf, off)
    if (msg_len == nil or msg_len < 0) then return nil end
    return msg_len
end

-- Read message type contained in buf.
-- @param buf Input buffer.
-- @param off Offset to message type.
-- @return qd_message_type.
local function read_msg_type(buf, off)
    qd_message_type = {}
    qd_message_type.val_uint = buf(off, 1):uint()
    qd_message_type.val_str = utils.enum_val_to_str(fields.message_type,
                                                    qd_message_type.val_uint)
    return qd_message_type
end

-- Read full length of the received message.
-- @param buf Input buffer.
-- @param off Offset in input buffer.
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

-- Dissect input message.
-- @param proto Protocol object.
-- @param tvb_buf Input buffer.
-- @param off Offset in input buffer
-- @param packet_info Packet information.
-- @param tree Tree for display fields in Wireshark.
-- @return dissection_result.
function qd.dissect(proto, tvb_buf, off, packet_info, tree)
    dissection_result = {}
    -- Read full message length.
    local full_msg_len, compact_len, msg_len = qd.read_full_msg(tvb_buf, off)
    dissection_result.qd_full_msg_len = full_msg_len
    if (full_msg_len <= 0) then return dissection_result end

    -- Fill message length.
    local len_off = off
    local len_sizeof = compact_len
    local len = msg_len

    -- If message length zero, then this HEARTBEAT.
    if (len == 0) then
        -- Fill tree.
        local subtree = tree:add(proto, tvb_buf(off, full_msg_len),
                                 "HEARTBEAT_ZERO_LENGTH")
        subtree:add(fields.qd.msg_len, tvb_buf(len_off, len_sizeof), len)
        subtree:add(fields.qd.msg_type, fields.message_type.HEARTBEAT)
        dissection_result.subtree = subtree
        return dissection_result
    end

    -- Get message type.
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
    subtree:add(fields.qd.msg_len, tvb_buf(len_off, len_sizeof), len)
    subtree:add(fields.qd.msg_type, tvb_buf(type_off, type_sizeof),
                type.val_uint)

    -- Creating a QD message for subsequent dissectors.
    local data_off = type_off + type_sizeof
    local data_len = len - type_sizeof
    qd_message = {}
    qd_message.type = type
    qd_message.data = tvb_buf(data_off, data_len)

    -- Fill dissection result
    dissection_result.qd_message = qd_message
    dissection_result.subtree = subtree
    return dissection_result
end

return qd
