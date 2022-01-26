-- @file qd.lua
-- @brief Dissector QD message.
package.prepend_path("../")
local utils = require("utils")
local fields = require("fields")
local dbg = require("dbg")

local qd = {}

-- Check length input buffer.
-- @param buf Input buffer.
-- @param off Offset in input buffer.
-- @return true  - if buffer size and offset is correct;
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
    if ((buf:len()) - off ~= buf:reported_length_remaining(off)) then
        return false
    end
    return true
end

-- Check compact length contained in buf.
-- @param buf Input buffer.
-- @param off Offset to compact length.
-- @return true  - if compact length may fit in buffer;
--         false - if not.
local function check_compact_len(buf, off)
    local n = buf(off, 1):uint()
    local compact_len = utils.get_compact_len(n)
    local buf_len = buf:len() - off
    if (compact_len > buf_len) then
        return false
    else
        return true
    end
end

-- Check message length contained in buf.
-- @param buf Input buffer.
-- @param off Offset to message length.
-- @return true  - if message length success read;
--         false - if not.
local function check_msg_len(buf, off)
    local msg_len = utils.read_compact_int(buf, off)
    if (msg_len == nil or msg_len < 0) then
        return false
    else
        return true
    end
end

-- Get message type.
-- @param buf Input buffer.
-- @param off Offset to message type.
-- @return Message type.
local function get_msg_type(buf, off)
    local type = {}
    -- Message type num.
    type.val_uint = buf(off, 1):uint()
    -- String representation message type.
    type.val_str = utils.enum_val_to_str(fields.message_type, type.val_uint)
    return type
end

-- Check receive message.
-- @param buf Input buffer.
-- @param off Offset in input buffer.
-- @return  0  - this not QD message;
--         <0  - size input buffer not enough for assemble
--               full QD message (negative num bytes, num which are missing);
--         >0, - full size QD message.
function qd.check_msg(buf, off)
    local result = check_input_buf_len(buf, off)
    if (result == false) then
        dbg.warn(dbg.file(), dbg.line(), "Bad input buffer length.")
        return 0
    end

    local result = check_input_buf_cut_off(buf, off)
    if (result == false) then
        dbg.warn(dbg.file(), dbg.line(),
                 "Captured packet was shorter than original, can't reassemble.")
        return 0
    end

    local result = check_compact_len(buf, off)
    if (result == false) then
        dbg.info(dbg.file(), dbg.line(),
                 "Not enough buffer length for get compact_len.")
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    local result = check_msg_len(buf, off)
    if (result == false) then
        dbg.warn(dbg.file(), dbg.line(), "Bad message length.")
        return 0
    end

    local msg_len, msg_len_size = utils.read_compact_int(buf, off)
    local buf_len = buf:len() - off
    local full_msg_len = msg_len_size + msg_len
    if (full_msg_len > buf_len) then
        dbg.info(dbg.file(), dbg.line(), "Need more data for build message.")
        return -(full_msg_len - buf_len)
    end

    return full_msg_len
end

-- Dissect input message.
-- @param proto Protocol object.
-- @param tvb Input buffer.
-- @param off Offset in input buffer
-- @param pinfo Package info.
-- @param tree Tree for display fields in Wireshark.
-- @return  0  - this not QD message;
--         <0  - size input buffer not enough for assemble
--               full QD message (negative num bytes, num which are missing);
--         >0, - full size QD message, message data (may be nil) and subtree.
function qd.dissect(proto, tvb, off, pinfo, tree)
    -- Check input buf.
    local full_msg_len = qd.check_msg(tvb, off)
    if (full_msg_len <= 0) then return full_msg_len end

    -- Get message length.
    local len_off = off
    local len, len_size = utils.read_compact_int(tvb, off)

    -- If message length zero, then this HEARTBEAT.
    if (len == 0) then
        -- Fill tree.
        local subtree = tree:add(proto, tvb(off, full_msg_len),
                                 "HEARTBEAT_ZERO_LENGTH")
        subtree:add(fields.qd.msg_len, tvb(len_off, len_size), len)
        subtree:add(fields.qd.msg_type, fields.message_type.HEARTBEAT)
        return full_msg_len, nil, subtree
    end

    -- Get message type.
    local type_off = len_off + len_size
    local type_size = 1
    local type = get_msg_type(tvb, type_off)
    if (utils.is_empty_str(type.val_str) == true) then
        dbg.error(dbg.file(), dbg.line(), "Unknown message type.")
        return 0
    end

    -- Fill tree.
    local subtree = tree:add(proto, tvb(off, full_msg_len), type.val_str)
    subtree:add(fields.qd.msg_len, tvb(len_off, len_size), len)
    subtree:add(fields.qd.msg_type, tvb(type_off, type_size), type.val_uint)

    -- Creating a QD message for subsequent dissectors.
    local data_off = type_off + type_size
    local data_size = len - type_size
    local qd_message = {type = type, data = tvb(data_off, data_size)}
    return full_msg_len, qd_message, subtree
end

return qd
