-- @file heartbeat.lua
-- @brief The HEARTBEAT message dissector.
package.prepend_path(Dir.global_plugins_path())
local utils = require("qd_proto.utils")
local stream_reader = require("qd_proto.io.stream_reader")

local heartbeat = {}

-- Bit flags content byte.
-- Each bit determines which fields are present in this message.
local content = {
    EMPTY = 0,
    TIME_MILLIS = 1,
    TIME_MARK = 2,
    DELTA_MARK = 4,
    LAG_MARK = 8
}

-- List of HEARTBEAT fields to display in Wireshark.
-- @note Some fields have a built-in type ProtoField.int64, but in fact the
-- maximum value this fields is limited to 32-bits, this is done because
-- compact_int type is used which can take up more then 32-bit, but value
-- limited 32-bit (MSB bits define sizeof field).
heartbeat.ws_fields = {
    -- Content byte.
    content = ProtoField.uint8("qd.heartbeat.content", "Content", base.HEX),
    -- Contest bit flags.
    content_millis = ProtoField.bool("qd.heartbeat.content.has_millis",
                                     "HAS_MILLIS", 4, nil, content.TIME_MILLIS),
    content_time_mark = ProtoField.bool("qd.heartbeat.content.has_mark",
                                        "HAS_TIME_MARK", 4, nil,
                                        content.TIME_MARK),
    content_delta_mark = ProtoField.bool("qd.heartbeat.content.has_delta",
                                         "HAS_DELTA_MARK", 4, nil,
                                         content.DELTA_MARK),
    content_lag_mark = ProtoField.bool("qd.heartbeat.content.has_lag",
                                       "HAS_LAG_MARK", 4, nil, content.LAG_MARK),
    time_mills = ProtoField.int64("qd.heartbeat.time_mills",
                                  "Time Milliseconds", base.DEC),
    time_utc = ProtoField.absolute_time("qd.heartbeat.time_utc", "Time UTC",
                                        base.UTC),
    -- int32
    time_mark = ProtoField.int64("qd.heartbeat.time_mark", "Time Mark", base.DEC),
    -- int32
    delta_mark = ProtoField.int64("qd.heartbeat.delta_mark", "Delta Mark",
                                  base.DEC),
    -- int32
    lag_mark = ProtoField.int64("qd.heartbeat.lag_mark", "Lag Mark", base.DEC)
}

local function is_empty_content(content_byte)
    return content_byte == content.EMPTY
end

local function has_time_millis(content_byte)
    return (bit.band(content_byte, content.TIME_MILLIS) ~= 0) and true or false
end

local function has_time_mark(content_byte)
    return (bit.band(content_byte, content.TIME_MARK) ~= 0) and true or false
end

local function has_delta_mark(content_byte)
    return (bit.band(content_byte, content.DELTA_MARK) ~= 0) and true or false
end

local function has_lag_mark(content_byte)
    return (bit.band(content_byte, content.LAG_MARK) ~= 0) and true or false
end

-- Displays HEARTBEAT message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display(stream, tree)
    -- Handles a byte of content.
    local content_byte, content_range = stream:read_uint8()

    local ws_fields = heartbeat.ws_fields
    -- Adds content subtree.
    local content_flags_tree = tree:add(ws_fields.content, content_range,
                                        content_byte)
    -- Adds content bit field to subtree.
    content_flags_tree:add(ws_fields.content_millis, content_range)
    content_flags_tree:add(ws_fields.content_time_mark, content_range)
    content_flags_tree:add(ws_fields.content_delta_mark, content_range)
    content_flags_tree:add(ws_fields.content_lag_mark, content_range)

    if (is_empty_content(content_byte)) then return end

    -- Handles the fields.
    if (has_time_millis(content_byte)) then
        local time_millis, time_millis_range = stream:read_compact_long()
        local ns_time = utils.millis_to_nstime(time_millis)
        tree:add(ws_fields.time_mills, time_millis_range, time_millis)
        tree:add(ws_fields.time_utc, time_millis_range, ns_time)
    end
    if (has_time_mark(content_byte)) then
        local time_mark, time_mark_range = stream:read_compact_int()
        time_mark = utils.int_to_long(time_mark)
        tree:add(ws_fields.time_mark, time_mark_range, time_mark)
    end
    if (has_delta_mark(content_byte)) then
        local delta_mark, delta_mark_range = stream:read_compact_int()
        delta_mark = utils.int_to_long(delta_mark)
        tree:add(ws_fields.delta_mark, delta_mark_range, delta_mark)
    end
    if (has_lag_mark(content_byte)) then
        local lag_mark, lag_mark_range = stream:read_compact_int()
        lag_mark = utils.int_to_long(lag_mark)
        tree:add(ws_fields.lag_mark, lag_mark_range, lag_mark)
    end
end

-- Dissects the HEARTBEAT message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function heartbeat.dissect(proto, tvb_buf, packet_info, subtree)
    local res, err = pcall(function()
        local sr = stream_reader:new(tvb_buf, 0)
        while (sr:is_empty() ~= true) do display(sr, subtree) end
    end)
    if (res == false) then error(err) end
end

return heartbeat
