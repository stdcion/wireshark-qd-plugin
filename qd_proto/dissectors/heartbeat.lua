-- @file heartbeat.lua
-- @brief The HEARTBEAT message dissector.
package.prepend_path(Dir.global_plugins_path())
local utils = require("qd_proto.utils")
local dbg = require("qd_proto.dbg")

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

-- List of HEARTBEAT fields.
-- @note Some fields have a built-in type ProtoField.int64, but in fact the
-- maximum value this fields is limited to 32-bits, this is done because
-- compact_int type is used which can take up more then 32-bit, but value
-- limited 32-bit (MSB bits define sizeof field).
heartbeat.fields = {
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

-- Dissects the HEARTBEAT message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function heartbeat.dissect(proto, tvb_buf, packet_info, subtree)
    local off = 0
    -- Handles a byte of content.
    local content_range = tvb_buf(off, 1)
    local content_byte = content_range:uint()
    if (content_byte == nil) then
        dbg.error(dbg.file(), dbg.line(), "Can't read content_byte.")
    end

    local fields = heartbeat.fields
    -- Adds content subtree.
    local content_flags_tree = subtree:add(fields.content, content_range,
                                           content_byte)
    -- Adds content bit field to subtree.
    content_flags_tree:add(fields.content_millis, content_range)
    content_flags_tree:add(fields.content_time_mark, content_range)
    content_flags_tree:add(fields.content_delta_mark, content_range)
    content_flags_tree:add(fields.content_lag_mark, content_range)

    if (is_empty_content(content_byte)) then return end

    -- Handles the fields.
    off = off + 1
    if (has_time_millis(content_byte)) then
        local time_millis = utils.read_compact_long(tvb_buf, off)
        if (time_millis == nil) then
            dbg.error(dbg.file(), dbg.line(), "Can't read time_millis.")
            return
        end
        local time_millis_range = tvb_buf(off, time_millis.sizeof)
        -- Displays in milliseconds.
        subtree:add(fields.time_mills, time_millis_range, time_millis.val)

        -- Gets the time in second.
        local sec = (time_millis.val / 1000):tonumber()
        -- Gets the remainder in nanoseconds
        local nanosec_remainder = (time_millis.val % 1000):tonumber() * 1000000
        -- Displays the time in UTC.
        local ns_time = NSTime(sec, nanosec_remainder)
        subtree:add(fields.time_utc, time_millis_range, ns_time)
        off = time_millis.next_pos
    end
    if (has_time_mark(content_byte)) then
        local time_mark = utils.read_compact_int(tvb_buf, off)
        if (time_mark == nil) then
            dbg.error(dbg.file(), dbg.line(), "Can't read time_mark.")
            return
        end
        local time_mark_range = tvb_buf(off, time_mark.sizeof)
        time_mark.val = utils.int_to_long(time_mark.val)
        subtree:add(fields.time_mark, time_mark_range, time_mark.val)
        off = time_mark.next_pos
    end
    if (has_delta_mark(content_byte)) then
        local delta_mark = utils.read_compact_int(tvb_buf, off)
        if (delta_mark == nil) then
            dbg.error(dbg.file(), dbg.line(), "Can't read delta_mark.")
            return
        end
        local delta_mark_range = tvb_buf(off, delta_mark.sizeof)
        delta_mark.val = utils.int_to_long(delta_mark.val)
        subtree:add(fields.delta_mark, delta_mark_range, delta_mark.val)
        off = delta_mark.next_pos
    end
    if (has_lag_mark(content_byte)) then
        local lag_mark = utils.read_compact_int(tvb_buf, off)
        if (lag_mark == nil) then
            dbg.error(dbg.file(), dbg.line(), "Can't read lag_mark.")
            return
        end
        local lag_mark_range = tvb_buf(off, lag_mark.sizeof)
        lag_mark.val = utils.int_to_long(lag_mark.val)
        subtree:add(fields.lag_mark, lag_mark_range, lag_mark.val)
        off = lag_mark.next_pos
    end
end

return heartbeat
