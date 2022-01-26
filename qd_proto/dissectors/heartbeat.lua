-- @file heartbeat.lua
-- @brief Provides dissector for HEARTBEAT message type.
package.prepend_path("../")
local utils = require("utils")
local fields = require("fields")
local dbg = require("dbg")

local heartbeat = {}

local content = {
    EMPTY = 0,
    TIME_MILLIS = 1,
    TIME_MARK = 2,
    DELTA_MARK = 4,
    LAG_MARK = 8
}

local function has_time_millis(contentBit)
    return (bit.band(contentBit, content.TIME_MILLIS) ~= 0) and true or false
end

local function has_time_mark(contentBit)
    return (bit.band(contentBit, content.TIME_MARK) ~= 0) and true or false
end

local function has_delta_mark(contentBit)
    return (bit.band(contentBit, content.DELTA_MARK) ~= 0) and true or false
end

local function has_lag_mark(contentBit)
    return (bit.band(contentBit, content.LAG_MARK) ~= 0) and true or false
end

function heartbeat.dissect(proto, tvb, off, pinfo, tree)
    local content_byte = tvb(off, 1):uint()
    off = off + 1
    if (has_time_millis(content_byte)) then
        local time_millis, time_millis_size = utils.read_compact_long(tvb, off)
        tree:add(fields.qd.heartbeat_time_millis, tvb(off, time_millis_size),
                 time_millis)
        off = off + time_millis_size
    end
    if (has_time_mark(content_byte)) then
        local time_mark, time_mark_size = utils.read_compact_int(tvb, off)
        tree:add(fields.qd.heartbeat_time_mark, tvb(off, time_mark_size),
                 Int64(time_mark, 0))
        off = off + time_mark_size
    end
    if (has_delta_mark(content_byte)) then
        local delta_mark, delta_mark_size = utils.read_compact_int(tvb, off)
        tree:add(fields.qd.heartbeat_delta_mark, tvb(off, delta_mark_size),
                 Int64(delta_mark, 0))
        off = off + delta_mark_size
    end
    if (has_lag_mark(content_byte)) then
        local lag_mark, lag_mark_size = utils.read_compact_int(tvb, off)
        tree:add(fields.qd.heartbeat_lag_mark, tvb(off, lag_mark_size),
                 Int64(lag_mark, 0))
        off = off + lag_mark_size
    end
end

return heartbeat
