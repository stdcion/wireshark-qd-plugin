-- @file add_subscription.lua
-- @brief The TICKER_ADD_SUBSCRIPTION, HISTORY_ADD_SUBSCRIPTION and
--        STREAM_ADD_SUBSCRIPTION message dissector.
package.prepend_path(Dir.global_plugins_path())
local dbg = require("qd_proto.dbg")
local utils = require("qd_proto.utils")
local data_struct = require("qd_proto.data_struct")
local binary_reader = require("qd_proto.io.stream_reader")
local symbol_reader = require("qd_proto.io.symbol_reader"):new()

local add_subscription = {}

-- List of *_ADD_SUBSCRIPTION fields to display in Wireshark.
add_subscription.ws_fields = {
    symbol = ProtoField.string("qd.add_subscription.symbol", "Symbol",
                               base.UNICODE),
    rid = ProtoField.uint32("qd.add_subscription.rid", "Record ID", base.DEC),
    from_time = ProtoField.absolute_time("qd.add_subscription.from_time",
                                         "From Time", base.UTC)
}

-- Displays *_add_subscription message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
-- @param type The QD message type.
local function display(stream, tree, type)
    local ws_fields = add_subscription.ws_fields

    -- Parses and displays symbol.
    local symbol, symbol_range = symbol_reader:read_symbol(stream)
    tree:add(ws_fields.symbol, symbol_range, symbol)

    -- Parses and displays id.
    local rid, rid_range = stream:read_compact_int()
    tree:add(ws_fields.rid, rid_range, rid)

    -- Parses and displays time (if present).
    if (type == data_struct.qd_type.HISTORY_ADD_SUBSCRIPTION) then
        local time, time_range = stream:read_compact_long()
        if (time ~= 0) then
            local millis = (time:rshift(32) * 1000) + time:band(0xFFFFFFFF)
            local ns_time = utils.millis_to_nstime(millis)
            tree:add(ws_fields.from_time, time_range, ns_time)
        end
    end

    -- Appends an symbol and rid to the tree header.
    tree:append_text(", ")
    tree:append_text("Symbol: " .. symbol)
    tree:append_text(", ")
    tree:append_text("ID: " .. rid)
end

-- Dissects the *_ADD_SUBSCRIPTION message.
-- @param type The QD message type.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function add_subscription.dissect(type, proto, tvb_buf, packet_info, subtree)
    local res, err = pcall(function()
        symbol_reader:reset()
        local br = binary_reader:new(tvb_buf, 0)
        while br:is_empty() ~= true do display(br, subtree, type) end
    end)
    if (res == false) then dbg.error(dbg.file(), dbg.line(), err) end
end

return add_subscription
