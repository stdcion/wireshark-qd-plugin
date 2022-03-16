-- @file remove_subscription.lua
-- @brief The TICKER_REMOVE_SUBSCRIPTION, HISTORY_REMOVE_SUBSCRIPTION and
--        STREAM_REMOVE_SUBSCRIPTION message dissector.
package.prepend_path(Dir.global_plugins_path())
local binary_reader = require("qd_proto.io.stream_reader")
local symbol_reader = require("qd_proto.io.symbol_reader"):new()

local remove_subscription = {}

-- List of *_REMOVE_SUBSCRIPTION fields to display in Wireshark.
remove_subscription.ws_fields = {
    symbol = ProtoField.string("qd.remove_subscription.symbol", "Symbol",
                               base.UNICODE),
    rid = ProtoField.uint32("qd.remove_subscription.rid", "Record ID", base.DEC)
}

-- Displays *_remove_subscription message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display(stream, tree)
    local ws_fields = remove_subscription.ws_fields

    -- Parses and displays symbol.
    local symbol, symbol_range = symbol_reader:read_symbol(stream)
    tree:add(ws_fields.symbol, symbol_range, symbol)

    -- Parses and displays id.
    local rid, rid_range = stream:read_compact_int()
    tree:add(ws_fields.rid, rid_range, rid)

    -- Appends an symbol and rid to the tree header.
    tree:append_text(", ")
    tree:append_text("Symbol: " .. symbol)
    tree:append_text(", ")
    tree:append_text("ID: " .. rid)
end

-- Dissects the *_REMOVE_SUBSCRIPTION message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function remove_subscription.dissect(proto, tvb_buf, packet_info, subtree)
    local res, err = pcall(function()
        symbol_reader:reset()
        local br = binary_reader:new(tvb_buf, 0)
        while (br:is_empty() ~= true) do display(br, subtree) end
    end)
    if (res == false) then error(err) end
end

return remove_subscription
