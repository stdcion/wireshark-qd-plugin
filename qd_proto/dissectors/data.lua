-- @file data.lua
-- @brief The TICKER_DATA, HISTORY_DATA and STREAM_DATA message dissector.
package.prepend_path(Dir.global_plugins_path())
local utils = require("qd_proto.utils")
local data_struct = require("qd_proto.data_struct")
local stream_reader = require("qd_proto.io.stream_reader")
local symbol_reader = require("qd_proto.io.symbol_reader"):new()
local field_reader = require("qd_proto.io.field_reader")

local data = {}

-- List of *_DATA fields to display in Wireshark.
data.ws_fields = {
    symbol = ProtoField.string("qd.data.symbol", "Symbol", base.UNICODE),
    rid = ProtoField.uint32("qd.data.rid", "Record ID", base.DEC),
    flags = ProtoField.uint8("qd.data.flags", "Flags", base.HEX),
    flags_tx_pending = ProtoField.bool("qd.data.flags.tx_pending", "TX_PENDING",
                                       8, nil,
                                       data_struct.event_flags.TX_PENDING),
    flags_remove_event = ProtoField.bool("qd.data.flags.remove_event",
                                         "REMOVE_EVENT", 8, nil,
                                         data_struct.event_flags.REMOVE_EVENT),
    flags_snapshot_begin = ProtoField.bool("qd.data.flags.snapshot_begin",
                                           "SNAPSHOT_BEGIN", 8, nil,
                                           data_struct.event_flags
                                               .SNAPSHOT_BEGIN),
    flags_snapshot_end = ProtoField.bool("qd.data.flags.snapshot_end",
                                         "SNAPSHOT_END", 8, nil,
                                         data_struct.event_flags.SNAPSHOT_END),
    flags_snapshot_snip = ProtoField.bool("qd.data.flags.snapshot_snip",
                                          "SNAPSHOT_SNIP", 8, nil,
                                          data_struct.event_flags.SNAPSHOT_SNIP),
    flags_reserved = ProtoField.bool("qd.data.flags.reserved", "RESERVER", 8,
                                     nil, data_struct.event_flags.RESERVED),
    flags_snapshot_mode = ProtoField.bool("qd.data.flags.reserved",
                                          "SNAPSHOT_MODE", 8, nil,
                                          data_struct.event_flags.SNAPSHOT_MODE),
    flags_remove_symbol = ProtoField.bool("qd.data.flags.remove_symbol",
                                          "REMOVE_SYMBOL", 8, nil,
                                          data_struct.event_flags.REMOVE_SYMBOL)
}

-- List of string representation field types. 
local field_types = utils.enum_tbl_to_str_tbl(data_struct.field_type)

-- Displays *_data message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
-- @param describe_records The describe record message dissector.
local function display(stream, tree, describe_records)
    local ws_fields = data.ws_fields
    local start_pos = stream:get_current_pos()

    -- Parses symbol.
    local symbol, symbol_range, flags, flags_range =
        symbol_reader:read_symbol(stream)

    -- Parses record id.
    local rid, rid_range = stream:read_compact_int()

    -- Parses field.
    local fields = nil
    -- Finds record_digest by id.
    local record_digest = describe_records.get_record_digest(rid)
    if (record_digest ~= nil) then
        fields = {}
        if (utils.is_flag_set(flags, data_struct.event_flags.REMOVE_EVENT)) then
            -- If the remove_event flag is set, only the service field is read.
            local val, range = stream:read_compact_long()
            fields[1] = {
                name = "Service Field",
                type = data_struct.field_type.LONG,
                val = val,
                range = range
            }
        else
            for i, field in ipairs(record_digest.fields) do
                local val, range = field_reader.read_field(stream, field.type)
                fields[i] = {
                    name = field.name,
                    type = field.type,
                    val = val,
                    range = range
                }
            end
        end
    end

    -- Create subtree for symbol data.
    local sub = tree:add(ws_fields.symbol,
                         stream:get_range(start_pos, stream:get_current_pos()),
                         symbol)
    -- Displays flags.
    if (flags ~= nil) then
        -- Adds flags subtree.
        local flags_tree = sub:add(ws_fields.flags, flags_range, flags)
        -- Adds flags bit field to subtree.
        flags_tree:add(ws_fields.flags_tx_pending, flags_range, flags)
        flags_tree:add(ws_fields.flags_remove_event, flags_range, flags)
        flags_tree:add(ws_fields.flags_snapshot_begin, flags_range, flags)
        flags_tree:add(ws_fields.flags_snapshot_end, flags_range, flags)
        flags_tree:add(ws_fields.flags_snapshot_snip, flags_range, flags)
        flags_tree:add(ws_fields.flags_reserved, flags_range, flags)
        flags_tree:add(ws_fields.flags_snapshot_mode, flags_range, flags)
        flags_tree:add(ws_fields.flags_remove_symbol, flags_range, flags)
    end

    -- Displays symbol.
    sub:add(ws_fields.symbol, symbol_range, symbol)

    -- Displays record id.
    sub:add(ws_fields.rid, rid_range, rid)

    -- Throw an error if record_digest is not found because fields cannot be parsed.
    if (record_digest == nil) then error("Unknown Record ID") end
    -- Displays fields.
    if (fields ~= nil) then
        for _, field in pairs(fields) do
            local str = field.name
            str = str .. "("
            str = str .. field_types[field.type]
            str = str .. ")"
            str = str .. ": "
            if (field.val ~= nil) then
                str = str .. field.val
            end
            sub:add(field.range, str)
        end
    end

    -- Appends additional data to the tree header.
    sub:append_text(", ")
    sub:append_text("Record Name: " .. record_digest.name)
    sub:append_text(", ")
    sub:append_text("ID: " .. rid)
    sub:append_text(", ")
    if (flags ~= nil) then
        sub:append_text("Flags: " ..
                            utils.bit_flags_to_str(data_struct.event_flags,
                                                   flags))
    end
end

-- Dissects the *_DATA message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
-- @param describe_records The describe record message dissector.
function data.dissect(proto, tvb_buf, packet_info, subtree, describe_records)
    local res, err = pcall(function()
        symbol_reader:reset()
        local sr = stream_reader:new(tvb_buf, 0)
        while (sr:is_empty() ~= true) do
            display(sr, subtree, describe_records)
        end
    end)
    if (res == false) then error(err) end
end

return data
