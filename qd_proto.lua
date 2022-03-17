-- @file qd_proto.lua
-- @brief Main plugin file. Contains functions that Wireshark calls.
package.prepend_path(Dir.global_plugins_path())
local settings = require("qd_proto.settings")
local utils = require("qd_proto.utils")
local qd = require("qd_proto.dissectors.qd")
local data_struct = require("qd_proto.data_struct")
local heartbeat = require("qd_proto.dissectors.heartbeat")
local describe_protocol = require("qd_proto.dissectors.describe_protocol")
local describe_records = require("qd_proto.dissectors.describe_records")
local add_subscription = require("qd_proto.dissectors.add_subscription")
local data = require("qd_proto.dissectors.data")
local remove_subscription = require("qd_proto.dissectors.remove_subscription")

-- Creates the protocol object.
local qd_proto = Proto("QD", "Quote Distribution protocol")
-- Registers the fields for Wireshark.
utils.append_to_table(qd_proto.fields, qd.ws_fields)
utils.append_to_table(qd_proto.fields, heartbeat.ws_fields)
utils.append_to_table(qd_proto.fields, describe_protocol.ws_fields)
utils.append_to_table(qd_proto.fields, describe_records.ws_fields)
utils.append_to_table(qd_proto.fields, add_subscription.ws_fields)
utils.append_to_table(qd_proto.fields, data.ws_fields)
utils.append_to_table(qd_proto.fields, remove_subscription.ws_fields)

-- Called Wireshark when plugin loading.
function qd_proto.init()
    if settings.is_init == false then
        settings.is_init = true
        settings.register_preference(qd_proto)
        settings.enable_dissector(qd_proto)
    end
end

-- Called Wireshark when user change preference.
function qd_proto.prefs_changed()
    -- Enable/Disable.
    if settings.is_enabled ~= qd_proto.prefs.is_enabled then
        settings.is_enabled = qd_proto.prefs.is_enabled
        if settings.is_enabled == true then
            settings.enable_dissector(qd_proto)
        else
            settings.disable_dissector(qd_proto)
        end
    end

    -- Set TCP port.
    if settings.port ~= qd_proto.prefs.port then
        settings.disable_dissector(qd_proto)
        settings.port = qd_proto.prefs.port
        if settings.is_enabled == true then
            settings.enable_dissector(qd_proto)
        end
    end
end

-- Parses QD message.
-- @param proto The protocol object.
-- @param type The type of QD message.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The subtree for display fields in Wireshark.
local function parse_message(proto, type, tvb_buf, packet_info, subtree)
    if (type == nil or tvb_buf:len() == 0) then return end
    type = type.val_uint
    if (type == data_struct.qd_type.HEARTBEAT) then
        heartbeat.dissect(proto, tvb_buf, packet_info, subtree)
    elseif (type == data_struct.qd_type.DESCRIBE_PROTOCOL) then
        describe_protocol.dissect(proto, tvb_buf, packet_info, subtree)
    elseif (type == data_struct.qd_type.DESCRIBE_RECORDS) then
        describe_records.dissect(proto, tvb_buf, packet_info, subtree)
    elseif (type == data_struct.qd_type.TICKER_ADD_SUBSCRIPTION or
            type == data_struct.qd_type.HISTORY_ADD_SUBSCRIPTION or
            type == data_struct.qd_type.STREAM_ADD_SUBSCRIPTION) then
        add_subscription.dissect(type, proto, tvb_buf, packet_info, subtree)
    elseif (type == data_struct.qd_type.TICKER_DATA or
            type == data_struct.qd_type.HISTORY_DATA or
            type == data_struct.qd_type.STREAM_DATA) then
        data.dissect(proto, tvb_buf, packet_info, subtree, describe_records)
    elseif (type == data_struct.qd_type.TICKER_REMOVE_SUBSCRIPTION or
            type == data_struct.qd_type.HISTORY_REMOVE_SUBSCRIPTION or
            type == data_struct.qd_type.STREAM_REMOVE_SUBSCRIPTION) then
        remove_subscription.dissect(proto, tvb_buf, packet_info, subtree)
    end
end

-- Called Wireshark when package captured.
-- @param tvb_buf The Tvb represents the packet’s buffer.
--                It is passed as an argument to dissectors,
--                and can be used to extract information (via TvbRange)
--                from the packet’s data.
-- @param packet_info The packet information.
-- @param tree The TreeItem represent information in the packet details pane
--             of Wireshark, and the packet details view of TShark.
-- @return 0             - if the packet does not belong to your dissector;
--         tvb_buf:len() - and set desegment_offset/desegment_len
--                         if needs more bytes;
--         tvb_buf:len() - if don't need more bytes.
function qd_proto.dissector(tvb_buf, packet_info, tree)
    -- Do not process empty packages.
    local len = tvb_buf:len()
    if len == 0 then return 0 end

    local byte_processed = 0
    while byte_processed < len do
        -- Dissects the QD message.
        local result = qd.dissect(qd_proto, tvb_buf, byte_processed,
                                  packet_info, tree)
        if result.qd_full_msg_len > 0 then
            -- This is QD message.
            packet_info.cols.protocol = qd_proto.name
            -- Parses QD message.
            parse_message(qd_proto, result.qd_message.type,
                          result.qd_message.data, packet_info, result.subtree)
            -- Tries to find the next QD message in this packet.
            byte_processed = byte_processed + result.qd_full_msg_len
        elseif result.qd_full_msg_len == 0 then
            -- Ignoring package.
            return 0
        else
            -- Offset in the tvb at which the dissector
            -- will continue processing when next called.
            packet_info.desegment_offset = byte_processed
            -- Estimated number of additional bytes required
            -- for completing the PDU.
            packet_info.desegment_len = -result.qd_full_msg_len
            -- In this case return tvb length.
            return len
        end
    end
    -- Returns count handled bytes.
    return byte_processed
end
