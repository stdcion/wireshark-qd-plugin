package.prepend_path(Dir.global_plugins_path())
local settings = require("qd_proto.settings")
local utils = require("qd_proto.utils")
local qd = require("qd_proto.dissectors.qd")
local heartbeat = require("qd_proto.dissectors.heartbeat")

-- Create protocol object.
local qd_proto = Proto("QD", "Quote Distribution protocol")
-- Register fields for Wireshark.
utils.append_to_table(qd_proto.fields, qd.fields)
utils.append_to_table(qd_proto.fields, heartbeat.fields)

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

-- Parse QD message.
-- @param proto Protocol object.
-- @param type QD message type.
-- @param tvb_buf Input buffer.
-- @param packet_info Packet information.
-- @param subtree Subtree for display fields in Wireshark
--                (for concrete type message).
local function parse_message(proto, type, tvb_buf, packet_info, subtree)
    if (type ~= nil and tvb_buf:len() ~= 0) then
        if (type.val_uint == qd.type.HEARTBEAT) then
            heartbeat.dissect(proto, tvb_buf, packet_info, subtree)
        end
    end
end

-- Called Wireshark when package captured.
-- @param tvb_buf Tvb represents the packet’s buffer. It is passed as an argument
--        to dissectors, and can be used to extract information (via TvbRange)
--        from the packet’s data.
-- @param packet_info Packet information.
-- @param tree TreeItem represent information in the packet details pane
--             of Wireshark, and the packet details view of TShark.
-- @return 0 - if the packet does not belong to your dissector,
--         tvb_buf:len() and set desegment_offset/desegment_len if needs more bytes,
--         tvb_buf:len() if don't need more bytes.
function qd_proto.dissector(tvb_buf, packet_info, tree)
    -- Do not process empty packages.
    local len = tvb_buf:len()
    if len == 0 then return 0 end

    local byte_processed = 0
    while byte_processed < len do
        -- Dissect QD message.
        local result = qd.dissect(qd_proto, tvb_buf, byte_processed,
                                  packet_info, tree)
        if result.qd_full_msg_len > 0 then
            -- This is QD message.
            packet_info.cols.protocol = qd_proto.name
            -- Parsing QD message.
            parse_message(qd_proto, result.qd_message.type,
                            result.qd_message.data, packet_info, result.subtree)
            -- Try find next QD message in this package.
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
    -- Return count handled bytes.
    return byte_processed
end
