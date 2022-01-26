package.prepend_path("qd_proto")
local settings = require("settings")
local fields = require("fields")
local qd = require("dissectors/qd")

-- Create protocol object.
local qd_proto = Proto("QD", "Quote Distribution protocol")
-- Register fields for Wireshark.
qd_proto.fields = fields.qd

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

-- Called Wireshark when package captured.
function qd_proto.dissector(tvb, pinfo, tree)
    -- Do not process empty packages.
    local len = tvb:len()
    if len == 0 then return end

    local byte_processed = 0
    while byte_processed < len do
        -- Dissect QD message.
        local result, qd_message, qd_subtree =
            qd.dissect(qd_proto, tvb, byte_processed, pinfo, tree)
        if result > 0 then
            -- This is QD message.
            pinfo.cols.protocol = qd_proto.name
            -- Try find next QD message in this package.
            byte_processed = byte_processed + result
        elseif result == 0 then
            -- Ignoring package.
            return 0
        else
            -- Offset in the tvb at which the dissector
            -- will continue processing when next called.
            pinfo.desegment_offset = byte_processed
            -- Estimated number of additional bytes required
            -- for completing the PDU.
            pinfo.desegment_len = -result
            -- In this case return tvb length.
            return len
        end
    end
    -- Return count handled bytes.
    return byte_processed
end
