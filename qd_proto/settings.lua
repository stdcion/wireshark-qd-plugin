-- @file settings.lua
-- @brief Provides preference for dissector.
local settings = {}

-- Default settings.
settings = {
    -- Initialization flag.
    is_init = false,
    -- Enable flag.
    is_enabled = true,
    -- TCP port.
    port = 6666
}

-- Register preference in Wireshark.
-- @param proto Protocol object for which preferences are set.
function settings.register_preference(proto)
    proto.prefs.is_enabled = Pref.bool("Enabled", settings.is_enabled)
    proto.prefs.port = Pref.uint("TCP port", settings.port)
end

-- Enable dissector.
-- Add TCP port from settings to Wireshark.
-- @param proto Protocol object.
function settings.enable_dissector(proto)
    DissectorTable.get("tcp.port"):add(settings.port, proto)
end

-- Disable dissector.
-- Remove previously added TCP from Wireshark.
-- @param proto Protocol object.
function settings.disable_dissector(proto)
    DissectorTable.get("tcp.port"):remove(settings.port, proto)
end

return settings
