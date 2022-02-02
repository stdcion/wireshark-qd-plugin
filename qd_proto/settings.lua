-- @file settings.lua
-- @brief Provides settings for the dissector.
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

-- Sets a preference in Wireshark.
-- @param proto The protocol object for which preferences are sets.
function settings.register_preference(proto)
    proto.prefs.is_enabled = Pref.bool("Enabled", settings.is_enabled)
    proto.prefs.port = Pref.uint("TCP port", settings.port)
end

-- Enables the dissector.
-- Adds a TCP port from settings to Wireshark.
-- @param proto The protocol object.
function settings.enable_dissector(proto)
    DissectorTable.get("tcp.port"):add(settings.port, proto)
end

-- Disables the dissector.
-- Removes a previously added TCP port from Wireshark.
-- @param proto The protocol object.
function settings.disable_dissector(proto)
    DissectorTable.get("tcp.port"):remove(settings.port, proto)
end

return settings
