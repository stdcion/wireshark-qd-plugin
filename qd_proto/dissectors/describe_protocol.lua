-- @file describe_protocol.lua
-- @brief The DESCRIBE_PROTOCOL message dissector.
package.prepend_path(Dir.global_plugins_path())
local utils = require('qd_proto.utils')
local stream_reader = require("qd_proto.io.stream_reader")

local describe_protocol = {}

-- List of *DESCRIBE_PROTOCOL fields to display in Wireshark.
describe_protocol.ws_fields = {
    magic = ProtoField.string("qd.describe_protocol.magic", "Magic",
                              base.UNICODE)
}

-- Displays properties in DESCRIBE_PROTOCOL.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display_properties(stream, tree)
    local count = stream:read_compact_int()
    if (count > 0) then
        local sub = tree:add("Properties")
        for _ = 1, count, 1 do
            local start_pos = stream:get_current_pos()
            local key = stream:read_utf8_str()
            local val = stream:read_utf8_str()

            local range = stream:get_range(start_pos, stream:get_current_pos())
            sub:add(range, key .. ": " .. val)
        end
    end
end

-- Displays descriptors in DESCRIBE_PROTOCOL.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
-- @param name The name descriptors.
local function display_descriptors(stream, tree, name)
    local count = stream:read_compact_int()
    if (count > 0) then
        local sub = tree:add(name)
        for _ = 1, count, 1 do
            local start_pos = stream:get_current_pos()
            local id = stream:read_compact_int()
            local name = stream:read_utf8_str()

            local range = stream:get_range(start_pos, stream:get_current_pos())
            sub:add(range, name .. ": " .. id)
            -- If presents.
            display_properties(stream, tree)
        end
    end
end

-- Displays Endpoint ID in DESCRIBE_PROTOCOL.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display_endpoint_id(stream, tree)
    local sub = tree:add("Endpoint ID")

    local jvm_id, jvm_id_range = stream:read_byte_array()
    sub:add(jvm_id_range, "JVM ID: " .. jvm_id:tohex())

    local name, name_range = stream:read_utf8_str()
    sub:add(name_range, "Name: " .. name)

    local id, id_range = stream:read_compact_long()
    sub:add(id_range, "ID: " .. id)
end

-- Displays DESCRIBE_PROTOCOL message in Wireshark.
-- @param stream Represents the input buffer.
-- @param tree The tree for display.
local function display(stream, tree)
    local ws_fields = describe_protocol.ws_fields

    -- Parses and displays magic.
    local magic, magic_range = stream:read_uint32()
    tree:add(ws_fields.magic, magic_range, utils.codepoint_to_char(magic))

    -- Parsers and displays fields DESCRIBE_PROTOCOL. 
    display_properties(stream, tree)
    display_descriptors(stream, tree, "Send Descriptors")
    display_descriptors(stream, tree, "Receive Descriptors")

    -- Process extension bytes (if present).
    if (stream:is_empty() ~= true) then display_endpoint_id(stream, tree) end
end

-- Dissects the DESCRIBE_PROTOCOL message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function describe_protocol.dissect(proto, tvb_buf, packet_info, subtree)
    local res, err = pcall(function()
        local sr = stream_reader:new(tvb_buf, 0)
        while (sr:is_empty() ~= true) do display(sr, subtree) end
    end)
    if (res == false) then error(err) end
end

return describe_protocol
