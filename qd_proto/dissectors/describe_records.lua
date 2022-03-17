-- @file describe_records.lua
-- @brief The DESCRIBE_RECORDS message dissector.
package.prepend_path(Dir.global_plugins_path())
local utils = require("qd_proto.utils")
local data_struct = require("qd_proto.data_struct")
local dbg = require("qd_proto.dbg")

local describe_records = {}

-- Map record digest.
describe_records.record_digest = {}

-- List of DESCRIBE_RECORDS fields to display in Wireshark.
describe_records.ws_fields = {
    record = ProtoField.string("qd.describe_records.record", "Record",
                               base.UNICODE),
    rid = ProtoField.uint32("qd.describe_records.rid", "Record ID", base.DEC),
    record_name = ProtoField.string("qd.describe_records.record_name",
                                    "Record Name", base.UNICODE),
    fields = ProtoField.uint32("qd.describe_records.fields", "Fields", base.DEC),
    fields_count = ProtoField.uint32("qd.describe_records.fields_count",
                                     "Fields Count", base.DEC),
    field = ProtoField.string("qd.describe_records.field", "Field", base.UNICODE),
    field_name = ProtoField.string("qd.describe_records.field_name",
                                   "Field Name", base.UNICODE),
    field_type = ProtoField.uint32("qd.describe_records.field_type",
                                   "Field Type", base.DEC,
                                   utils.enum_tbl_to_str_tbl(
                                       data_struct.field_type))
}

-- Parses field in DESCRIBE_RECORD message.
-- @param tvb_buf The input buffer.
-- @param off The offset in input buffer to field.
-- @param The field, or nil if error occurred.
local function parse_field(tv_buf, off)
    local field = {
        -- The starting position of the field in the buffer.
        start_pos = off,
        -- Field name.
        name = nil,
        -- Field type.
        type = nil,
        -- Field size in bytes.
        sizeof = nil,
        -- Offset for the next object in the buffer.
        next_pos = nil
    }

    field.name = utils.read_utf8_string(tv_buf, off)
    if field.name == nil then
        dbg.error(dbg.file(), dbg.line(), "Can't parses field name.")
        return nil
    end
    off = field.name.next_pos

    field.type = utils.read_compact_int(tv_buf, off)
    if field.type == nil then
        dbg.error(dbg.file(), dbg.line(), "Can't parses field type.")
        return nil
    end
    off = field.type.next_pos

    field.sizeof = off - field.start_pos
    field.next_pos = off
    return field
end

-- Parses fields in DESCRIBE_RECORD message.
-- @param tvb_buf The input buffer.
-- @param off The offset in input buffer to fields.
-- @param The fields, or nil if error occurred.
local function parse_fields(tv_buf, off)
    local fields = {
        -- The starting position of the count fields in the buffer.
        start_pos = off,
        -- Count fields in array.
        count = nil,
        -- Array of fields.
        arr = {},
        -- Size (count + fields array) in bytes.
        sizeof = nil,
        -- Offset for the next object in the buffer.
        next_pos = nil
    }

    fields.count = utils.read_compact_int(tv_buf, off)
    if fields.count == nil or fields.count.val < 0 then
        dbg.error(dbg.file(), dbg.line(), "Can't parses field count.")
        return nil
    end
    off = fields.count.next_pos

    for i = 1, fields.count.val do
        local field = parse_field(tv_buf, off)
        if field == nil then return nil end
        off = field.next_pos
        fields.arr[i] = field
    end

    fields.sizeof = off - fields.start_pos
    fields.next_pos = off
    return fields
end

-- Parses record in DESCRIBE_RECORD message.
-- @param tvb_buf The input buffer.
-- @param off The offset in input buffer to record.
-- @param The record, or nil if error occurred.
local function parse_record(tv_buf, off)
    local record = {
        -- The starting position of the record in the buffer.
        start_pos = off,
        -- The record ID.
        id = nil,
        -- The record name
        name = nil,
        -- Array of fields.
        fields = nil,
        -- Sizeof record in bytes.
        sizeof = nil,
        -- Offset for the next object in the buffer.
        next_pos = nil
    }

    record.id = utils.read_compact_int(tv_buf, off)
    if record.id == nil then
        dbg.error(dbg.file(), dbg.line(), "Can't parses record id.")
        return nil
    end
    off = record.id.next_pos

    record.name = utils.read_utf8_string(tv_buf, off)
    if record.name == nil then
        dbg.error(dbg.file(), dbg.line(), "Can't parses record name.")
        return nil
    end
    off = record.name.next_pos

    record.fields = parse_fields(tv_buf, off)
    if record.fields == nil then return nil end
    off = record.fields.next_pos

    record.sizeof = off - record.start_pos
    record.next_pos = off
    return record
end

-- Displays field in Wireshark.
-- @param field The field.
-- @param tvb_buf The input buffer.
-- @param tree The tree for display.
local function display_field(field, tvb_buf, tree)
    local ws_fields = describe_records.ws_fields
    local name = field.name
    local type = field.type
    local type_name = utils.enum_val_to_str(data_struct.field_type, type.val)

    -- Creates a subtree for field.
    local field_range = tvb_buf(name.start_pos, name.sizeof + type.sizeof)
    local field_tree = tree:add(ws_fields.field, field_range, "")
    -- Appends a name and type to the tree header.
    field_tree:append_text(name.val)
    field_tree:append_text("(")
    field_tree:append_text(type_name)
    field_tree:append_text(")")

    -- Adds name and type to the tree (for search by fields).
    local field_name_range = tvb_buf(name.start_pos, name.sizeof)
    field_tree:add(ws_fields.field_name, field_name_range, name.val)
    local field_type_range = tvb_buf(type.start_pos, type.sizeof)
    field_tree:add(ws_fields.field_type, field_type_range, type.val)
end

-- Displays fields in Wireshark.
-- @param field The fields.
-- @param tvb_buf The input buffer.
-- @param tree The tree for display.
local function display_fields(fields, tvb_buf, tree)
    local ws_fields = describe_records.ws_fields
    local count = fields.count

    -- Creates a subtree for fields.
    local fields_range = tvb_buf(fields.start_pos, fields.sizeof)
    local fields_tree = tree:add(ws_fields.fields, fields_range, count.val)

    -- Adds the number of fields to the tree (for searching by fields).
    local fields_count_range = tvb_buf(count.start_pos, count.sizeof)
    fields_tree:add(ws_fields.fields_count, fields_count_range, fields.count.val)

    -- Displays all fields.
    for i = 1, count.val do
        display_field(fields.arr[i], tvb_buf, fields_tree)
    end
end

-- Displays record in Wireshark.
-- @param record The record.
-- @param tvb_buf The input buffer.
-- @param tree The tree for display.
local function display_record(record, tvb_buf, tree)
    local ws_fields = describe_records.ws_fields
    local rid = record.id
    local record_name = record.name

    -- Creates a subtree for record.
    local record_range = tvb_buf(record.start_pos, record.sizeof)
    local record_tree = tree:add(ws_fields.record, record_range, "")
    -- Appends an id and name to the tree header.
    record_tree:append_text("ID: " .. record.id.val)
    record_tree:append_text(", ")
    record_tree:append_text("Name: " .. record.name.val)

    -- Adds an id and name to the tree (for search by fields).
    local rid_range = tvb_buf(rid.start_pos, rid.sizeof)
    record_tree:add(ws_fields.rid, rid_range, rid.val)
    local record_name_range = tvb_buf(record_name.start_pos, record_name.sizeof)
    record_tree:add(ws_fields.record_name, record_name_range, record_name.val)

    display_fields(record.fields, tvb_buf, record_tree)
end

-- Gets record digest byte record ID.
-- @param rid The record ID.
-- @return The record digest or nil, if record if was not found.
function describe_records.get_record_digest(rid)
    local record_digest = {name = nil, fields = {}}
    local fields = describe_records.record_digest[rid].fields.arr
    if fields == nil then return nil end
    for index, value in ipairs(describe_records.record_digest[rid].fields.arr) do
        record_digest.fields[index] = {}
        record_digest.fields[index].name = value.name.val
        record_digest.fields[index].type = value.type.val
    end
    record_digest.name = describe_records.record_digest[rid].name.val
    return record_digest
end

-- Dissects the DESCRIBE_RECORD message.
-- @param proto The protocol object.
-- @param tvb_buf The input buffer.
-- @param packet_info The packet information.
-- @param subtree The tree for display fields in Wireshark.
function describe_records.dissect(proto, tvb_buf, packet_info, subtree)
    local off = 0
    while off < tvb_buf:len() do
        local record = parse_record(tvb_buf, off)
        if record == nil then
            dbg.error(dbg.file(), dbg.line(), "Record parsing error.")
            break
        end
        -- Fills record digest.
        describe_records.record_digest[record.id.val] = record
        display_record(record, tvb_buf, subtree)
        off = record.next_pos
    end
end

return describe_records
