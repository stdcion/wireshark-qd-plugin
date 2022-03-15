-- @file symbol_reader.lua
-- @brief Reads "symbol" data form the buffer.
package.prepend_path(Dir.global_plugins_path())
local penta_codec = require("qd_proto.format.penta_codec"):new()

local SymbolReader = {}

-- Creates a new instance of the SymbolReader class.
function SymbolReader:new()
    -- #region Private

    local private = {}

    private.MRU_EVENT_FLAGS = 1
    -- Most Recently Used flags.
    private.mru_event_flags = private.MRU_EVENT_FLAGS
    -- Current symbol.
    private.symbol = nil
    -- Current symbol range.
    private.symbol_range = nil
    -- Current events flags.
    private.event_flags = nil
    -- Current events flags range.
    private.event_flags_range = nil

    -- #endregion

    -- #region Public

    local public = {}

    -- Clears current symbol and event flags.
    function public:reset()
        private.mru_event_flags = private.MRU_EVENT_FLAGS
        private.symbol = nil
        private.symbol_range = nil
        private.event_flags = nil
        private.event_flags_range = nil
    end

    -- Reads symbol from stream.
    -- @throws BufferOutOfRange, FormatError.
    -- @param stream Represents the input buffer.
    -- @return symbol - the symbol,
    --         symbol_range - represents the range of the buf
    --                 where the symbol is stored.
    --         event - the event flags (may be nil),
    --         event_range - represents (may be nil), the range of the buf
    --                 where the event flags is stored.
    function public:read_symbol(stream)
        private.event_flags = nil
        private.event_flags_range = nil
        private.symbol_range = nil
        local start_pos = stream:get_current_pos()
        while true do
            ::continue::
            local i = stream:read_uint8()
            local penta = Int64(0, 0)
            if (i < 0x80) then -- 15-bit
                penta = penta + bit.lshift(i, 8) + stream:read_uint8()
            elseif (i < 0xC0) then -- 30-bit
                penta = penta + bit.lshift(bit.band(i, 0x3F), 24)
                penta = penta + bit.lshift(stream:read_uint8(), 16)
                penta = penta + stream:read_uint16()
            elseif (i < 0xE0) then -- reserved (first range)
                error("FormatError: Reserved bit sequence")
            elseif (i < 0xF0) then -- 20-bit
                penta = penta + bit.lshift(bit.band(i, 0x0F), 16)
                penta = penta + stream:read_uint16()
            elseif (i < 0xF8) then -- 35-bit
                penta = Int64(stream:read_uint32(), bit.band(i, 0x07))
            elseif (i == 0xF8) then -- mru event flags
                if (private.event_flags_range ~= nil) then
                    error("FormatError: Duplicated event flags prefix")
                end
                private.event_flags = private.mru_event_flags
                private.event_flags_range =
                    stream:get_range(start_pos, stream:get_current_pos())
                start_pos = stream:get_current_pos()
                goto continue -- read next byte
            elseif (i == 0xF9) then -- new event flags
                if (private.event_flags_range ~= nil) then
                    error("FormatError: Duplicated event flags prefix")
                end
                private.mru_event_flags = stream:read_compact_int(stream)
                private.event_flags = private.mru_event_flags
                private.event_flags_range =
                    stream:get_range(start_pos, stream:get_current_pos())
                start_pos = stream:get_current_pos()
                goto continue -- read next byte
            elseif (i < 0xFC) then -- reserved (second range)
                error("FormatError: Reserved bit sequence")
            elseif (i == 0xFC) then -- UTF-8
                private.symbol = stream:read_utf8_sequence(false) -- str len in bytes.
                private.symbol_range = stream:get_range(start_pos,
                                                        stream:get_current_pos())
                break
            elseif (i == 0xFD) then -- CESU-8
                private.symbol = stream:read_utf8_sequence(true) -- str len in chars.
                private.symbol_range = stream:get_range(start_pos,
                                                        stream:get_current_pos())
                break
            elseif (i == 0xFE) then -- 0-bit
                penta = Int64(0, 0);
            else -- repeat of the last symbol
                if (private.symbol == nil) then
                    error("FormatError: Symbol is undefined")
                end
                private.symbol_range = stream:get_range(start_pos,
                                                        stream:get_current_pos())
                break
            end
            private.symbol = penta_codec:penta_to_str(penta)
            private.symbol_range = stream:get_range(start_pos,
                                                    stream:get_current_pos())
            break
        end

        return private.symbol, private.symbol_range,
               private.event_flags, private.event_flags_range
    end

    -- #endregion

    setmetatable(public, self)
    self.__index = self;
    return public
end

return SymbolReader
