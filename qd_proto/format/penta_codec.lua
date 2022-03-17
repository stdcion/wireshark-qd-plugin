-- @file penta_code.lua
-- @brief The PentaCodec performs symbol coding and serialization using
-- extensible 5-bit encoding. The eligible characters are assigned penta codes
-- (either single 5-bit or double 10-bit) according to the following table:
--
-- 'A' to 'Z'                 - 5-bit pentas from 1 to 26
-- '.'                        - 5-bit penta 27
-- '/'                        - 5-bit penta 28
-- '$'                        - 5-bit penta 29
-- ''' and '`'                - none (ineligible characters)
-- ' ' to '~' except above    - 10-bit pentas from 960 to 1023
-- all other                  - none (ineligible characters)
--
-- The 5-bit penta 0 represents empty space and is eligible only at the start.
-- The 5-bit pentas 30 and 31 are used as a transition mark to switch to 10-bit pentas.
-- The 10-bit pentas from 0 to 959 do not exist as they collide with 5-bit pentas.
--
-- The individual penta codes for character sequence are packed into 64-bit value
-- from high bits to low bits aligned to the low bits. This allows representation
-- of up to 35-bit penta-coded character sequences. If some symbol contains one or
-- more ineligible characters or does not fit into 35-bit penta, then it is not
-- subject to penta-coding and is left as a string. 
-- Please note that penta code 0 is a valid code as it represents empty character
-- sequence.
--
-- The following table defines used serial format (the first byte is given in bits
-- with 'x' representing payload bit; the remaining bytes are given in bit count):
--
-- 0xxxxxxx  8x - for 15-bit pentas
-- 10xxxxxx 24x - for 30-bit pentas
-- 110xxxxx ??? - reserved (payload TBD)
-- 1110xxxx 16x - for 20-bit pentas
-- 11110xxx 32x - for 35-bit pentas
-- 111110xx ??? - reserved (payload TBD)
-- 11111100 zzz - for UTF-8 string with length in bytes
-- 11111101 zzz - for CESU-8 string with length in characters
-- 11111110     - for 0-bit penta (empty symbol)
-- 11111111     - for void (null)
package.prepend_path(Dir.global_plugins_path())
local utils = require("qd_proto.utils")

local PentaCodec = {}

-- Creates a new instance of the PentaCodec class.
function PentaCodec:new()
    -- #region Private

    local private = {}

    -- Size pentas and pentas_lens.
    private.PENTA_LEN = 128
    -- Size pentas_characters.
    private.PENTA_CHARACTERS_LEN = 1024
    -- Pentas for ASCII characters. Invalid pentas are set to 0.
    private.pentas = {}
    -- Lengths (in bits) of pentas for ASCII characters. Invalid lengths are set to 64.
    private.pentas_lens = {}
    -- ASCII characters for pentas. Invalid characters are set to 0.
    private.pentas_characters = {}

    -- Helper function for initialization.
    function private:init_penta(c, penta, penta_length)
        private.pentas_characters[penta + 1] = c
        private.pentas[c + 1] = penta
        private.pentas_lens[c + 1] = penta_length
    end

    -- Initializes a PentaCodec object.
    function private:init()
        utils.set_tbl(private.pentas, 1, 0, private.PENTA_LEN)
        utils.set_tbl(private.pentas_lens, 1, 64, private.PENTA_LEN)
        utils.set_tbl(private.pentas_characters, 1, 0,
                      private.PENTA_CHARACTERS_LEN)

        for i = string.byte('A'), string.byte('Z') do
            private:init_penta(i, i - string.byte('A') + 1, 5)
        end

        private:init_penta(string.byte('.'), 27, 5)
        private:init_penta(string.byte('/'), 28, 5)
        private:init_penta(string.byte('$'), 29, 5)

        local penta = 0x03C0
        for i = 32, 126 do
            if (private.pentas[i + 1] == 0 and i ~= string.byte('\'') and i ~=
                string.byte('`')) then
                private:init_penta(i, penta, 10)
                penta = penta + 1
            end
        end
    end

    -- #endregion

    -- #region Public

    local public = {}

    -- Converts penta to string.
    -- @param penta The penta code.
    -- @return A string (may be empty) associated with the penta code.
    function public:penta_to_str(penta)
        local penta_len = 0
        local str = ""
        while (penta:rshift(penta_len) ~= Int64(0, 0)) do
            penta_len = penta_len + 5
        end

        while penta_len > 0 do
            penta_len = penta_len - 5
            local code = penta:rshift(penta_len):band(0x1F):tonumber()
            if (code >= 30 and penta_len > 0) then
                penta_len = penta_len - 5
                code = penta:rshift(penta_len):band(0x3FF):tonumber()
            end
            str = str .. string.char(private.pentas_characters[code + 1])
        end

        return str
    end

    -- #endregion

    private:init()
    setmetatable(public, self)
    self.__index = self;
    return public
end

return PentaCodec
