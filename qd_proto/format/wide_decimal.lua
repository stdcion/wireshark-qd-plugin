-- @file wide_decimal.lua
-- @brief The file contains a set of methods to work with
-- floating-point numbers packed into long primitive type.
package.prepend_path(Dir.global_plugins_path())
local utils = require "qd_proto.utils"
local wide_decimal = {}

-- List of constant values.
local const = {
    BIAS = 128,
    -- NaN, Infinity, -Infinity, 0
    nf_double = {(0 / 0), math.huge, -math.huge, 0.0}
}

-- Converts a wide decimal number to a double.
-- @note The returned number can be converted
--       to a string using string.format(format, value).
--       Format can specify precision, for example:
--       string.format("%.10g", value) - exp form, ten decimal places.
-- @param val The Wide Decimal number.
-- @return The double number.
function wide_decimal.to_double(val)
    local significand = val:arshift(8)
    local rank = val:band(0xFF):tonumber()

    if (rank == 0) then
        -- Special cases.
        return const.nf_double[(significand:band(0x03) + 1):tonumber()]
    end
    if (rank == const.BIAS) then
        -- Non-floating point number.
        return significand:tonumber()
    end

    -- Specifies an exponential power.
    local exp = 0
    if (rank > const.BIAS) then
        exp = "e-" .. (rank - const.BIAS)
    else
        exp = "e" .. (const.BIAS - rank)
    end

    -- Converts to string with exponential form.
    significand = tostring(significand)
    significand = utils.insert_str(significand, exp, (#significand + 1), 1)
    -- Converts to number.
    return tonumber(significand)
end

return wide_decimal
