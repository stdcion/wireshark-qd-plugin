-- @file decimal.lua
-- The file contains a set of methods to work with
-- floating-point numbers packed into primitive type.
package.prepend_path(Dir.global_plugins_path())
local utils = require "qd_proto.utils"
local decimal = {}

-- List of constant values.
local const = {
    UNITY_POWER = 9,
    MANTISSA_SHIFT = 4,
    EXTRA_MANTISSA_SHIFT = 7,
    EXTRA_DIVISORS = {
        (0 / 0), -- NaN
        math.huge, -- Infinity
        10000000, -- 10^7
        100000000, -- 10^8
        0, -- reserved
        0, -- reserved
        128, -- -1/128
        -math.huge -- -Infinity
    }
}

-- Converts a decimal number to a double.
-- @note The returned number can be converted
--       to a string using string.format(format, value).
--       Format can specify precision, for example:
--       string.format("%.10g", value) - exp form, ten decimal places.
-- @param val The Decimal number.
-- @return The double number.
function decimal.to_double(val)
    local power = bit.band(val, 0x0F)
    local mantissa = bit.arshift(val, const.MANTISSA_SHIFT)

    -- Extra precision and special cases.
    if (power == 0) then
        local divisor = const.EXTRA_DIVISORS[bit.band(mantissa, 0x07) + 1]
        if (divisor ~= divisor or divisor == math.huge or divisor == -math.huge) then
            -- Special cases.
            return divisor
        else
            -- Mantissa in highest 25 bits for supported extra precision formats.
            return (bit.arshift(val, const.EXTRA_MANTISSA_SHIFT) / divisor)
        end
    end

    -- Specifies an exponential power.
    local exp = ""
    if (power > const.UNITY_POWER) then
        exp = tostring(mantissa) .. "e-" .. (power - const.UNITY_POWER)
    else
        exp = tostring(mantissa) .. "e" .. (const.UNITY_POWER - power)
    end

    -- Converts to number.
    return tonumber(mantissa)
end

return decimal
