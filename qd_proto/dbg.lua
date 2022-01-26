-- @file dbg.lua
-- @brief Provides debug output functionality.
package.prepend_path("qd_proto")
local utils = require("utils")

local dbg = {}

-- Print message with file, line and severity.
-- @param file Path to file.
-- @param line Line in file.
-- @param str Message.
local function dprint(file, line, str)
    file = utils.get_filename(file)
    print("QD " .. "File: " .. file .. " " .. "Line: " .. line .. " " .. str)
end

-- Print trace.
-- @param file Path to file.
-- @param line Line in file.
-- @param str Trace message.
function dbg.trace(file, line, str) dprint(file, line, "Trace: " .. str) end

-- Print info.
-- @param file Path to file.
-- @param line Line in file.
-- @param str Info message.
function dbg.info(file, line, str) dprint(file, line, "Info: " .. str) end

-- Print warning.
-- @param file Path to file.
-- @param line Line in file.
-- @param str Warning message.
function dbg.warn(file, line, str) dprint(file, line, "Warn: " .. str) end

-- Print error.
-- @param file Path to file.
-- @param line Line in file.
-- @param str Error message.
function dbg.error(file, line, str) dprint(file, line, "Error: " .. str) end

-- Get full path to file where call this function.
-- Analogue C maros __FILE__.
-- @return Path to file.
function dbg.file() return debug.getinfo(2, 'S').source end

-- Get line in file where call this function.
-- Analogue C maros __LINE__.
-- @return Line.
function dbg.line() return debug.getinfo(2, 'l').currentline end

return dbg
