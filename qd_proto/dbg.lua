-- @file dbg.lua
-- @brief Provides debug output.
package.prepend_path(Dir.global_plugins_path())
local utils = require("qd_proto.utils")

local dbg = {}

-- Prints a message containing the file, line and severity.
-- @param file The path to the file.
-- @param line The line in the file.
-- @param str The message.
local function dprint(file, line, str)
    file = utils.get_filename(file)
    print("QD " .. "File: " .. file .. " " .. "Line: " .. line .. " " .. str)
end

-- Prints a trace message.
-- @param file The path to the file.
-- @param line The line in the file.
-- @param str The trace message.
function dbg.trace(file, line, str) dprint(file, line, "Trace: " .. str) end

-- Prints an information message.
-- @param file Path to file.
-- @param line The line in the file.
-- @param str The info message.
function dbg.info(file, line, str) dprint(file, line, "Info: " .. str) end

-- Prints a warning message.
-- @param file Path to file.
-- @param line The line in the file.
-- @param str The warning message.
function dbg.warn(file, line, str) dprint(file, line, "Warn: " .. str) end

-- Prints an error message.
-- @param file The path to the file.
-- @param line The line in the file.
-- @param str The error message.
function dbg.error(file, line, str) dprint(file, line, "Error: " .. str) end

-- Gets the full path to the file in which this function is called.
-- @note Analogue C maros __FILE__.
-- @return The path to the file.
function dbg.file() return debug.getinfo(2, 'S').source end

-- Gets the line in the file where this function is called.
-- @note Analogue C maros __LINE__.
-- @return The line in the file.
function dbg.line() return debug.getinfo(2, 'l').currentline end

return dbg
