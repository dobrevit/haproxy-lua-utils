-- The MIT License (MIT)
--
-- Copyright (c) 2023 Dobrev IT Ltd., Martin Dobrev
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--
-- SPDX-License-Identifier: MIT
--
-- Portions of this file are derived from the haproxy-protection project, which
-- is licensed under the MIT License. The original source code can be found at
-- https://gitgud.io/fatchan/haproxy-protection
--

local _M = {}

local tor_control_host = os.getenv("TOR_CONTROL_HOST")
local tor_control_port = os.getenv("TOR_CONTROL_PORT")
local tor_control_password = os.getenv("TOR_CONTROL_PORT_PASSWORD")

-- check if a value is nil
_M.is_nil = function(value)
    return value == nil or value == "nil"
end

-- check if a table contains a value
_M.has_value = function(tbl, value)
    for _, v in pairs(tbl) do
        if v == value then
            return true
        end
    end
    return false
end

-- split string by delimiter
function _M.split(inputstr, sep)
	local t = {}
	for str in string.gmatch(inputstr, "([^"..sep.."]*)") do
		table.insert(t, str)
	end
	return t
end

-- detect if a tor circuit is being used
function _M.detect_tor_circuit(txn)
    local ip = txn.sf:src()
    if ip:sub(1,19) ~= "fc00:dead:beef:4dad" then
        return nil, false -- not a tor circuit id/ip
    end
    -- split the IP, take the last 2 sections
    local split_ip = _M.split(ip, ":")
    local aa_bb = split_ip[5] or "0000"
    local cc_dd = split_ip[6] or "0000"
    aa_bb = string.rep("0", 4 - #aa_bb) .. aa_bb
    cc_dd = string.rep("0", 4 - #cc_dd) .. cc_dd
    -- convert the last 2 sections to a number from hex, which makes the circuit ID
    local circuit_identifier = tonumber(aa_bb..cc_dd, 16)
    --core.log(core.debug, 'Tor circuit ID: '..circuit_identifier..', "IP": '..ip)
    return circuit_identifier, true
end

-- kill a tor circuit
function _M.kill_tor_circuit(txn)
	local circuit_identifier, is_tor_circuit = _M.detect_tor_circuit(txn)
    if not is_tor_circuit then
        return
    end
	--core.log(core.debug, 'Closing Tor circuit ID: '..circuit_identifier)
	_M.close_tor_circuit(circuit_identifier)
end

-- connect to the tor control port and instruct it to close a circuit
function _M.close_tor_circuit(circuit_identifier)
    if _M.is_nil(tor_control_host) or _M.is_nil(tor_control_port) or _M.is_nil(tor_control_password) then
        core.log(core.debug, 'Tor control port not configured')
        return
    end

	local tcp = core.tcp()
	tcp:settimeout(1)
	tcp:connect(tor_control_host, tonumber(tor_control_port))
	-- not buffered, so we are better off sending it all at once
	tcp:send('AUTHENTICATE "' .. tor_control_password .. '"\nCLOSECIRCUIT ' .. circuit_identifier ..'\n')
	tcp:close()
end

return _M
