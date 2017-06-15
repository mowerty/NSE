local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "table"

description = [[
Performs brute force password auditing against IPMI server with 'ipmiutil' and change default password if 'pwdchange' argument >= 5 symbols with 'ipmitool'.
Check admin rights - ipmiutil config -N <host> -U ADMIN -P ADMIN 
Change ADMIN password - ipmitool -H IP -U ADMIN -P ADMIN user set password 2 NEWPWD 
Version: 0.4
Dependent utility: ipmutil and ipmitool
]]
author = "mowerty"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


---
-- @usage
-- nmap -sU  -p623 -PS80,443 -PA80,443 --max-retries 5 --script ipmi-ipmiutil-brute --script-args 'userdb=/opt/ipmi-users.txt,passdb=/opt/ipmi-pwd.txt' <host>
-- nmap -sU  -p623 -PS80,443 -PA80,443 --max-retries 5 --script ipmi-ipmiutil-brute --script-args 'brute.credfile=/opt/ipmi-creds.txt' <host>
-- nmap -sU -p 623 -PA80,443 -PS80,443 --reason --open --max-retries 5 --script ipmi-ipmiutil-brute --script-args 'brute.credfile=/opt/ipmi-creds.txt,pwdchange=NEWPWDADMIN' <host>
-- brute.firstonly = Boolean - Stop attack when the first credentials are found (https://nmap.org/nsedoc/lib/brute.html)
-- brute.mode = user/creds/pass - Username password iterator (see https://nmap.org/nsedoc/lib/brute.html)
-- passdb = file - Path to password list --- file with one pass = one string
-- userdb = file - Path to user list --- file with one login = one string
-- brute.credfile = file - Path to credentials file, use '/' as delimeter (ADMIN/ADMIN)
-- 
-- for debug message use -d option
-- 
-- @output
-- PORT     STATE  SERVICE REASON
-- 623/udp  open|filtered  unknown
-- | ipmi-supermicro-brute:
-- |   Accounts
-- |_    admin:admin => Valid credentials
--



portrule = shortport.port_or_service(623, "asf-rmcp", "udp", {"open", "open|filtered"})

-- if string.find(s1, "welcome home") ~= nil then

Driver = {
	new = function(self, host, port, pwdchange)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		o.host = host
		o.port = port
		o.pwdchange = pwdchange
		return o
	end,
	
	connect = function( self )
		return true
	end,
	
	disconnect = function( self )
		return true
	end,
	
	check = function( self )
		if (self.port.state == "open" or self.port.state == "open|filtered") then
			return true
		else 
			return false
		end
	end,
	
	login = function( self, username, password )
	--[[ ipmiutil error codes - http://ipmiutil.sourceforge.net/docs/UserGuide
	Code  Dec  Description
	----  ---  -----------------------------------------
	+0x00,   0, "Command completed successfully",
	0x80, 128, "Invalid Session Handle or Empty Buffer",
	+0x81, 129, "Lost Arbitration", --- "GetSessChallenge: Invalid user name"
	0x82, 130, "Bus Error",
	0x83, 131, "NAK on Write - busy",
	0x84, 132, "Truncated Read",
	0xC0, 192, "Node Busy",
	0xC1, 193, "Invalid Command",
	0xC2, 194, "Command invalid for given LUN",
	0xC3, 195, "Timeout while processing command",
	0xC4, 196, "Out of space",
	0xC5, 197, "Invalid Reservation ID, or cancelled",
	0xC6, 198, "Request data truncated",
	0xC7, 199, "Request data length invalid",
	0xC8, 200, "Request data field length limit exceeded",
	0xC9, 201, "Parameter out of range",
	0xCA, 202, "Cannot return requested number of data bytes",
	0xCB, 203, "Requested sensor, data, or record not present",
	0xCC, 204, "Invalid data field in request",
	0xCD, 205, "Command illegal for this sensor/record type",
	0xCE, 206, "Command response could not be provided",
	0xCF, 207, "Cannot execute duplicated request",
	0xD0, 208, "SDR Repository in update mode, no response",
	0xD1, 209, "Device in firmware update mode, no response",
	0xD2, 210, "BMC initialization in progress, no response",
	0xD3, 211, "Destination unavailable",
	0xD4, 212, "Cannot execute command. Insufficient privilege level",
	0xD5, 213, "Cannot execute command. Request parameters not supported",
		253, "some IPMI - Cannot connect, some - Wrong password"
	0xFF, 255, "Unspecified error"
	]]
		-- ipmiutil config -N <host> -U ADMIN -P ADMIN 
		local cmd = "ipmiutil config  -U " .. username .. " -P " .. password .. " -N " .. self.host.ip .. "  2>&1 ; echo RC=$?"
		local handler = assert(io.popen(cmd))
		local output = "EMPTY"
		local retcod = "9999"
		--local output = assert(handler:read('*a')) -- '*a' означает считывание всех данных
		for line in handler:lines() do
			if string.len(line) >= 1 then
				if string.match(line, "RC=") then retcod = tonumber(line:match "RC=(%d+)") end 
				if string.match(line, "ipmiutil config, ") then output = line:match "ipmiutil config, (.*)" end
			end 
		end
		handler:close()
		
		if retcod == 0 then 
			if string.len(self.pwdchange) >= 5 then 
				-- ipmitool -H IP -U ADMIN -P ADMIN user set password 2 NEWPWD 
				local pwdoutput = "EMPTY"
				local pwdretcod = "8888"
				local pwdtry = 1 
				local pwdcmd = "ipmitool -U " .. username .. " -P " .. password .. " -H " .. self.host.ip .. " user set password 2 " .. self.pwdchange .. "  2>&1 ; echo RC=$?"
				::PWDNEWTRY::
				stdnse.print_debug(1, "IPMI pwdcmd (try %s): %s", pwdtry, pwdcmd)
				local pwdhandler = assert(io.popen(pwdcmd))
				for line in pwdhandler:lines() do
					if string.len(line) >= 1 then
						if string.match(line, "RC=") then 
							pwdretcod = tonumber(line:match "RC=(%d+)")
						elseif  string.match(line, "Invalid user name") then
							pwdoutput = "Invalid user name" 
						else 
							pwdoutput = line
						end 
					end 
				end
				pwdhandler:close()
				if pwdretcod == 0 then 
					stdnse.print_debug(1, "IPMI INF (%s): %s - password changed to %s (%s:%s)", pwdretcod, pwdoutput, self.pwdchange,username, password)
					return true, creds.Account:new(username, password,  "Valid credentials (new password is " .. self.pwdchange .. ")")
				elseif pwdtry <=2 then
					pwdtry = pwdtry+1
					goto PWDNEWTRY
				else 
					stdnse.print_debug(1, "IPMI ERR (%s): fail to change password with %s tries (new %s, old %s:%s)", pwdretcod, pwdtry, self.pwdchange, username, password)
					return false, brute.Error:new( "Failed to change password." )
				end
			else 
				stdnse.print_debug(1, "IPMI INF (%s): %s - success (%s:%s)", retcod, output, username, password)
				return true, creds.Account:new(username, password, creds.State.VALID)
			end
		elseif retcod == 129 then
			stdnse.print_debug(1, "IPMI WARN (%s): %s - wrong username (%s:%s)", retcod, output, username, password)
			return false, brute.Error:new( "Wrong username." )
		elseif retcod == 206 or retcod == 253 then
			stdnse.print_debug(1, "IPMI WARN (%s): %s - wrong password (%s:%s)", retcod, output, username, password)
			return false, brute.Error:new( "Wrong password." )
		else
			stdnse.print_debug(1, "IPMI ERR (%s): %s - unknown error (%s:%s)", retcod, output, username, password)
			return false, brute.Error:new( "Unknown error." )
		end
	end,
	
	disconnect = function( self )
		return true
	end
}

action = function(host, port)
	local pwdchange = ''          -- нужно ли менять пароль? если переменная не пустая, то будет задан новый пароль, равный значению переменной
	local status, result, engine
	if nmap.registry.args['pwdchange'] then pwdchange = nmap.registry.args.pwdchange end
	engine = brute.Engine:new( Driver, host, port, pwdchange)
--	engine:setMaxThreads(thread_num)
	engine.options.script_name = SCRIPT_NAME
	status, result = engine:start()
	return result
end
