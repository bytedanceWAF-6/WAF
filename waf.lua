local content_length=tonumber(ngx.req.get_headers()['content-length'])
local method=ngx.req.get_method()
local ngxmatch=ngx.re.match



local mysql = require "resty.mysql"
local db, err = mysql:new()
if not db then
ngx.say("new sql error",err)
return
end
db:set_timeout(5000)
local props = {
     host = "127.0.0.1",
     port = 3306,
     database = "rules",
     user = "root",
     password = "123456",
     max_package_size = 1024
 }
local res, err, errno, sqlstate = db:connect(props)
if not res then
     ngx.say("failed to connect:",err,":",errno," ",sqlState)
     return
end

function read_post_drop_rules()
local uri = ngx.var.request_uri
	-- body
	res, err, errno, sqlState = db:query("select reg_expr from reg_match where jump = 'drop' and (url is Null or url='' or url='"..uri.."')")
    if not res then
        ngx.say("get rules failed")
    	return
    else
    	-- local cjson = require("cjson")
			
    	-- ngx.say(cjson.encode(res))
    	local rres = {}
    	for i,row in ipairs(res) do
    		for _,rule in pairs(row) do
    			table.insert(rres,rule)
    		end
    	end
    	return(rres)
    end
end

function read_post_accept_rules()
	-- body
	res, err, errno, sqlState = db:query("select reg_expr from reg_match where jump = 'accept'")
    if not res then
        ngx.say("get rules failed")
    	return
    else
    	local rres = {}
    	for i,row in ipairs(res) do
    		for _,rule in pairs(row) do
    			table.insert(rres,rule)
    		end
    	end
    	return(rres)
    end
end



function read_post_drop_rules_by_usr()
local uri = ngx.var.request_uri
	local rres = {}
	for k,v in pairs(Level) do
		res, err, errno, sqlState = db:query("select reg_expr from reg_match where jump = 'drop' and (url is Null or url='' or url='"..uri.."') and reg_expr_name ='"..k.."' and local_level <="..v)
		if not res then
			goto continue
		else
			for i,row in ipairs(res) do
				for _,rule in pairs(row) do
					table.insert(rres,rule)
				end
			end
		end
		::continue::
	end
	return(rres)
end

function read_post_accept_rules_by_usr()
	local rres = {}
	for k,v in pairs(Level) do

		res, err, errno, sqlState = db:query("select reg_expr from reg_match where jump = 'accept' and reg_expr_name ='"..k.."' and local_level <="..v)
		if not res then
			goto continue
		else
			for i,row in ipairs(res) do
				for _,rule in pairs(row) do
					table.insert(rres,rule)
				end
			end
		end

		::continue::
	end
	return(rres)
end



function getClientIp()
        IP  = ngx.var.remote_addr 
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end

function write(msg)
    local fd = io.open("/usr/local/openresty/nginx/conf/waf/log.txt","ab")
    if fd == nil then 
	return end
    fd:write(msg.."\n")
    fd:flush()
    fd:close()
end

function log(method,url,data,ruletag,doa)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()
--[[data=string.gsub(data, "\"", function(c)
    return "\\"..c
end)
--]]
ruletag=ngx.quote_sql_str(ruletag)
data=ngx.quote_sql_str(data)
        if ua  then
            line = doa..realIp.." ["..time.."] "..method.." "..servername..url.." "..data.." "..ua.." "..ruletag
        else
            line = doa..realIp.." ["..time.."] "..method.." "..servername..url.." "..data.." - "..ruletag
        end
write(line)
local s="INSERT INTO ip_list ( ip, bow ) ( SELECT '"..realIp.."', 'black' WHERE NOT EXISTS ( SELECT * FROM ip_list WHERE ip = '"..realIp.."' ) LIMIT 1 )"

res, err, errno, sqlState = db:query(s)

--ngx.say(data)
s=[[prepare str from 'insert into log(simplify_content,jump,time,full_content) values(?,?,?,?)';
set @a="]]..data.." --- "..ruletag..[[";
set @b="]]..doa..[[";
set @c="]]..time..[[";
set @d="]]..line..[[";
execute str using @a,@b,@c,@d;]]
--ngx.say(s)
res, err, errno, sqlState = db:query(s)
    end
end

 function CSRFposttest(rules)
 	-- body
 	if table_is_empty(rules) then
		return
	end
	 local request_uri = ngx.var.request_uri
	 local HTTPVersion = ngx.req.http_version()
	 local str = method.." "..request_uri.." ".."HTTP".." "..HTTPVersion.."\n"

	 local referer_content = ngx.req.get_headers()['Referer']
	 if referer_content == "" then
		 ngx.status = ngx.HTTP_FORBIDDEN
		 ngx.say("illegal access")
		 ngx.exit(ngx.status)

	 end
	 local t = ngx.req.get_headers()
	 for k,v in pairs(t) do
		 str = str..k..": "..v.."\n"
	 end
	 if str ~=""  then
		 for _,rule in pairs(rules) do

			 if not ngx.re.match(str,rule,"ism") then
				 log('POST',ngx.var.request_uri,"",rule,'drop')
				 if ngx.var.request_uri == "/api/auth/sign-in" then
					 ngx.header.content_type = "application/json;charset=utf-8"
					 ngx.status = ngx.HTTP_FORBIDDEN
					 ngx.say("{\"message\":\"illegal input,攻击零容忍,已入黑名单,去后台解封\"}")
					 ngx.exit(ngx.status)
				 elseif ngx.var.request_uri == "/api/update-profile" then
					 ngx.header.content_type = "application/json;charset=utf-8"
					 ngx.status = ngx.HTTP_FORBIDDEN
					 ngx.say("{\"message\":\"forbidden url,攻击零容忍,已入黑名单,去后台解封\"}")
					 ngx.exit(ngx.status)
				 else
					 say_html()
				 end
--				 say_html()
			 end
		 end
	 end
	 return
 end



function body_filter(data,rules,doa)
	if table_is_empty(rules) then
		return false
	end

    for _,rule in pairs(rules) do
        if rule ~="" and data~="" and ngx.re.match(ngx.unescape_uri(data),rule,"isjo") then
            log('POST',ngx.var.request_uri,data,rule,doa)
            if ngx.var.request_uri == "/api/auth/sign-in" then
		    	ngx.header.content_type = "application/json;charset=utf-8"
		    	ngx.status = ngx.HTTP_FORBIDDEN
		    	ngx.say("{\"message\":\"illegal input,攻击零容忍,已入黑名单,去后台解封\"}")
		    	ngx.exit(ngx.status)
	    	elseif ngx.var.request_uri == "/api/update-profile" then
				ngx.header.content_type = "application/json;charset=utf-8"
		    	ngx.status = ngx.HTTP_FORBIDDEN
		    	ngx.say("{\"message\":\"forbidden url,攻击零容忍,已入黑名单,去后台解封\"}")
		    	ngx.exit(ngx.status)
			else
	    		say_html()
			end
            return true
        end
    end
    return false
end

function read_blackip()
	-- body
local rres={}
	res, err, errno, sqlState = db:query("select ip from ip_list where bow = 'black'")
    if not res then
    	return
    else
    	for i,row in ipairs(res) do
    		for _,rule in pairs(row) do
    			table.insert(rres,rule)
    		end
    	end
    	return(rres)
    end
end

function blackip()
	local ipBlacklist=read_blackip()
	if next(ipBlacklist) ~= nil then
		for _,ip in pairs(ipBlacklist) do
			if getClientIp()==ip then
if ngx.var.request_uri == "/api/auth/sign-in" then
		    	ngx.header.content_type = "application/json;charset=utf-8"
		    	ngx.status = ngx.HTTP_FORBIDDEN
		    	ngx.say("{\"message\":\"ip is in black list,请去后台解封\"}")
		    	ngx.exit(ngx.status)
	    	elseif ngx.var.request_uri == "/api/update-profile" then
				ngx.header.content_type = "application/json;charset=utf-8"
		    	ngx.status = ngx.HTTP_FORBIDDEN
		    	ngx.say("{\"message\":\"ip is in black list,请去后台解封\"}")
		    	ngx.exit(ngx.status)
			else
	    		say_html()
			end
				--ngx.exit(403)
				return true
			end
		end
	end
		return false
end

function urlandcookiesql()
	res, err, errno, sqlState = db:query("select reg_expr from reg_match where reg_expr_name='sqlInjectionCommon' or reg_expr_name='file'")
    if not res then
        ngx.say("get rules failed")
    	return
    else
    	local rres = {}
    	for i,row in ipairs(res) do
    		for _,rule in pairs(row) do
    			table.insert(rres,rule)
    		end
    	end
	for _,rule in pairs(rres) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule,'drop')
                say_html()
                return true
elseif rule ~="" and ngxmatch(ngx.var.http_cookie,rule,"isjo") then
	log('Cookie',ngx.var.request_uri,"-",rule,'drop')
                say_html()
            return true
            end
        end
 return false
end
end

if blackip() then
elseif denycc() then
elseif ngx.var.http_Acunetix_Aspect then
    ngx.exit(444)
elseif ngx.var.http_X_Scan_Memo then
    ngx.exit(444)
elseif whiteurl() then
elseif ua() then
elseif urlandcookiesql() then
elseif args() then
elseif url() then
elseif args() then
elseif cookie() then
elseif PostCheck then
    if method=="POST" then

		if level then
			postdroprules = read_post_drop_rules_by_usr()
			postacceptrules = read_post_accept_rules_by_usr()
		else
			postdroprules = read_post_drop_rules()
			postacceptrules = read_post_accept_rules()
		end

		CSRFposttest(postacceptrules)
--    local request_uri = ngx.var.request_uri
--    local HTTPVersion = ngx.req.http_version()
--	local str = method.." "..request_uri.." ".."HTTP".." "..HTTPVersion.."\n"
--
--	local referer_content = ngx.req.get_headers()['Referer']
--	if referer_content == "" then
--		ngx.say("illegal access")
--	end
--	local t = ngx.req.get_headers()
--	for k,v in pairs(t) do
--		str = str..k..": "..v.."\n"
--	end
--	if str ~=""  then
--		for _,rule in pairs(postacceptrules) do
--
--		 	if not ngx.re.match(str,rule,"ism") then
--		 		say_html()
--			end
--		end
--	end
		local boundary = get_boundary()
           
	    
	    if boundary then	    
            local sock, err = ngx.req.socket()
	    
    	    if not sock then
					return
            end
	    
	    ngx.req.init_body(128 * 1024)
            sock:settimeout(0)
	    local content_length = nil
    	    content_length=tonumber(ngx.req.get_headers()['content-length'])
    	    local chunk_size = 4096
            if content_length < chunk_size then
					chunk_size = content_length
	    end
            local size = 0
	    while size < content_length do
		local data, err, partial = sock:receive(chunk_size)
		data = data or partial
		if not data then
			return
		end
		ngx.req.append_body(data)
        	if body_filter(data,postdroprules,'drop') then
	   	        return true
    	    	end
		size = size +string.len(data)
		local m = ngxmatch(data,[[Content-Disposition: form-data;(.+)filename="(.+)\\.(.*)"]],'ijo')
        	if m then
            		fileExtCheck(m[3])
            		filetranslate = true
        	else
            		if ngxmatch(data,"Content-Disposition:",'isjo') then
                		filetranslate = false
            		end
            		if filetranslate==false then
            			if body_filter(data,postdroprules,'drop') then
                    			return true
                		end
            		end
        	end
		local less = content_length - size
		if less < chunk_size then
			chunk_size = less
		end
	 end
	 ngx.req.finish_body()
    else
	    ngx.req.read_body()
			local dat = ngx.req.get_body_data()
--ngx.say(dat)
			if not dat then
				return
			end

			local cjson = require("cjson")
			local json = cjson.decode(dat)
			for key, val in pairs(json) do
			        if type(val) == "table" then
					if type(val[1]) == "boolean" then
						return
					end
					data=table.concat(val,",")
				else
					data=val
				end
				if data and type(data) ~= "boolean" and body_filter(data,postdroprules,'drop') then
					body_filter(key,postdroprules,'drop')
				end
				
			end
		end
    end
else
    return
end
