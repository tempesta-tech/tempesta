-- NOTE: each wrk thread has an independent Lua scripting context

cookie = nil
-- User-Agent header is required for correct parsing of Cookie header
if not wrk.headers["User-Agent"] then
    wrk.headers["User-Agent"] = "wrk/4.0.2"
end

request = function()
    return wrk.format()
end

response = function(status, headers, body)
   if not cookie and status == 302 then
      cookie = headers["Set-Cookie"]
      wrk.headers["Cookie"] = cookie
   end
end

