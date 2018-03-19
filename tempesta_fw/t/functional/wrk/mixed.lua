-- example script demonstrating HTTP pipelining

local_init = function(args)
   local r = {}
   r[1] = wrk.format("OPTIONS", "/")
   r[2] = wrk.format("GET", "/")
   r[3] = wrk.format("HEAD", "/")
   r[4] = wrk.format("POST", "/")
   r[5] = wrk.format("PUT", "/")
   r[6] = wrk.format("PATCH", "/")
   r[7] = wrk.format("DELETE", "/")
   req = table.concat(r)
end

request = function()
   return req
end
