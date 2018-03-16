-- example script demonstrating HTTP pipelining

local_init = function(args)
   local r = {}
   r[1] = wrk.format("GET", "/")
   r[2] = wrk.format("GET", "/")
   r[3] = wrk.format("GET", "/")
   r[4] = wrk.format("GET", "/")
   r[5] = wrk.format("GET", "/")
   r[6] = wrk.format("GET", "/")
   r[7] = wrk.format("GET", "/")

   req = table.concat(r)
end

request = function()
   return req
end
