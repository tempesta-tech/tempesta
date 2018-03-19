local_init = function(args)
        local r = {}
        r[1] = wrk.format("HEAD", "/")
        r[2] = wrk.format("GET", "/")
        req = table.concat(r)
end

request = function()
        return req
end
