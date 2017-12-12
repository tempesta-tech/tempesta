init = function(args)
    local r = {}
    r[1] = wrk.format("GET", "/")
    r[2] = wrk.format("GET", "/", {["Accept"] = "text/plain"})
    r[3] = wrk.format("POST", "/")
    r[4] = wrk.format("POST", "/", {["Content-Type"]="text/plain"})
    r[5] = wrk.format("GET", "/", {["Host"] = ""})
    req = table.concat(r)
end

request = function()
    return req
end
