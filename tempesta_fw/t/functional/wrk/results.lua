
local threads = {}
local tid = 1

setup = function(thread)
    thread:set("id", tid)
    table.insert(threads, thread)
    tid = tid + 1
end

init = function(args)
    responses = {}
    for status=100,599 do
        responses[status] = 0
    end
    if local_init ~= nil then
        local_init(args)
    end
end

response = function(status, headers, body)
    responses[status] = responses[status] + 1
    if local_response ~= nil then
        local_response(status, headers, body)
    end
end

done = function(summary, latency, requests)
    responses = {}
    for status=100,599 do
        responses[status] = 0
    end
    for index, thread in ipairs(threads) do
        local tresp = thread:get("responses")
        for status=100,599 do
            responses[status] = responses[status] + tresp[status]
        end
    end

    io.write("---- RESULTS --------\n")
    for status=100,599 do
        if responses[status] > 0 then
            local tmpl = "Status %d : %d times\n"
            local result = tmpl:format(status, responses[status])
            io.write(result)
        end
    end
    io.write("---- END ------------\n")
end
