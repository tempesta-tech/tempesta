local body = "some not very long text\n"

wrk.method  = "POST"
wrk.headers = {["Content-Type"]="text/plain", ["Content-Length"] = string.len(body)}
wrk.body    = body
