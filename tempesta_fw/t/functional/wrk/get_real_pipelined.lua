
local r1 = {}
r1.method="GET"
r1.path="/"
r1.headers = {
        ["Connection"] = "keep-alive",
        ["Cache-Control"] = "max-age=0",
        ["Upgrade-Insecure-Requests"] = "1",
        ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36",
        ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        ["Accept-Encoding"] = "gzip, deflate",
        ["Accept-Language"] = "en-US,en;q=0.9",
        ["If-None-Match"] = "\"29cd-551189982e76f-gzip\"",
        ["If-Modified-Since"] = "Sun, 04 Jun 2017 01:49:40",
    }


local r2 = {}
r2.method="GET"
r2.path="/"
r2.headers = {
        ["Host"] = "yandex.ru",
        ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ["Accept-Language"] = "en-US,en;q=0.5",
        ["Accept-Encoding"] = "gzip, deflate, br",
        ["Cookie"] = "my=YzYBAQA=; yandexuid=1489696891470411041; _ym_uid=1472643187536716147; i=eOSeyr6gEr//nv7qBvDdsLgh+Kdl+2DakdBZFqXtrsS64n4nDa8PAjgcVvyV7ZwMJ7azBh2JNAxLKLLKgH53Qs6Nrsc=; yp=1521586770.szm.1_00:1920x1080:1920x893#1547045375.old.1#1518101365.ygu.1#1516718966.ysl.1#1518187799.csc.1; mda=0; yandex_gid=2; yabs-frequency=/4/0000000000000000/TtroSCWjGNnAi738BO5YVN9mo2qX/; yc=1515768590.cb.1%3A1; zm=m-white_bender.gen.css-https%3Awww_klVxYSejR7PRTES1DInob9ponr4%3Al; _ym_isad=1",
        ["Connection"] = "keep-alive",
        ["Upgrade-Insecure-Requests"] = "1",
        ["Cache-Control"] = "max-age=0",
    }


local r3 = {}
r3.method="GET"
r3.path="/www/_/i/H/t-h2mCk0raxxffOF6ttcnH40Q.js"
r3.headers = {
        ["Host"] = "yastatic.net",
        ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        ["Accept"] = "*/*",
        ["Accept-Language"] = "en-US,en;q=0.5",
        ["Accept-Encoding"] = "gzip, deflate, br",
        ["Referer"] = "https://yandex.ru/",
        ["Origin"] = "https://yandex.ru",
        ["Connection"] = "keep-alive",
        ["If-Modified-Since"] = "Fri, 29 Dec 2017 12:35:14 GMT",
        ["If-None-Match"] = "\"5a463682-28257\"",
        ["Cache-Control"] = "max-age=0",
    }

local req

init = function()
    local req1 = wrk.format(r1.method, r1.path, r1.headers)
    local req2 = wrk.format(r2.method, r2.path, r2.headers)
    local req3 = wrk.format(r3.method, r3.path, r3.headers)
    req = table.concat({req1, req2, req3})
end

request = function()
    return req
end
