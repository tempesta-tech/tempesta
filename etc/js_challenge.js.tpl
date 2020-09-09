var c_name = "[% STICKY_NAME %]";
var delay_min = [% DELAY_MIN %];
var delay_range = [% DELAY_RANGE %];
/*
 * If JS challenge are enabled, then Location header cannot be used to add
 * rmark to the url. We pass rmark through the response body.
 */
var TFW_DONT_CHANGE_NAME = "";

function cookieVal(input, c_name) {
    var re = new RegExp("(.*;)?\s*" + c_name + "=([0-9a-f]+)")
    var found = input.match(re)
    if (!found)
        return ""
    return  found[2];
}

var c_val = cookieVal(document.cookie, c_name)

if (navigator.cookieEnabled && !!c_val) {
    var ts = "0x" + c_val.substr(0, 16);
    setTimeout(function() {
        var url = location.pathname;
        /* If there is rmark */
        if (TFW_DONT_CHANGE_NAME) {
            url = TFW_DONT_CHANGE_NAME + location.pathname;
            const regex = /\/__tfw=[0-9a-z]+/;
            if (location.pathname.search(regex) != -1)
                url = location.pathname.replace(regex, TFW_DONT_CHANGE_NAME);
        }
        location.replace(url);
    }, delay_min + Number(ts) % delay_range);
} else {
    document.write("<h3 align='center' style='color:red'>"
                   + "Please enable cookies and reload"
                   + " the page</h3>");
}
