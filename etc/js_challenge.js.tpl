var c_name = "[% STICKY_NAME %]";
var delay_min = [% DELAY_MIN %];
var delay_range = [% DELAY_RANGE %];

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
        location.reload();
    }, delay_min + Number(ts) % delay_range);
} else {
    document.write("<h3 align='center' style='color:red'>"
                   + "Please enable cookies and reload"
                   + " the page</h3>");
}
