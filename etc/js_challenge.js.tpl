var prefix = "[% STICKY_NAME %]";
var delay_min = [% DELAY_MIN %];
var delay_range = [% DELAY_RANGE %];
if (navigator.cookieEnabled
    && document.cookie.startsWith(prefix))
{
    var ts = "0x" + document.cookie.substr(prefix.length + 1, 16);
    setTimeout(function() {
        location.reload();
    }, delay_min + Number(ts) % delay_range);
} else {
    document.write("<h3 align='center' style='color:red'>"
                   + "Please enable cookies and reload"
                   + " the page</h3>");
}
