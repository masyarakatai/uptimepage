// A live poll that swaps markup (the status page's status region, the monitor
// page's check facts) would close every row a visitor opened. Rows marked
// data-keep-open are reopened by id.
(function () {
    "use strict";

    var open = [];

    document.addEventListener("htmx:beforeSwap", function () {
        var nodes = document.querySelectorAll("details[data-keep-open][open]");
        open = Array.prototype.map.call(nodes, function (d) { return d.id; });
    });

    document.addEventListener("htmx:afterSwap", function () {
        for (var i = 0; i < open.length; i++) {
            var d = open[i] && document.getElementById(open[i]);
            if (d) d.open = true;
        }
    });
})();
