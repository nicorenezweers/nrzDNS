// Streamer-Modus von nrzNetwork: schwärzt IPs, Domains, E-Mails, UUIDs, MACs und Schlüssel
// (CSS Custom Highlight API), blendet Tooltips aus; die Klasse `streamer` am <html> macht
// Eingabefelder, Namen und technische Angaben unscharf (siehe ui/tailwind.css).
(function () {
    var KEY = 'nrz-streamer', on = false, obs = null, timer = 0;
    var RX = [
        /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:\/\d{1,2})?\b/g,
        /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g,
        /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
        /\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b/gi,
        /\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b\.?/gi,
        /(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}/gi,
        /[A-Za-z0-9_+\/=-]{24,}/g
    ];
    function sensitive(i, m) {
        if (i === 5) { // IPv6: "::" oder mindestens 5 Gruppen, keine Uhrzeit
            var hex = m.replace(/:/g, '');
            return hex.length >= 3 && (m.indexOf('::') >= 0 || m.split(':').length >= 5);
        }
        if (i === 6) return /\d/.test(m) && /[A-Za-z]/.test(m);
        return true;
    }
    function scan() {
        timer = 0;
        if (!on || !window.CSS || !CSS.highlights || typeof Highlight === 'undefined') return;
        var ranges = [];
        var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
            acceptNode: function (n) {
                var p = n.parentElement;
                if (!p || /^(SCRIPT|STYLE|NOSCRIPT)$/.test(p.tagName) || p.closest('[data-public]')) return NodeFilter.FILTER_REJECT;
                return n.nodeValue.length > 3 ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
            }
        });
        var node;
        while ((node = walker.nextNode())) {
            var text = node.nodeValue;
            for (var i = 0; i < RX.length; i++) {
                RX[i].lastIndex = 0;
                var m;
                while ((m = RX[i].exec(text))) {
                    if (!m[0].length) { RX[i].lastIndex++; continue; }
                    if (!sensitive(i, m[0])) continue;
                    var r = new Range();
                    r.setStart(node, m.index);
                    r.setEnd(node, m.index + m[0].length);
                    ranges.push(r);
                }
            }
        }
        CSS.highlights.set('nrz-redact', new Highlight(...ranges));
    }
    function hideTitles(root) {
        (root.querySelectorAll ? root.querySelectorAll('[title]') : []).forEach(function (el) {
            el.setAttribute('data-nrz-title', el.getAttribute('title'));
            el.removeAttribute('title');
        });
    }
    function later() { if (!timer) timer = setTimeout(scan, 120); }
    function set(v) {
        on = !!v;
        try { localStorage.setItem(KEY, on ? '1' : '0'); } catch (e) {}
        document.documentElement.classList.toggle('streamer', on);
        if (on) {
            if (!obs) {
                obs = new MutationObserver(function (list) {
                    list.forEach(function (m) {
                        if (m.type === 'attributes' && m.target.hasAttribute('title')) hideTitles(m.target.parentNode || m.target);
                        m.addedNodes && m.addedNodes.forEach(function (n) { if (n.nodeType === 1) { if (n.hasAttribute('title')) hideTitles(n.parentNode); hideTitles(n); } });
                    });
                    later();
                });
            }
            var start = function () {
                hideTitles(document.body);
                obs.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['title'] });
                scan();
            };
            if (document.body) start(); else document.addEventListener('DOMContentLoaded', start);
        } else {
            if (obs) obs.disconnect();
            if (window.CSS && CSS.highlights) CSS.highlights.delete('nrz-redact');
            document.querySelectorAll('[data-nrz-title]').forEach(function (el) {
                el.setAttribute('title', el.getAttribute('data-nrz-title'));
                el.removeAttribute('data-nrz-title');
            });
        }
    }
    window.nrzStreamer = { set: set, get: function () { return on; } };
    var saved = false;
    try { saved = localStorage.getItem(KEY) === '1'; } catch (e) {}
    if (saved) set(true);
})();
