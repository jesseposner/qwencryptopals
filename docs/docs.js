(function () {
  var links = Array.prototype.slice.call(document.querySelectorAll(".toc-list a[data-toc]"));
  if (!links.length) return;

  function paint(spy) {
    var offset = 90;
    var current = null;
    for (var i = 0; i < links.length; i++) {
      var targetId = links[i].getAttribute("href").slice(1);
      var el = document.getElementById(targetId);
      if (!el) continue;
      var s = el.getBoundingClientRect().top;
      if (s - offset <= 0 && (current === null || s > current.s)) {
        current = { link: links[i], s: s };
      }
    }
    links.forEach(function (a) { a.classList.remove("active"); });
    if (current) current.link.classList.add("active");
  }

  var ticking = false;
  function schedule() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () { paint(spy); ticking = false; });
  }
  paint(false);
  window.addEventListener("scroll", schedule, { passive: true });
  window.addEventListener("resize", schedule, { passive: true });
})();
(function () {
  var codeWraps = document.querySelectorAll(".code-wrap");
  codeWraps.forEach(function (wrap) {
    var code = wrap.querySelector("pre code");
    if (!code) return;
    var btn = document.createElement("button");
    btn.className = "copy";
    btn.type = "button";
    btn.textContent = "copy";
    btn.setAttribute("aria-label", "Copy code to clipboard");
    btn.addEventListener("click", function () {
      var text = code.innerText || "";
      function okLabel() {
        var old = btn.textContent;
        btn.textContent = "copied";
        btn.classList.add("ok");
        setTimeout(function () { btn.textContent = old; btn.classList.remove("ok"); }, 1200);
      }
      function legacy() {
        var range = document.createRange();
        range.selectNodeContents(code);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        document.execCommand("copy");
        sel.removeAllRanges();
        okLabel();
      }
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(okLabel, legacy);
      } else {
        legacy();
      }
    });
    wrap.appendChild(btn);
  });
})();
