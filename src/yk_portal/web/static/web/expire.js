// Revealed YubiKey secrets stay on the page for a while only, and are removed when the
// page is left (spec §34). A file, not an inline script, for the Content-Security-Policy.
"use strict";

(function () {
  var secrets = document.querySelectorAll("[data-expires]");
  var note = document.querySelector("[data-expires-note]");

  function hide() {
    secrets.forEach(function (element) {
      element.textContent = element.getAttribute("data-mask");
      element.classList.remove("revealed");
    });
    if (note) {
      note.textContent = "Hidden again. Reveal it again to see it.";
    }
  }

  if (secrets.length) {
    var seconds = parseInt(secrets[0].getAttribute("data-expires"), 10) || 60;
    window.setTimeout(hide, seconds * 1000);
    window.addEventListener("pagehide", hide);
  }
})();
