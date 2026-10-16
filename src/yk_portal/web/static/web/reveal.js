// Show/hide buttons for masked fields: passwords, private IDs and AES keys.
// A file, not an inline script, so the Content-Security-Policy stays strict.
// Without JavaScript the fields simply stay masked.
"use strict";

document.querySelectorAll("input[data-reveal]").forEach(function (input) {
  var label = document.querySelector('label[for="' + input.id + '"]');
  var name = label ? label.textContent.trim() : "the value";
  var wrap = document.createElement("span");
  var button = document.createElement("button");

  wrap.className = "reveal";
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);

  button.type = "button";
  button.className = "reveal-toggle";
  button.setAttribute("aria-controls", input.id);

  function show(visible) {
    input.type = visible ? "text" : "password";
    button.textContent = visible ? "Hide" : "Show";
    button.setAttribute("aria-label", (visible ? "Hide " : "Show ") + name);
  }

  button.addEventListener("click", function () {
    show(input.type === "password");
  });
  // Masked again before sending, so the browser never stores the value as typed text.
  if (input.form) {
    input.form.addEventListener("submit", function () {
      show(false);
    });
  }
  show(false);
  wrap.appendChild(button);
});
