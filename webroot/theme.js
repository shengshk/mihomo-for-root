(function () {
  "use strict";
  const dark = matchMedia("(prefers-color-scheme: dark)");
  const manifest = document.querySelector('link[rel="manifest"]');
  function update() {
    const path = dark.matches ? "manifest-dark.webmanifest" : "manifest.webmanifest";
    manifest.href = new URL(path, document.baseURI).href;
  }
  update();
  dark.addEventListener("change", update);
})();
