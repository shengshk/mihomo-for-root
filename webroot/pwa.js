(function () {
  "use strict";
  if (typeof window.ksu?.exec === "function" || !window.isSecureContext || !/^https?:$/.test(location.protocol)) return;
  const button=document.getElementById("install-app");
  let pending;
  window.addEventListener("beforeinstallprompt", event => {
    event.preventDefault();pending=event;
    if (!matchMedia("(display-mode: standalone)").matches) button.hidden=false;
  });
  button.onclick=async()=>{
    if (!pending) return;
    await pending.prompt();await pending.userChoice;
    pending=null;button.hidden=true;
  };
  window.addEventListener("appinstalled",()=>{pending=null;button.hidden=true;});
  if ("serviceWorker" in navigator) {
    window.addEventListener("load",()=>navigator.serviceWorker.register("./sw.js",{updateViaCache:"none"}).catch(()=>{}));
  }
})();
