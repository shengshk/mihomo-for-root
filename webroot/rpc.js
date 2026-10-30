(function () {
  "use strict";
  let sequence = 0;
  function exec(command, payload, timeoutMs = 180000) {
    return new Promise((resolve, reject) => {
      if (!window.ksu || typeof window.ksu.exec !== "function") {
        reject(new Error("请从 Root 管理器打开模块管理。"));
        return;
      }
      const callback = "mfr_" + Date.now() + "_" + sequence++;
      const timeout = setTimeout(() => {
        delete window[callback];
        reject(new Error("操作超时，可稍后刷新查看结果。"));
      }, timeoutMs);
      window[callback] = (errno, stdout, stderr) => {
        clearTimeout(timeout);
        delete window[callback];
        if (Number(errno) !== 0) {
          reject(new Error((stderr || "").trim() || "操作失败，原有配置已保留。"));
          return;
        }
        try { resolve(JSON.parse(stdout)); }
        catch (_) { reject(new Error("无法读取操作结果。")); }
      };
      const bytes = new TextEncoder().encode(JSON.stringify(payload || {}));
      const encoded = btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(""));
      try { window.ksu.exec(command, JSON.stringify({env:{MFR_PAYLOAD:encoded}}), callback); }
      catch (_) {
        clearTimeout(timeout);
        delete window[callback];
        reject(new Error("无法调用模块，请重新打开管理页。"));
      }
    });
  }
  async function run(action, payload) {
    if (!/^[a-z-]+$/.test(action)) return Promise.reject(new Error("操作无效。"));
    if (typeof window.ksu?.exec !== "function" && /^https?:$/.test(window.location?.protocol || "")) {
      let response;
      try {
        response = await fetch("/cgi-bin/manager?" + action, {
          method:"POST", headers:{"Content-Type":"application/json"},
          body:JSON.stringify(payload || {}), cache:"no-store"
        });
      } catch (_) { throw new Error("模块管理服务未连接，请确认模块已启用后重试。"); }
      const result = await response.json();
      if (!response.ok || result.error) throw new Error(result.error || "操作失败。");
      return result;
    }
    const bytes = new TextEncoder().encode(JSON.stringify(payload || {}));
    if (bytes.length > 40000) {
      const upload = await run("upload-start");
      for (let offset=0; offset<bytes.length; offset+=24576) {
        await run("upload-chunk", {token:upload.token,
          chunk:btoa(Array.from(bytes.subarray(offset,offset+24576),byte=>String.fromCharCode(byte)).join(""))});
      }
      payload = {__request_token:upload.token};
    }
    return exec("/system/bin/sh /data/adb/box/scripts/box.manager " + action, payload, action === "geodata-update" ? 600000 : 180000);
  }
  function dashboardUrl(config) {
    let controller = String(config.controller || "127.0.0.1:9090");
    if (controller.startsWith(":")) controller = "127.0.0.1" + controller;
    const target = new URL("http://" + controller);
    if (target.username || target.password || target.pathname !== "/" || target.search || target.hash) {
      throw new Error("内核控制接口地址无效。请检查配置。" );
    }
    if (target.hostname === "0.0.0.0") target.hostname = "127.0.0.1";
    if (target.hostname === "[::]") target.hostname = "[::1]";
    const parameters = new URLSearchParams({protocol:"http",hostname:target.hostname,port:target.port || "80",secret:String(config.secret ?? "")});
    target.pathname = "/ui/";
    target.hash = "/setup?" + parameters.toString();
    return target.href;
  }
  window.MFR = {run, dashboardUrl, connection:() => typeof window.ksu?.exec === "function" ? exec("/system/bin/sh /data/adb/box/scripts/box.webui") : run("connection")};
})();
