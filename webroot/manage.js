(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  let state, applications = [], preferences, loadedApps = false, appsLoading, busy = false;
  let activityId = 0, appsRenderId = 0, importRenderId = 0, appsRequested = false;
  const selected = {include:new Set(),exclude:new Set()};
  let appLimit=100, importLimit=100, importCandidates=[], importSelected=new Set();
  let dnsOverrides = {}, dnsDirty = false;
  let defaultsLoaded = false, defaultsRevision = "", adgResetPending = false;
  const dnsFields = ["nameserver", "fallback", "default-nameserver"];
  const dnsLines = field => [...new Set($("dns-" + field).value.split(/\r?\n/).map(value => value.trim()).filter(Boolean))];
  function message(text, error = false) { $("message").textContent = text; $("message").classList.toggle("error",error); }
  const choice = id => $(id).dataset.value;
  function setChoice(id, value) {
    $(id).dataset.value = value;
    $(id).querySelectorAll("[data-value]").forEach(button => {
      const active = button.dataset.value === value;
      button.classList.toggle("selected", active);
      button.setAttribute("aria-pressed", String(active));
    });
  }
  function wifiNames() { return [...new Set($("wifi-ssids").value.split(/\r?\n/).filter(name => name.length))]; }
  function updateSummaries() {
    const base=state?.mihomo_base || {tun:true,dns_mode:"fake-ip",ipv6:true};
    // Only annotate missing source fields while following YAML; keep drafts intact.
    for (const [field,control,label,title,fallback] of [
      ["tun","tun-mode","tun-label","TUN 模式",base.tun ? "默认开启" : "默认关闭"],
      ["dns_mode","dns-mode","dns-mode-label","DNS 模式","默认 " + (base.dns_mode === "fake-ip" ? "Fake-IP" : "Redir-Host")],
      ["ipv6","ipv6-mode","ipv6-label","IPv6",base.ipv6 ? "默认开启" : "默认关闭"]
    ]) {
      $(label).textContent=title + (choice(control) === "follow" && base.configured?.[field] === false ? " · YAML 未配置，" + fallback : "");
    }
    const tun=choice("tun-mode") === "follow" ? base.tun : choice("tun-mode") === "on";
    const dns=choice("dns-mode") === "follow" ? base.dns_mode : choice("dns-mode");
    const v6=choice("ipv6-mode") === "follow" ? base.ipv6 : choice("ipv6-mode") === "on";
    updateNotice();
    // This card previews settings, independently of whether the core is paused.
    const hijackMode=choice("dns-hijack-mode"), entries=base.dns_hijack || [];
    const yamlCapture=base.dns_enabled && (tun ? entries.length > 0 : entries.some(entry => /^(?:(?:udp|tcp):\/\/)?(?:any|0\.0\.0\.0):53$/.test(entry)));
    const capture=$("adg-enabled").checked ? "AGH劫持DNS" :
      (hijackMode === "on" || (hijackMode === "follow" && yamlCapture)) ? "Mihomo劫持DNS" : "不劫持DNS";
    $("network-summary").textContent=[tun ? "TUN" : "TProxy",dns === "fake-ip" ? "Fake-IP" : "Redir-Host",v6 ? "IPv6" : "IPv4",capture,$("append-dns").checked ? "追加系统 DNS" : ""].filter(Boolean).join(" · ");
    const mode=choice("app-mode");
    const installed=loadedApps && selected[mode] ? applications.filter(app=>selected[mode].has(app.packageName)).length : (state?.app_counts?.[mode] || 0);
    $("apps-summary").textContent=mode === "all" ? "全部代理" : (mode === "include" ? "白名单" : "黑名单") + " · 总数 " + (selected[mode]?.size || 0) + " · 已安装 " + installed;
    $("import-apps").textContent=mode === "include" ? "添加非中国大陆应用清单" : "添加中国大陆应用清单";
    $("wifi-summary").textContent=$("wifi-pause").checked ? "已设置 " + wifiNames().length + " 个" : "未启用";
  }
  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    if (busy && (tag === "button" || tag === "input")) element.disabled = true;
    return element;
  }
  // Give both HTTP and native bridges a painted frame before starting work.
  function paint() {
    return new Promise(resolve => {
      const fallback = setTimeout(resolve, 100);
      requestAnimationFrame(() => setTimeout(() => { clearTimeout(fallback); resolve(); }, 0));
    });
  }
  async function operation(text, action, {reload = true, done = "操作成功。"} = {}) {
    if (busy) return;
    busy = true;
    const id = ++activityId, controls = new Map();
    message(text);
    (document.querySelector("dialog[open]") || document.body).append($("activity"));
    $("activity").hidden = false;
    $("activity").className = "activity";
    $("activity-text").textContent = text;
    document.querySelector("main").setAttribute("aria-busy", "true");
    // Navigation and folding remain available; freeze editable values until done.
    document.querySelectorAll("button:not([data-tab]), input, textarea").forEach(control => {
      controls.set(control, control.disabled); control.disabled = true;
    });
    let failed = false;
    try {
      await paint();
      await action();
      if (reload) await refresh();
      message(done);
      $("activity-text").textContent = "已完成";
    } catch (error) {
      failed = true;
      message(error.message, true);
      $("activity-text").textContent = error.message;
    } finally {
      busy = false;
      document.querySelector("main").setAttribute("aria-busy", "false");
      document.querySelectorAll("button:not([data-tab]), input, textarea").forEach(control => {
        control.disabled = controls.get(control) || false;
      });
      updateServiceControl(); updateAdgVisibility(); updateAdgControl(); updateDefaultsControl();
      if ($("advanced-settings").open && !defaultsLoaded && !failed) setTimeout(()=>{
        if (!busy && $("advanced-settings").open && !defaultsLoaded) $("advanced-settings").dispatchEvent(new Event("toggle"));
      },0);
      scheduleControl("profile"); scheduleControl("edit");
      if (!$("activity").closest("dialog")?.open) document.body.append($("activity"));
      $("activity").classList.add("finished");
      $("activity").classList.toggle("error", failed);
      setTimeout(() => {
        if (id !== activityId || busy) return;
        $("activity").classList.add("fading");
        setTimeout(() => { if (id === activityId && !busy) $("activity").hidden = true; }, 200);
      }, failed ? 3000 : 500);
      if (appsRequested) {
        appsRequested = false;
        if (!failed && $("apps-settings").open) setTimeout(() => {
          if (!busy && $("apps-settings").open) operation("加载应用…",updateAppPicker,{reload:false,done:"应用已加载。"});
        }, 0);
      }
    }
  }
  function adgEditor(lines) {
    const hint="# 允许增删或者注释";
    return (lines.some(line=>line.trim() === hint) ? lines : [hint,...lines]).join("\n");
  }
  const adgLines=id=>$(id).value.split(/\r?\n/).filter(line=>line.trim().length > 0);
  function updateServiceControl() {
    $("open-dashboard").disabled = busy || !state?.running;
  }
  function renderServiceState(current = state) {
    $("state").textContent = current.running ? "运行中" : current.wifi_paused ? "代理已暂停" : "已停止";
    $("state").classList.toggle("on",current.running);
    $("service-toggle").textContent = current.wifi_paused ? "保持停止" : current.running ? "停止代理" : "启动代理";
    $("active-name").textContent = current.summary;
    $("active-name").title = current.summary;
    updateServiceControl();
  }
  function updateAdgVisibility() {
    // Visibility follows successfully applied preferences, never an unsaved checkbox.
    const enabled = !!state?.preferences.adguardhome_enabled;
    $("adg-settings").hidden = !enabled;
    $("copy-adg").hidden = !enabled;
    if (!enabled) $("adg-settings").open = false;
    $("help-summary").textContent = enabled ? "程序使用说明" : "程序使用说明 • AGH隐藏入口";
    $("help-enable-adg").hidden = !state || enabled;
    $("help-enable-adg").disabled = busy || !state || enabled;
  }
  function renderAdgState() {
    const adg = state.adguardhome || {};
    const upstreamNames={system:"系统DNS 作为上游",mihomo:"MihomoDNS 作为上游",pending:"上游待就绪",other:"其他DNS 作为上游",unknown:"上游未知"};
    const filterNames={enabled:"阻止 IPv6 解析",disabled:"允许 IPv6 解析",unknown:"IPv6 解析状态未知"};
    $("adg-state").textContent = adg.error || (!state.preferences.adguardhome_enabled ? "未启用" :
      !adg.running ? "已停止" : adg.api_available === false ? "状态读取失败" :
      "运行中 · " + (upstreamNames[adg.upstream] || "上游未知") + " · " + (filterNames[adg.aaaa_filter] || "v6状态未知"));
    updateAdgVisibility();
  }
  function updateAdgControl() {
    const enabled = $("adg-enabled").checked;
    $("dns-hijack-mode").querySelectorAll("button").forEach(button => button.disabled = busy || enabled);
    $("dns-hijack-mode").hidden = enabled;
    $("dns-hijack-label").textContent = enabled ? "Mihomo DNS 劫持：关闭 · AGH 接管" : "Mihomo DNS 劫持";
    $("dns-hijack-help").hidden = enabled;
    $("adg-shortcuts").disabled = busy || !enabled;
    $("adg-ipv6-allow").disabled = busy || !enabled || !$("adg-ipv6-filter").checked;
    $("adg-ipv6-field").hidden = !$("adg-ipv6-filter").checked;
    $("adg-filter-field").hidden = !$("adg-adblock").checked;
    $("dns-hijack-help").textContent = "跟随 YAML／开启／关闭，接管普通 TCP、UDP 53。";
  }
  function renderDns(values) {
    for (const field of dnsFields) $("dns-" + field).value = (values[field] || []).join("\n");
  }
  for (const field of dnsFields) $("dns-" + field).addEventListener("input", () => {
    dnsDirty = true;
    const values = dnsLines(field);
    if (JSON.stringify(values) === JSON.stringify(state.dns.base[field])) delete dnsOverrides[field];
    else dnsOverrides[field] = values;
  });
  $("dns-restore").onclick = () => {
    dnsDirty = true;
    dnsOverrides = {};
    renderDns(state.dns.base);
    message("已恢复配置值，保存后生效。");
  };
  $("adg-enabled").onchange = () => { updateAdgControl(); updateSummaries(); };
  $("adg-ipv6-filter").onchange = updateAdgControl;
  $("adg-adblock").onchange = updateAdgControl;
  $("append-dns").onchange = updateSummaries;
  $("wifi-pause").onchange = updateSummaries;
  $("wifi-ssids").addEventListener("input",updateSummaries);
  $("adg-restore").onclick = () => {
    const defaults=state?.adg_defaults;
    if (!defaults) return;
    $("adg-ipv6-filter").checked=defaults.ipv6_filter;
    $("adg-ipv6-allow").value=adgEditor(defaults.ipv6_allow);
    $("adg-adblock").checked=defaults.adblock;
    $("adg-filter-urls").value=adgEditor(defaults.filter_urls);
    adgResetPending=true;
    $("adg-restore-status").hidden=false;
    updateAdgControl();
    message("已恢复默认配置，保存后生效。");
  };
  $("open-adg").onclick = () => {
    if (!state?.preferences.adguardhome_enabled) { message("请先启用 AdGuard Home。"); return; }
    location.href = "http://127.0.0.1:9092/";
  };
  $("help-enable-adg").onclick = () => {
    if (!busy && state && !state.preferences.adguardhome_enabled) $("adg-enable-dialog").showModal();
  };
  $("adg-enable-cancel").onclick = () => $("adg-enable-dialog").close();
  $("adg-enable-confirm").onclick = () => {
    $("adg-enable-dialog").close();
    operation("启用 AdGuard Home…", async () => {
      await MFR.run("adg-enable");
      const current = await MFR.run("status");
      if (!current.preferences.adguardhome_enabled) throw new Error("AdGuard Home 未能启用，请重试。");
      // Keep unrelated settings drafts; this action changes only AGH's enable flag.
      state.preferences.adguardhome_enabled = true;
      state.adguardhome = current.adguardhome;
      state.running = current.running; state.wifi_paused = current.wifi_paused;
      state.summary = current.summary;
      $("adg-enabled").checked = true;
      renderServiceState(); renderAdgState(); updateAdgControl(); updateSummaries();
      $("adg-settings").open = true;
    }, {reload:false,done:"AdGuard Home 已启用。"});
  };
  async function refresh() {
    state = await MFR.run("status");
    renderServiceState();
    $("defaults-summary").textContent = state.defaults_custom ? "自定义兜底" : "内置兜底";
    $("core-version").textContent = state.version;
    setChoice("routing-mode", state.routing_mode || state.preferences.routing_mode || "rule");
    dnsDirty = false;
    dnsOverrides = structuredClone(state.dns.override);
    renderDns(state.dns.effective);
    $("dns-detected").textContent = state.dns_detected.join("\n") || "未检测到系统 DNS";
    preferences = state.preferences;
    $("adg-enabled").checked = preferences.adguardhome_enabled || false;
    renderAdgState();
    adgResetPending=false;
    $("adg-restore-status").hidden=true;
    const controls=state.adg_controls;
    $("adg-ipv6-filter").checked=controls.ipv6_filter;
    $("adg-ipv6-allow").value=adgEditor(controls.ipv6_allow);
    $("adg-adblock").checked=controls.adblock;
    $("adg-filter-urls").value=adgEditor(controls.filter_urls);
    updateAdgControl();
    setChoice("tun-mode", preferences.tun_mode || "follow");
    setChoice("dns-mode", preferences.dns_mode || "follow");
    setChoice("ipv6-mode", preferences.ipv6_mode);
    setChoice("dns-hijack-mode", preferences.dns_hijack_mode || "follow");
    $("wifi-pause").checked = preferences.wifi_pause_enabled || false;
    $("wifi-ssids").value = (preferences.wifi_pause_ssids || []).join("\n");
    $("current-wifi").textContent = state.current_ssid ? "当前 Wi-Fi：" + state.current_ssid : "当前未连接 Wi-Fi";
    $("append-dns").checked = preferences.append_network_dns;
    setChoice("app-mode", preferences.app_mode);
    selected.include = new Set(preferences.include_apps);
    selected.exclude = new Set(preferences.exclude_apps);
    updateSummaries();
    renderProfiles(); await updateAppPicker();
    if ($("help-settings").open) await refreshHelpAddress();
  }
  function renderProfiles() {
    $("active-profile").replaceChildren();
    $("profile-list").replaceChildren();
    for (const profile of state.configs.profiles) {
      const card=node("article"), head=node("div",undefined,"profile-head");
      head.append(node("h2",profile.name));
      if (profile.id === state.configs.active) head.append(node("span","正在使用","current"));
      card.append(head,node("p",profile.url ? "订阅配置" : "本地配置","muted"));
      if (profile.updated) card.append(node("p","上次更新："+profile.updated,"muted"));
      if (profile.url) card.append(node("p",profile.cron ? "定时刷新：" + profile.cron : "定时刷新：关闭","muted"));
      const actions=node("div",undefined,"actions");
      if (profile.id !== state.configs.active) {
        const use=node("button","使用此配置");
        use.onclick=()=>operation("切换配置…",()=>MFR.run("profile-activate",{id:profile.id})); actions.append(use);
      }
      if (profile.url) {
        const update=node("button","刷新订阅");
        update.onclick=()=>operation("更新订阅…",()=>MFR.run("profile-update",{id:profile.id})); actions.append(update);
      }
      const edit=node("button","编辑");
      edit.onclick=()=>editProfile(profile); actions.append(edit);
      if (profile.id !== state.configs.active) {
        const remove=node("button","删除","danger");
        remove.onclick=()=>{if(confirm("删除配置“"+profile.name+"”？"))operation("正在删除配置…",()=>MFR.run("profile-delete",{id:profile.id}));}; actions.append(remove);
      }
      card.append(actions); $(profile.id === state.configs.active ? "active-profile" : "profile-list").append(card);
    }
  }
  let editingProfile;
  function scheduleControl(prefix) {
    const enabled = $(prefix + "-auto"), hasUrl = !!$(prefix + "-url").value.trim();
    enabled.disabled = busy || !hasUrl;
    if (!hasUrl) enabled.checked = false;
    $(prefix + "-cron-field").hidden = !enabled.checked;
    $(prefix + "-cron").required = enabled.checked;
  }
  for (const prefix of ["profile", "edit"]) {
    $(prefix + "-url").addEventListener("input", () => scheduleControl(prefix));
    $(prefix + "-auto").onchange = () => scheduleControl(prefix);
  }
  function editProfile(profile) {
    editingProfile = profile.id;
    $("edit-name").value = profile.name;
    $("edit-url").value = profile.url || "";
    $("edit-auto").checked = !!profile.cron;
    $("edit-cron").value = profile.cron || "10 2 * * *";
    scheduleControl("edit");
    $("edit-dialog").showModal();
  }
  $("edit-cancel").onclick = () => $("edit-dialog").close();
  $("edit-profile").onsubmit = event => {
    event.preventDefault();
    const payload = {id:editingProfile,name:$("edit-name").value.trim(),url:$("edit-url").value.trim(),
      cron:$("edit-auto").checked ? $("edit-cron").value.trim() : ""};
    operation("保存订阅…",async()=>{
      await MFR.run("profile-edit",payload);
      $("edit-dialog").close();
    });
  };
  async function loadApps() {
    if (loadedApps) return;
    if (appsLoading) return appsLoading;
    appsLoading = (async () => {
      applications = await MFR.run("apps");
      if (typeof window.ksu?.getPackagesInfo === "function") {
        try {
          // Keep large installed-app lists responsive on native WebUI too.
          for (let start = 0; start < applications.length; start += 100) {
            await paint();
            const batch = applications.slice(start, start + 100);
            const info = JSON.parse(window.ksu.getPackagesInfo(JSON.stringify(batch.map(app => app.packageName))));
            const labels = new Map(info.map(app => [app.packageName, app.appLabel || app.label]));
            batch.forEach(app => app.label = labels.get(app.packageName) || app.packageName);
          }
        } catch (_) { /* Package names remain usable on other compatible managers. */ }
      }
      applications.sort((a,b) => (a.label || a.packageName).localeCompare(b.label || b.packageName, "zh-CN"));
      const counts = new Map();
      applications.forEach(app => counts.set(app.uid, (counts.get(app.uid) || 0) + 1));
      applications.forEach(app => app.sharedUid = counts.get(app.uid) > 1);
      loadedApps = true;
    })();
    try { await appsLoading; } finally { appsLoading = undefined; }
  }
  function updateNotice() {
    const dns=choice("dns-mode") === "follow" ? state?.mihomo_base?.dns_mode : choice("dns-mode");
    $("fakeip-notice").hidden = choice("app-mode") === "all" || dns !== "fake-ip";
  }
  async function updateAppPicker() {
    updateSummaries();
    $("app-picker").hidden = choice("app-mode") === "all";
    $("import-apps").hidden = choice("app-mode") === "all";
    updateNotice();
    if ($("app-picker").hidden || !$("apps-settings").open) return;
    await loadApps(); await renderApps();
  }
  function appCount() {
    const mode=choice("app-mode"), names=selected[mode];
    const installed=new Set(applications.map(app=>app.packageName));
    const present=[...names].filter(name=>installed.has(name)).length;
    $("app-count").textContent=`已选 ${names.size} 项：已安装 ${present}，未安装 ${names.size-present}。`;
  }
  async function renderApps() {
    const renderId = ++appsRenderId;
    updateSummaries();
    const mode=choice("app-mode");
    if (mode === "all") return;
    appCount();
    const search=$("app-search").value.toLowerCase(), install=choice("app-install-filter"), kind=choice("app-kind-filter");
    const rows=MFRApps.rows(applications,selected[mode]).filter(app => {
      if (install === "installed" && !app.installed || install === "pending" && app.installed) return false;
      if (kind === "system" && (!app.installed || !app.system) || kind === "user" && (!app.installed || app.system)) return false;
      if ($("app-selected-only").checked && !selected[mode].has(app.packageName)) return false;
      return ((app.label||"")+app.packageName).toLowerCase().includes(search);
    });
    $("app-list").replaceChildren();
    let rendered = 0;
    for (const app of rows.slice(0,appLimit)) {
      if (renderId !== appsRenderId) return;
      if (rendered++ % 50 === 0) { await paint(); if (renderId !== appsRenderId) return; }
      const row=node("label",undefined,"app"), name=node("span",app.label||app.packageName,"app-name");
      name.append(node("small",app.packageName));
      name.append(node("small",!app.installed?"未安装 · 包名已保留":(app.system?"系统应用":"用户应用")+(app.sharedUid?" · 共享 UID "+app.uid:" · UID "+app.uid)));
      const checkbox=node("input"); checkbox.type="checkbox"; checkbox.checked=selected[mode].has(app.packageName);
      checkbox.onchange=()=>{checkbox.checked?selected[mode].add(app.packageName):selected[mode].delete(app.packageName);renderApps();};
      row.append(name,checkbox); $("app-list").append(row);
    }
    if (!rows.length) $("app-list").append(node("p","没有匹配项目。","muted"));
    $("app-more").hidden=rows.length<=appLimit;
  }
  function importRows() {
    const search=$("import-search").value.toLowerCase();
    return importCandidates.filter(app=>(app.packageName+app.label).toLowerCase().includes(search));
  }
  async function renderImport() {
    const renderId = ++importRenderId;
    const rows=importRows();
    $("import-count").textContent=`待新增 ${importCandidates.length} 项，已勾选 ${importSelected.size} 项；当前搜索匹配 ${rows.length} 项。`;
    $("import-list").replaceChildren();
    let rendered = 0;
    for (const app of rows.slice(0,importLimit)) {
      if (renderId !== importRenderId) return;
      if (rendered++ % 50 === 0) { await paint(); if (renderId !== importRenderId) return; }
      const row=node("label",undefined,"app"), name=node("span",app.label,"app-name");
      name.append(node("small",app.packageName),node("small",app.installed?(app.system?"系统应用":"已安装"):"未安装 · 安装后自动排除"));
      const input=node("input");input.type="checkbox";input.checked=importSelected.has(app.packageName);
      input.onchange=()=>{input.checked?importSelected.add(app.packageName):importSelected.delete(app.packageName);renderImport();};
      row.append(name,input);$("import-list").append(row);
    }
    $("import-more").hidden=rows.length<=importLimit;
  }
  async function copyAddress(text) {
    if (navigator.clipboard?.writeText) {
      try { await navigator.clipboard.writeText(text); return; } catch (_) {}
    }
    const input=document.createElement("textarea"), focused=document.activeElement;
    input.value=text; input.readOnly=true; input.tabIndex=-1;
    input.setAttribute("aria-hidden","true");
    input.style.cssText="position:fixed;left:-9999px;opacity:0";
    document.body.append(input);
    try {
      input.focus({preventScroll:true}); input.select(); input.setSelectionRange(0,text.length);
      if (!document.execCommand("copy")) throw new Error("复制失败，请长按地址复制。");
    } finally { input.remove(); focused?.focus({preventScroll:true}); }
  }
  document.querySelectorAll("[data-copy-address]").forEach(button=>button.onclick=async()=>{
    if (!button.dataset.copyAddress) { message("请重新展开帮助读取地址。", true); return; }
    try { await copyAddress(button.dataset.copyAddress); }
    catch (error) { message(error.message, true); }
  });
  let helpGeneration=0;
  async function refreshHelpAddress() {
    const generation=++helpGeneration;
    if (!$("help-settings").open) return;
    const button=$("copy-dashboard");
    button.dataset.copyAddress="";
    button.querySelector("code").textContent="正在读取…";
    try {
      const address=new URL(MFR.dashboardUrl(await MFR.connection()));
      // Copy the dashboard entry only; never display or copy its secret fragment.
      address.hash="";
      if (generation !== helpGeneration || !$("help-settings").open) return;
      button.dataset.copyAddress=address.href;
      button.querySelector("code").textContent=address.href;
    } catch (_) {
      if (generation === helpGeneration && $("help-settings").open) button.querySelector("code").textContent="地址读取失败，请重新展开";
    }
  }
  $("help-settings").addEventListener("toggle",refreshHelpAddress);
  function updateDefaultsControl() {
    for (const id of ["defaults-yaml","defaults-save","defaults-restore"]) $(id).disabled=busy || !defaultsLoaded;
  }
  function showDefaults(result) {
    $("defaults-yaml").value=result.yaml;
    defaultsRevision=result.revision; defaultsLoaded=true;
    $("defaults-summary").textContent=result.custom ? "自定义兜底" : "内置兜底";
    $("defaults-status").textContent=result.custom ? "自定义内容升级后保留。" : "正在使用内置兜底。";
    updateDefaultsControl();
  }
  async function refreshAfterDefaults() {
    // Refresh effective values without discarding drafts in the other cards.
    state=await MFR.run("status"); preferences=state.preferences;
    $("state").textContent=state.running ? "运行中" : state.wifi_paused ? "代理已暂停" : "已停止";
    $("state").classList.toggle("on",state.running);
    $("service-toggle").textContent=state.wifi_paused ? "保持停止" : state.running ? "停止代理" : "启动代理";
    $("active-name").textContent=state.summary; $("active-name").title=state.summary;
    if (!dnsDirty) renderDns(state.dns.effective);
    updateSummaries();
  }
  $("defaults-yaml").addEventListener("input",()=>{
    $("defaults-status").textContent="尚未保存。";
  });
  $("advanced-settings").addEventListener("toggle",()=>{
    if (!$("advanced-settings").open || defaultsLoaded || busy) return;
    operation("读取兜底…",async()=>showDefaults(await MFR.run("defaults-get")),{reload:false,done:"兜底已加载。"});
  });
  $("defaults-form").onsubmit=event=>{
    event.preventDefault();
    if (!defaultsLoaded) return;
    const payload={yaml:$("defaults-yaml").value,revision:defaultsRevision};
    operation("检查并应用兜底…",async()=>{
      showDefaults(await MFR.run("defaults-save",payload));
      await refreshAfterDefaults();
    },{reload:false,done:"兜底已保存并应用。"});
  };
  $("defaults-restore").onclick=()=>{
    if (!defaultsLoaded) return;
    operation("恢复内置兜底…",async()=>{
      showDefaults(await MFR.run("defaults-restore",{revision:defaultsRevision}));
      await refreshAfterDefaults();
    },{reload:false,done:"已恢复内置兜底。"});
  };
  let logTimer, logGeneration = 0, logInFlight = false, logPageActive = true;
  const logActive = () => logPageActive && $("logs-settings").open && !document.hidden && !$("system").hidden;
  function syncLogs() {
    clearTimeout(logTimer);
    logGeneration++;
    if (logActive() && !logInFlight) readLogs();
  }
  async function readLogs() {
    if (!logActive() || logInFlight) return;
    const generation = logGeneration;
    logInFlight = true;
    $("log-status").textContent = "读取日志…";
    try {
      const result = await MFR.run("logs", {type:choice("log-type")});
      if (generation !== logGeneration || !logActive()) return;
      const content = $("log-content"), bottom = content.scrollHeight - content.scrollTop - content.clientHeight < 24;
      const text = result.text || "暂无日志";
      if (content.textContent !== text) {
        content.textContent = text;
        if (bottom) content.scrollTop = content.scrollHeight;
      }
      $("log-status").textContent = "更新于 " + result.updated + " · 每 5 秒刷新";
    } catch (error) {
      if (generation === logGeneration && logActive()) $("log-status").textContent = error.message;
    } finally {
      logInFlight = false;
      if (logActive()) {
        if (generation !== logGeneration) readLogs();
        else logTimer = setTimeout(readLogs, 5000);
      }
    }
  }
  setChoice("log-type", "module");
  $("logs-settings").addEventListener("toggle", syncLogs);
  document.addEventListener("visibilitychange", syncLogs);
  window.addEventListener("pagehide", () => { logPageActive = false; syncLogs(); });
  window.addEventListener("pageshow", () => { logPageActive = true; syncLogs(); });
  document.querySelectorAll("[data-tab]").forEach(button=>button.onclick=()=>{
    document.querySelectorAll(".tab").forEach(section=>section.hidden=section.id!==button.dataset.tab);
    document.querySelectorAll("[data-tab]").forEach(tab=>tab.classList.toggle("selected",tab===button));
    syncLogs();
    if (button.dataset.tab === "system" && $("help-settings").open) refreshHelpAddress();
  });
  $("open-dashboard").onclick=()=>{
    if (!state?.running || busy) return;
    operation("打开面板…",async()=>{
      const connection = await MFR.connection();
      state.running = connection.running; state.wifi_paused = connection.wifi_paused;
      if (!state.running) renderServiceState();
      if (!state.running) throw new Error("代理未运行。");
      location.assign(MFR.dashboardUrl(connection));
    },{reload:false});
  };
  $("service-toggle").onclick=()=>operation(state.running || state.wifi_paused ?"正在停止代理…":"正在启动代理…",()=>MFR.run(state.running || state.wifi_paused ? "stop":"start"));
  $("core-check").onclick=()=>operation("检查更新…",async()=>{
    const result=await MFR.run("core-check");
    $("latest-version").textContent="官方稳定版："+result.latest+(state.version.includes(result.latest)?"，当前已是此版本。":"，可点击更新。");
  }, {reload:false});
  $("core-update").onclick=()=>{if(confirm("更新内核会短暂重启正在运行的代理，继续？"))operation("更新内核…",()=>MFR.run("core-update"));};
  $("core-rollback").onclick=()=>{if(confirm("恢复上一版本内核？"))operation("正在检查并恢复上一版本…",()=>MFR.run("core-rollback"));};
  document.querySelectorAll(".choices").forEach(group => group.querySelectorAll("[data-value]").forEach(button => {
    button.onclick = () => {
      setChoice(group.id, button.dataset.value);
      if (group.id === "log-type") { syncLogs(); return; }
      updateSummaries();
      if (group.id === "app-mode") {appLimit=100;operation("加载应用…",updateAppPicker,{reload:false,done:"应用已加载。"});}
      if (group.id === "app-kind-filter" || group.id === "app-install-filter") {appLimit=100;renderApps();}
    };
  }));
  $("add-current-wifi").onclick = () => operation("读取 Wi-Fi…", async () => {
    const current = await MFR.run("status");
    if (!current.current_ssid) throw new Error("当前未连接 Wi-Fi。");
    $("wifi-ssids").value = [...new Set([...wifiNames(), current.current_ssid])].join("\n");
    $("current-wifi").textContent = "当前 Wi-Fi：" + current.current_ssid;
    updateSummaries();
  }, {reload:false,done:"已添加当前 Wi-Fi。"});
  // Native named details handles new browsers; toggle keeps older WebViews compatible.
  document.querySelectorAll("details.fold").forEach(detail => detail.addEventListener("toggle", () => {
    if (!detail.open) return;
    document.querySelectorAll("details.fold").forEach(other => { if (other !== detail) other.open = false; });
    if (detail.id === "apps-settings") {
      if (busy) appsRequested = true;
      else operation("加载应用…",updateAppPicker,{reload:false,done:"应用已加载。"});
    }
  }));
  $("app-search").oninput=()=>{appLimit=100;renderApps();};
  $("app-selected-only").onchange=()=>{appLimit=100;renderApps();};
  $("app-more").onclick=()=>operation("加载应用…",async()=>{appLimit+=100;await renderApps();},{reload:false,done:"应用已加载。"});
  $("add-package").onclick=()=>{
    const name=$("manual-package").value.trim(), mode=choice("app-mode");
    if (!MFRApps.validPackage(name)) {message("请填写有效的应用包名。",true);return;}
    selected[mode].add(name);$("manual-package").value="";
    setChoice("app-install-filter","all");setChoice("app-kind-filter","all");
    $("app-search").value=name;renderApps();message("包名已添加，保存设置后生效。");
  };
  let importMode="exclude";
  $("import-apps").onclick=()=>operation("加载清单…",async()=>{
    await loadApps();
    importMode=choice("app-mode");
    const title=importMode === "include" ? "添加非中国大陆应用清单" : "添加中国大陆应用清单";
    $("import-title").textContent=title;
    $("import-confirm").textContent=importMode === "include" ? "追加到白名单" : "追加到黑名单";
    const result=await MFR.run("app-list-preview",{kind:importMode === "include" ? "proxy" : "china"});
    await paint();
    importCandidates=MFRApps.candidates(result.packages,applications,selected[importMode]);
    importSelected=new Set(importCandidates.filter(app=>!app.system).map(app=>app.packageName));
    importLimit=100;$("import-search").value="";
    const origin={online:"在线最新清单",cache:"在线拉取失败，使用上次成功缓存",builtin:"在线拉取失败，使用模块内置清单"};
    $("import-source").textContent=(origin[result.origin]||"内置清单")+" · "+result.updated+" · "+result.source;
    await renderImport();$("import-dialog").showModal();
  },{reload:false,done:"请选择要追加的项目。"});
  $("import-search").oninput=()=>{importLimit=100;renderImport();};
  $("import-more").onclick=()=>operation("加载清单…",async()=>{importLimit+=100;await renderImport();},{reload:false,done:"清单已加载。"});
  $("import-all").onclick=()=>{importRows().forEach(app=>importSelected.add(app.packageName));renderImport();};
  $("import-none").onclick=()=>{importRows().forEach(app=>importSelected.delete(app.packageName));renderImport();};
  $("import-cancel").onclick=()=>$("import-dialog").close();
  $("import-confirm").onclick=()=>{
    const present=new Set(applications.map(app=>app.packageName));
    const installed=[...importSelected].filter(name=>present.has(name)).length;
    importSelected.forEach(name=>selected[importMode].add(name));
    $("import-summary").textContent=`新增 ${importSelected.size} 项，已安装 ${installed}，未安装 ${importSelected.size-installed}。保存设置后生效。`;
    $("import-dialog").close();renderApps();message("清单已追加，原有选择保留；保存设置后生效。");
  };
  setChoice("app-install-filter","installed");setChoice("app-kind-filter","all");
  document.addEventListener("visibilitychange",()=>{
    if(!document.hidden&&!busy&&state){
      loadedApps=false;
      if($("apps-settings").open&&choice("app-mode")!=="all") operation("加载应用…",async()=>{await loadApps();await renderApps();},{reload:false,done:"应用已加载。"});
    }
  });
  $("settings-form").onsubmit=event=>{
    event.preventDefault();
    const payload={tun_mode:choice("tun-mode"),dns_mode:choice("dns-mode"),adguardhome_enabled:$("adg-enabled").checked,routing_mode:choice("routing-mode"),ipv6_mode:choice("ipv6-mode"),dns_hijack_mode:choice("dns-hijack-mode"),wifi_pause_enabled:$("wifi-pause").checked,wifi_pause_ssids:wifiNames(),append_network_dns:$("append-dns").checked,app_mode:choice("app-mode"),include_apps:[...selected.include],exclude_apps:[...selected.exclude]};
    payload.adg_reset_defaults=adgResetPending;
    payload.adg_controls={ipv6_filter:$("adg-ipv6-filter").checked,ipv6_allow:adgLines("adg-ipv6-allow"),adblock:$("adg-adblock").checked,filter_urls:adgLines("adg-filter-urls")};
    payload.dns_profile_id = state.configs.active;
    payload.dns_override = dnsOverrides;
    operation("保存中…",()=>MFR.run("settings-save",payload));
  };
  $("add-profile").onsubmit=event=>{
    event.preventDefault();
    operation("检查配置…",async()=>{
      const payload={name:$("profile-name").value.trim(),url:$("profile-url").value.trim(),cron:$("profile-auto").checked ? $("profile-cron").value.trim() : ""};
      if (!payload.url) {
        const file=$("profile-file").files[0];
        if (!file) throw new Error("请填写订阅链接或选择 YAML 文件。");
        if (file.size>4194304) throw new Error("配置文件不能超过 4 MB。");
        const upload=await MFR.run("upload-start"); payload.token=upload.token;
        const bytes=new Uint8Array(await file.arrayBuffer());
        for(let offset=0;offset<bytes.length;offset+=24576){
          const chunk=btoa(Array.from(bytes.subarray(offset,offset+24576),byte=>String.fromCharCode(byte)).join(""));
          await MFR.run("upload-chunk",{token:upload.token,chunk});
        }
      }
      await MFR.run("profile-add",payload);
      $("add-profile").reset(); scheduleControl("profile");
    });
  };
  operation("读取状态…",refresh,{reload:false,done:"已连接模块管理。"});
})();
