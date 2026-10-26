(function (root) {
  "use strict";
  const validPackage = name => /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/.test(name);
  function rows(installed, selected) {
    const result = new Map(installed.map(app => [app.packageName, {...app, installed:true}]));
    for (const name of selected) if (!result.has(name)) result.set(name,{packageName:name, label:name, installed:false, system:false});
    return [...result.values()];
  }
  function candidates(packages, installed, selected) {
    const map = new Map(installed.map(app => [app.packageName, app]));
    return [...new Set(packages)].filter(name => validPackage(name) && !selected.has(name)).map(name => {
      const app=map.get(name);
      return {packageName:name, label:app?.label || name, installed:!!app, system:!!app?.system};
    });
  }
  const api={validPackage,rows,candidates};
  if (typeof module !== "undefined" && module.exports) module.exports=api;
  else root.MFRApps=api;
})(typeof window !== "undefined" ? window : globalThis);
