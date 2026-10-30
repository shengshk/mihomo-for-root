"use strict";
const CACHE="mfr-shell-2026102904";
const ASSETS=["./","./manage.html","./manage.css","./rpc.js","./apps.js","./manage.js","./pwa.js","./theme.js","./manifest.webmanifest","./manifest-dark.webmanifest","./icon.svg","./icon-192.png","./icon-512.png","./icon-maskable-512.png"];
const URLS=new Set(ASSETS.map(path=>new URL(path,self.registration.scope).href));
self.addEventListener("install",event=>{
  event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(ASSETS)).then(()=>self.skipWaiting()));
});
self.addEventListener("activate",event=>{
  event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith("mfr-shell-")&&key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim()));
});
self.addEventListener("fetch",event=>{
  // Cache only the public interface. API replies, passwords and subscriptions
  // never enter the service worker cache; mutations always reach the module.
  if(event.request.method!=="GET" || !URLS.has(event.request.url)) return;
  event.respondWith((async()=>{
    const cache=await caches.open(CACHE);
    try{
      const response=await fetch(event.request,{cache:"no-store"});
      if(response.ok) await cache.put(event.request,response.clone());
      return response;
    }catch(error){
      const cached=await cache.match(event.request);
      if(cached)return cached;
      throw error;
    }
  })());
});
