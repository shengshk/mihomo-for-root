const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const path = require('path');
const source = fs.readFileSync(path.join(__dirname, '../webroot/rpc.js'), 'utf8');
let lastCommand, lastPayload;
const uploads = new Map();
const window = {ksu:{exec(command, options, callback){
  lastCommand=command;
  lastPayload=JSON.parse(Buffer.from(JSON.parse(options).env.MFR_PAYLOAD,'base64').toString('utf8'));
  let result={ok:true};
  if(command.endsWith('upload-start')) {uploads.set('testtoken',[]);result={token:'testtoken'};}
  if(command.endsWith('upload-chunk')) uploads.get(lastPayload.token).push(Buffer.from(lastPayload.chunk,'base64'));
  if(lastPayload.__request_token) lastPayload=JSON.parse(Buffer.concat(uploads.get(lastPayload.__request_token)).toString('utf8'));
  window[callback](0,JSON.stringify(result),'');
}}};
vm.runInNewContext(source,{window,URL,URLSearchParams,TextEncoder,btoa,setTimeout,clearTimeout});
(async()=>{
  for(const [controller,host,port] of [['0.0.0.0:9090','127.0.0.1','9090'],[':9091','127.0.0.1','9091'],['[::]:9092','[::1]','9092']]) {
    for(const secret of [123456,'','a&b#?+%\'"\\中文']) {
      const url=new URL(window.MFR.dashboardUrl({controller,secret}));
      const params=new URLSearchParams(url.hash.split('?')[1]);
      assert.equal(url.hostname,host);assert.equal(url.port,port);assert.equal(url.pathname,'/ui/');
      assert.equal(url.search,'');assert.equal(params.get('secret'),String(secret));
      assert.equal(params.get('hostname'),host);assert.equal(params.get('port'),port);
    }
  }
  const payload={name:'中文订阅',url:'https://example.invalid/sub?token=TEST_ONLY'};
  await window.MFR.run('profile-add',payload);
  assert.equal(JSON.stringify(lastPayload),JSON.stringify(payload));
  assert(!lastCommand.includes('token'));assert(!lastCommand.includes('example.invalid'));
  const large={exclude_apps:Array.from({length:4000},(_,i)=>'com.example.application'+i)};
  await window.MFR.run('settings-save',large);
  assert.equal(JSON.stringify(lastPayload),JSON.stringify(large));
  let httpCall;
  const browser={location:{protocol:'http:'}};
  vm.runInNewContext(source,{window:browser,URL,URLSearchParams,TextEncoder,btoa,setTimeout,clearTimeout,fetch:async(url,options)=>{
    httpCall={url,options}; return {ok:true,json:async()=>({ok:true})};
  }});
  await browser.MFR.run('settings-save',large);
  assert.equal(httpCall.url,'/cgi-bin/manager?settings-save');
  assert.equal(httpCall.options.method,'POST');
  assert.equal(httpCall.options.headers['Content-Type'],'application/json');
  assert.equal(httpCall.options.body,JSON.stringify(large));
  await browser.MFR.connection();assert.equal(httpCall.url,'/cgi-bin/manager?connection');
  const apps=require('../webroot/apps.js');
  const installed=[{packageName:'com.test.user',uid:10001,system:false},{packageName:'com.test.system',uid:1000,system:true}];
  const chosen=new Set(['com.future.app','com.test.user']);
  assert.equal(apps.rows(installed,chosen).find(app=>app.packageName==='com.future.app').installed,false);
  let preview=apps.candidates(['com.future.app','com.extra.app','com.extra.app','com.test.system','bad name'],installed,chosen);
  assert.equal(preview.length,2);assert(preview.find(app=>app.packageName==='com.test.system').system);
  chosen.delete('com.future.app');assert(!apps.rows(installed,chosen).some(app=>app.packageName==='com.future.app'));
  assert(apps.candidates(['com.future.app'],installed,chosen).some(app=>app.packageName==='com.future.app'));
  const manifest=JSON.parse(fs.readFileSync(path.join(__dirname,'../webroot/manifest.webmanifest'),'utf8'));
  assert.equal(manifest.display,'standalone');assert.equal(manifest.start_url,'/');
  for(const icon of manifest.icons){
    const png=fs.readFileSync(path.join(__dirname,'../webroot',icon.src));
    assert.equal(png.toString('ascii',1,4),'PNG');
    const size=icon.sizes.split('x').map(Number);assert.equal(png.readUInt32BE(16),size[0]);assert.equal(png.readUInt32BE(20),size[1]);
  }
  assert(manifest.icons.some(icon=>icon.purpose==='maskable'));
  let entry;
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../webroot/launcher.js'),'utf8'),{
    location:{replace(target){entry=target;}}
  });
  assert.equal(entry,'manage.html');
  console.log('PASS: same-origin connections, secret encoding and private RPC environment payload');
})().catch(error=>{console.error(error);process.exitCode=1});
