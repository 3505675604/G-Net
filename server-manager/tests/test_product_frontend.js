'use strict';
// Offline regression checks for product workflows and credentials. No service or SSH connection.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const fixtureSource=fs.readFileSync(path.join(__dirname,'test_frontend.js'),'utf8').split('const tests=[];')[0];
const fixture=vm.createContext({require,__dirname,console,setImmediate,Headers,URL,Blob});
vm.runInContext(fixtureSource+'\nglobalThis.fixtures={harness,response,deferred,immediate};',fixture);
const {harness,response,deferred,immediate}=fixture.fixtures;
const source=fs.readFileSync(path.join(__dirname,'../static/product-ui.js'),'utf8');
new vm.Script(source,{filename:'product-ui.js'});
const server={id:'A',name:'示例服务器',host:'ecs.example',port:22,user:'ubuntu',auth_type:'private_key'};
const product=()=>({ok:true,product:{name:'G-Network',publisher:'Gloria',version:'0.2.0',platform:'windows-x64'},onboarding:{completed:true},updates:{enabled:false,state:'unconfigured'}});
async function productHarness(overrides={}){
  const h=harness();h.setFetch(async url=>url==='/api/product'?response({...product(),...overrides}):url==='/api/servers'?response([server]):url==='/api/nodes/protocols'?response({protocols:{},ss_methods:[]}):response({ok:true}));
  h.run(source);h.run('globalThis.tasksActive=false');
  await h.run('window.ProductUI.init({api,apiResponse,jsonPost,toast,showModal,closeModal,showAdd,loadServers,initNode,hasTasks:()=>globalThis.tasksActive,onImported:()=>{cur=null;resetServerView();}})');
  return h;
}
const tests=[];function test(name,fn){tests.push({name,fn});}
test('all SSH forms select password, private key or agent without mixing credentials',()=>{
  const h=harness();
  for(const prefix of ['a','nm-d','nm-e','nm-x','nlm']){
    h.element('#'+prefix+'-pass').value='password';h.element('#'+prefix+'-key').value='private-key';h.element('#'+prefix+'-passphrase').value='key-passphrase';
    h.element('#'+prefix+'-auth').value='private_key';
    const data=JSON.parse(h.run('JSON.stringify(authPayload('+JSON.stringify(prefix)+'))'));
    assert.deepEqual(data,{auth_type:'private_key',private_key:'private-key',key_passphrase:'key-passphrase'});
    h.element('#'+prefix+'-auth').value='agent';assert.equal(h.run('authValidation(authPayload('+JSON.stringify(prefix)+'))'),'');
    assert.deepEqual(JSON.parse(h.run('JSON.stringify(authPayload('+JSON.stringify(prefix)+'))')),{auth_type:'agent'});
    h.run('authTypeChanged('+JSON.stringify(prefix)+')');
    assert.equal(h.element('#'+prefix+'-pass').value,'');assert.equal(h.element('#'+prefix+'-key').value,'');assert.equal(h.element('#'+prefix+'-passphrase').value,'');
    assert.equal(h.element('#'+prefix+'-password-field').hidden,true);assert.equal(h.element('#'+prefix+'-agent-hint').hidden,false);
  }
  assert.match(h.run('authValidation({auth_type:"private_key",private_key:"密".repeat(50000)})'),/128 KiB/);
  assert.match(h.run('authValidation({auth_type:"password",password:""})'),/密码/);
  assert.match(h.run('authValidation({auth_type:"unknown"})'),/无效/);
});
test('private key file size limits and cancellation discard late file reads',async()=>{
  const h=harness(),file=h.element('#a-key-file');h.element('#a-auth').value='private_key';
  file.files=[{size:128*1024+1,text:()=>{throw new Error('must not read');}}];await h.run('readPrivateKey("a",document.querySelector("#a-key-file"))');assert.match(h.element('#toast').textContent,/128 KiB/);
  const late=deferred();file.files=[{size:20,text:()=>late.promise}];const read=h.run('readPrivateKey("a",document.querySelector("#a-key-file"))');h.run('clearAuthInputs("a")');late.resolve('late-private-key');await read;assert.equal(h.element('#a-key').value,'');
  file.files=[{size:20,text:async()=>'local-private-key'}];await h.run('readPrivateKey("a",document.querySelector("#a-key-file"))');assert.equal(h.element('#a-key').value,'local-private-key');assert.equal(h.requests.length,0);
  h.run('showAdd()');h.element('#a-pass').value='secret';h.element('#a-key').value='secret-key';h.run('closeModal("#add-mask")');assert.equal(h.element('#a-pass').value,'');assert.equal(h.element('#a-key').value,'');
});
test('metadata-only connections require credentials and editing sends PUT without fetching secrets',async()=>{
  const h=harness();h.run('editServer('+JSON.stringify({...server,credential_required:true})+')');
  await h.run('addServer()');assert.equal(h.requests.length,0);assert.match(h.element('#toast').textContent,/私钥/);
  h.element('#a-key').value='test-private-key';h.element('#a-passphrase').value='test-passphrase';
  h.setFetch(async(url,options)=>url==='/api/servers/A'&&options.method==='PUT'?response({ok:true,id:'A'}):url==='/api/servers'?response([server]):url==='/api/nodes/protocols'?response({protocols:{},ss_methods:[]}):url.endsWith('/info')?response({tools:{}}):url.endsWith('/capabilities')?response({tools:{}}):response({ok:true}));
  await h.run('addServer()');const put=h.requests.find(r=>r.options.method==='PUT');assert.ok(put);assert.equal(JSON.parse(put.options.body).auth_type,'private_key');assert.equal(JSON.parse(put.options.body).private_key,'test-private-key');assert.equal(h.element('#a-key').value,'');assert.equal(h.element('#a-passphrase').value,'');assert.ok(!h.requests.some(r=>r.url.includes('secret')));
});
test('capabilities disable unsupported actions, survive busy transitions and escape remote data',async()=>{
  const h=harness();h.run('cur='+JSON.stringify(server));
  h.setFetch(async()=>response({os:'<img src=x onerror=alert(1)>',arch:'x86_64',user:'ubuntu',has_apt:false,tools:{install_node:{available:false,reason:'<script>apt missing</script>'},check_env:{available:true}}}));
  await h.run('loadCapabilities("A",serverVersion)');assert.ok(!h.element('#capabilities-banner').innerHTML.includes('<img'));assert.match(h.element('#capabilities-banner').innerHTML,/&lt;img/);
  const button=()=>h.element('#tools').querySelectorAll('[data-tool-action]').find(b=>b.dataset.toolAction==='install_node');assert.equal(button().disabled,true);assert.match(button().innerHTML,/&lt;script/);
  h.run('setBusy("tool-job","#tools .tool",true);setBusy("tool-job","#tools .tool",false)');assert.equal(button().disabled,true);
  const count=h.requests.length;await h.run('runTool("install_node")');assert.equal(h.requests.length,count);assert.match(h.element('#toast').textContent,/apt missing/);
  h.setFetch(async()=>response({msg:'offline'},503));await h.run('loadCapabilities("A",serverVersion)');assert.match(h.element('#capabilities-banner').innerHTML,/重新检查/);assert.equal(h.element('#tools').querySelectorAll('[data-tool-action]').find(b=>b.dataset.toolAction==='check_env').disabled,false);
});
test('late capability replies cannot overwrite a newly selected server',async()=>{
  const h=harness(),late=deferred();h.run('cur='+JSON.stringify(server));h.setFetch(async()=>late.promise);const request=h.run('loadCapabilities("A",serverVersion)');h.run('cur={id:"B"};resetServerView()');late.resolve(response({os:'OLD',tools:{}}));await request;assert.ok(!h.element('#capabilities-banner').innerHTML.includes('OLD'));assert.equal(h.run('capabilityState'),null);
});
test('first-run guide can be skipped, persisted and reopened without exposing credentials',async()=>{
  const h=await productHarness({onboarding:{completed:false}});assert.equal(h.element('#product-guide-mask').classList.contains('show'),true);assert.match(h.element('#guide-title').textContent,/服务器/);
  await h.element('#guide-skip').click();const saved=h.requests.find(r=>r.url==='/api/product/onboarding');assert.deepEqual(JSON.parse(saved.options.body),{completed:true});assert.equal(h.element('#product-guide-mask').classList.contains('show'),false);
  h.run('window.ProductUI.openGuide()');h.element('#guide-next').click();assert.match(h.element('#guide-title').textContent,/阿里云/);h.element('#guide-next').click();assert.match(h.element('#guide-body').innerHTML,/Clash/);h.element('#guide-next').click();await h.element('#guide-next').click();assert.equal(h.element('#add-mask').classList.contains('show'),true);assert.equal(h.element('#a-pass').value,'');
});
test('unconfigured updates and releases without signature validation cannot download',async()=>{
  const h=await productHarness();assert.match(h.element('#product-settings').innerHTML,/尚未配置/);assert.equal(h.element('#product-download-update').disabled,true);
  h.setFetch(async()=>response({ok:true,updates:{enabled:true,state:'available',release:{version:'0.3.0',downloadable:false,notes:'<img src=x onerror=alert(1)>'}}}));
  await h.run('window.ProductUI.checkUpdate()');assert.equal(h.element('#product-download-update').disabled,true);assert.ok(!h.element('#product-settings').innerHTML.includes('<img'));const count=h.requests.length;await h.run('window.ProductUI.downloadUpdate()');assert.equal(h.requests.length,count);
});
test('validated update downloads carry CSRF and save a Blob without automatically launching it',async()=>{
  const h=await productHarness({updates:{enabled:true,state:'available',release:{version:'0.3.0',sha256:'a'.repeat(64),downloadable:true}}}),anchors=[],blobs=[];
  h.context.URL=class extends URL {static createObjectURL(blob){blobs.push(blob);return 'blob:validated-installer';}static revokeObjectURL(){}};
  const create=h.context.document.createElement;h.context.document.createElement=tag=>{const node=create(tag);if(tag==='a')node.click=()=>anchors.push({href:node.href,name:node.download});return node;};
  h.setFetch(async url=>url.endsWith('/download')?response({ok:true,filename:'../G-Network-Setup.exe'}):({ok:true,status:200,headers:new Headers(),blob:async()=>new Blob(['fake-installer'])}));
  await h.run('window.ProductUI.downloadUpdate()');assert.deepEqual(anchors,[{href:'blob:validated-installer',name:'G-Network-Setup.exe'}]);assert.equal(await blobs[0].text(),'fake-installer');const download=h.requests.find(r=>r.url.endsWith('/download'));assert.equal(download.options.headers.get('X-CSRF-Token'),'test-csrf-token');assert.deepEqual(JSON.parse(download.options.body),{version:'0.3.0',sha256:'a'.repeat(64)});
});
test('backup import requires a preview, explicit confirmation and an idle task queue',async()=>{
  const h=await productHarness();h.element('#product-import-backup').click();const file=h.element('#backup-file');file.files=[{size:20,text:async()=>JSON.stringify({format:'fake-backup'})}];await h.run('window.ProductUI.readBackup(document.getElementById("backup-file"))');await h.run('window.ProductUI.confirmBackup()');assert.ok(!h.requests.some(r=>r.url.endsWith('/import')));
  h.setFetch(async url=>url.endsWith('/preview')?response({ok:true,server_count:2,settings_count:0,encrypted:false,requires_credentials:true}):url==='/api/servers'?response([server]):url==='/api/nodes/protocols'?response({protocols:{},ss_methods:[]}):response({ok:true,imported:2,msg:'merged'}));
  await h.run('window.ProductUI.previewBackup()');assert.match(h.element('#backup-preview').innerHTML,/2 台/);assert.equal(h.element('#backup-confirm').disabled,false);
  h.run('globalThis.tasksActive=true');await h.run('window.ProductUI.confirmBackup()');assert.ok(!h.requests.some(r=>r.url.endsWith('/import')));h.run('globalThis.tasksActive=false');h.context.confirm=()=>false;await h.run('window.ProductUI.confirmBackup()');assert.ok(!h.requests.some(r=>r.url.endsWith('/import')));h.context.confirm=()=>true;
  h.element('#backup-passphrase').value='backup-passphrase';await h.run('window.ProductUI.confirmBackup()');const imported=h.requests.find(r=>r.url.endsWith('/import'));assert.equal(JSON.parse(imported.options.body).mode,'merge');assert.equal(h.element('#backup-passphrase').value,'');assert.equal(h.element('#product-backup-mask').classList.contains('show'),false);
});
test('backup changes and modal cancellation invalidate pending previews and erase the passphrase',async()=>{
  const h=await productHarness();h.element('#product-import-backup').click();const file=h.element('#backup-file');file.files=[{size:20,text:async()=>'{"format":"first"}'}];await h.run('window.ProductUI.readBackup(document.getElementById("backup-file"))');
  const late=deferred();h.setFetch(async()=>late.promise);const preview=h.run('window.ProductUI.previewBackup()');h.element('#backup-passphrase').value='different';h.element('#backup-passphrase').oninput();late.resolve(response({ok:true,server_count:9}));await preview;assert.equal(h.element('#backup-confirm').disabled,true);assert.ok(!h.element('#backup-preview').innerHTML.includes('9 台'));
  h.run('closeModal("#product-backup-mask")');assert.equal(h.element('#backup-passphrase').value,'');h.element('#product-import-backup').click();await h.run('window.ProductUI.previewBackup()');assert.match(h.element('#toast').textContent,/先选择/);
});
test('encrypted export verifies matching passphrases and clears inputs after success',async()=>{
  const h=await productHarness();h.element('#product-export-encrypted').click();h.element('#backup-passphrase').value='short';await h.run('window.ProductUI.confirmBackup()');assert.ok(!h.requests.some(r=>r.url.endsWith('/export')));
  h.element('#backup-passphrase').value='long-passphrase-value';h.element('#backup-repeat').value='different';await h.run('window.ProductUI.confirmBackup()');assert.ok(!h.requests.some(r=>r.url.endsWith('/export')));h.element('#backup-repeat').value='long-passphrase-value';
  h.setFetch(async()=>response({ok:true,filename:'encrypted.json',backup:{encrypted:true,ciphertext:'opaque'}}));await h.run('window.ProductUI.confirmBackup()');assert.deepEqual(JSON.parse(h.requests.find(r=>r.url.endsWith('/export')).options.body),{mode:'encrypted',passphrase:'long-passphrase-value'});assert.equal(h.element('#backup-passphrase').value,'');assert.equal(h.element('#backup-repeat').value,'');
});
test('SSH host trust requires full fingerprint confirmation and sends no authentication before consent',async()=>{
  const h=await productHarness(),fingerprint='SHA256:ABCDEFGHIJKLMNOPQRSTUVWXYZabc0123456789+/';h.setFetch(async(url,options)=>response(options.method==='GET'||!options.method?{ok:true,known:false,changed:false,host:'ecs.example',port:22,algorithm:'ssh-ed25519',fingerprint}:{ok:true}));
  const trust=h.run('window.ProductUI.ensureServerIdentity("A")');await immediate();assert.equal(h.element('#identity-fingerprint').textContent,fingerprint);assert.equal(h.element('#identity-trust').disabled,true);h.element('#identity-trust').click();assert.ok(!h.requests.some(r=>r.options.method==='POST'));
  h.element('#identity-verified').checked=true;h.element('#identity-verified').onchange();await h.element('#identity-trust').click();await trust;const posted=h.requests.find(r=>r.options.method==='POST');assert.deepEqual(JSON.parse(posted.options.body),{fingerprint});assert.ok(!h.requests.some(r=>r.url.endsWith('/test')));
});
test('changed SSH fingerprints are blocked and cancel leaves the connection untrusted',async()=>{
  const h=await productHarness();h.setFetch(async()=>response({ok:true,known:true,changed:true,fingerprint:'SHA256:abc'}));await assert.rejects(h.run('window.ProductUI.ensureServerIdentity("A")'),/指纹已变化/);assert.ok(!h.requests.some(r=>r.options.method==='POST'));
  h.setFetch(async()=>response({ok:true,known:false,changed:false,fingerprint:'SHA256:abc'}));const trust=h.run('window.ProductUI.ensureServerIdentity("A")'),rejected=assert.rejects(trust,error=>error.code==='IDENTITY_PENDING');await immediate();h.run('closeModal("#product-identity-mask")');await rejected;assert.ok(!h.requests.some(r=>r.options.method==='POST'));
});
(async()=>{for(const {name,fn}of tests){await fn();console.log('PASS '+name);}console.log(tests.length+' product frontend regression checks passed');})().catch(error=>{console.error(error);process.exitCode=1;});
