'use strict';
// Offline behavior checks. Reuse the existing DOM/API fixture without running its test cases.
// No local service, real configuration, SSH connection, or client application is used.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const fixtureFile=path.join(__dirname,'test_frontend.js');
const fixtureSource=fs.readFileSync(fixtureFile,'utf8').split('const tests=[];')[0];
assert.ok(fixtureSource.includes('function harness()'),'Shared offline harness must exist');
const fixture=vm.createContext({require,__dirname,console,setImmediate,Headers,URL,Blob});
vm.runInContext(fixtureSource+'\nglobalThis.clashFixtures={harness,response,deferred,immediate};',fixture,{filename:fixtureFile});
const {harness,response,deferred,immediate}=fixture.clashFixtures;
const token='AbCd_efgh-IjklmnopQRSTuvwxyz0123456789ABcde';
assert.equal(token.length,43);
const url='http://127.0.0.1:8620/api/clash-export/'+token+'.yaml';
const config=(overrides={})=>({available:true,yaml:'proxies:\n  - name: 测试节点\n    type: vmess\n',url,import_url:'clash://evil?url=https://bad.example/',filename:'fl-测试.yaml',compatibility:'classic',notice:'本机链接需程序在线。\n链接有效期 24 小时。',...overrides});
function setup(){const h=harness();h.element('meta[name="fl-loopback-port"]').content='8620';return h;}
function actionButton(h,selector,action){return h.element(selector).querySelectorAll('[data-clash-action]').find(b=>b.dataset.clashAction===action);}
const tests=[];
function test(name,fn){tests.push({name,fn});}

test('HTTP export links require the configured current panel port and exact high-entropy path',()=>{
  const h=setup();assert.equal(h.run('validatedClashURL('+JSON.stringify(url)+')'),url);
  const invalid=[
    url.replace('127.0.0.1','bad.example'),url.replace('127.0.0.1','127.0.0.2'),url.replace('127.0.0.1','localhost'),
    url.replace('http:','https:'),url.replace(':8620',':8621'),url.replace('/clash-export/','/file/'),
    url.replace(token,'short'),url.replace(token,token+'x'),url.replace('.yaml','.yml'),
    url+'?x=1',url+'#data',url.replace('127.0.0.1','user:secret@127.0.0.1'),url+' ',
    'javascript:alert(1)','clash://install-config?url='+encodeURIComponent(url),
    url.replace('127.0.0.1','127.0.0.1.bad.example'),url.replace(token,'%2e%2e'),
  ];
  for(const value of invalid)assert.equal(h.run('validatedClashURL('+JSON.stringify(value)+')'),null);
  h.element('meta[name="fl-loopback-port"]').content='8621';assert.equal(h.run('validatedClashURL('+JSON.stringify(url)+')'),null);
  h.element('meta[name="fl-loopback-port"]').content='';assert.equal(h.run('validatedClashURL('+JSON.stringify(url)+')'),null);
  h.element('meta[name="fl-loopback-port"]').content='8620';h.context.location.host='127.0.0.1:8622';assert.equal(h.run('validatedClashURL('+JSON.stringify(url)+')'),null);
});
test('configuration normalization retains YAML when the URL is rejected and uses a safe filename',()=>{
  const h=setup();
  for(const value of [null,{},config({available:false}),config({compatibility:'unsupported'}),config({yaml:''})])assert.equal(h.run('clashConfig('+JSON.stringify(value)+').available'),false);
  const c=h.run('clashConfig('+JSON.stringify(config({url:'https://bad.example/api/config',filename:'../../.hidden.yaml'}))+')');
  assert.equal(c.available,true);assert.equal(c.url,null);assert.equal(c.filename,'fl-network.yaml');
  assert.equal(h.run('clashConfig('+JSON.stringify(config({filename:'dir/合法配置.yaml'}))+').filename'),'合法配置.yaml');
});
test('deployment cards escape notice and YAML, retain sharing links and QR codes, and show no launch URL',()=>{
  const h=setup(),danger='</textarea><img src=x onerror="alert(1)"><script>unsafe</script>',qr=[];
  h.context.QRCode=class{constructor(el,options){qr.push(options.text);}};
  h.run('showNodeResult('+JSON.stringify({server:danger,params:{remark:danger},links:['vmess://share'],clash:config({notice:danger,yaml:danger})})+')');
  const html=h.element('#node-result').innerHTML;
  assert.ok(html.includes('Clash / Mihomo 配置'));assert.ok(html.includes('V2Ray 客户端导入'));assert.ok(html.includes('&lt;/textarea&gt;&lt;img'));
  assert.ok(!html.includes('<img'));assert.ok(!html.includes('<script>'));assert.ok(!html.includes('clash://evil'));
  assert.deepEqual(qr,['vmess://share']);assert.ok(h.element('#node-result').querySelectorAll('[data-copy-node]').length===1);
  h.run('showNodeResult('+JSON.stringify({server:'A',links:['vmess://share'],clash:{available:false,notice:danger}})+')');
  assert.equal(h.element('#node-result').querySelectorAll('[data-clash-action]').length,0);assert.ok(h.element('#node-result').innerHTML.includes('&lt;img'));
});
test('copy actions use validated HTTP URLs and inline YAML; scheme is constructed without name or launching apps',async()=>{
  const h=setup();let opened=0;h.context.window.open=()=>opened++;
  h.run('showNodeResult('+JSON.stringify({server:'A',links:['vmess://share'],clash:config()})+')');
  for(const [action,expected] of [['url',url],['yaml',config().yaml],['import','clash://install-config?url='+encodeURIComponent(url)]]){
    await actionButton(h,'#node-result',action).click();assert.equal(h.context.copied,expected);
  }
  assert.equal(opened,0);assert.equal(h.requests.length,0);assert.ok(!h.context.copied.includes('&name='));
});
test('YAML download saves UTF-8 inline data, removes the anchor, and revokes its Blob URL',async()=>{
  const h=setup(),created=[],revoked=[],links=[];let removed=0;
  h.context.URL=class extends URL {static createObjectURL(blob){created.push(blob);return 'blob:clash-'+created.length;}static revokeObjectURL(value){revoked.push(value);}};
  const create=h.context.document.createElement;
  h.context.document.createElement=tag=>{const el=create(tag);if(tag==='a'){el.click=()=>links.push({href:el.href,download:el.download});el.remove=()=>{removed++;h.context.document.body.children=h.context.document.body.children.filter(x=>x!==el);};}return el;};
  h.run('showNodeResult('+JSON.stringify({server:'A',clash:config(),links:[]})+')');
  await actionButton(h,'#node-result','download').click();
  assert.equal(created.length,1);assert.equal(await created[0].text(),config().yaml);assert.match(created[0].type,/yaml.*charset=utf-8/);
  assert.deepEqual(links,[{href:'blob:clash-1',download:'fl-测试.yaml'}]);assert.equal(removed,1);assert.equal(h.context.document.body.children.length,0);assert.equal(revoked.length,0);assert.equal(h.requests.length,0);
  await h.timer(1000);assert.deepEqual(revoked,['blob:clash-1']);assert.equal(h.run('clashBlobUrls.size'),0);
  await actionButton(h,'#node-result','download').click();h.events.beforeunload();assert.equal(revoked.at(-1),'blob:clash-2');assert.equal(h.run('clashBlobUrls.size'),0);
});
test('list export and original share actions bind their snapshot and reject saved callbacks after target changes',async()=>{
  const h=setup();
  h.setFetch(async()=>response({ok:true,host:h.element('#nl-server').value,inbounds:[{kind:'VMess',port:443,tag:'node',link:'vmess://'+h.element('#nl-server').value,clash:config({yaml:'target: '+h.element('#nl-server').value})}]}));
  await h.run('loadNodeList()');const staleClash=actionButton(h,'#nl-body','yaml').onclick,staleShare=h.element('#nl-body').querySelectorAll('[data-copy-list]')[0].onclick;
  h.element('#nl-server').value='B';h.run("nodeSrvSel('#nl-server','#nl-man')");
  await staleClash();await staleShare();assert.equal(h.context.copied,undefined);assert.equal(h.element('#nl-body').innerHTML,'');
  await h.run('loadNodeList()');await staleClash();await staleShare();assert.equal(h.context.copied,undefined);
  await actionButton(h,'#nl-body','yaml').click();assert.equal(h.context.copied,'target: B');
  await h.element('#nl-body').querySelectorAll('[data-copy-list]')[0].click();assert.equal(h.context.copied,'vmess://B');
});
test('manual credentials and late responses invalidate list export snapshots',async()=>{
  const h=setup();h.element('#nl-server').value='__manual__';h.element('#nlm-host').value='first';h.element('#nlm-pass').value='password';
  h.setFetch(async()=>response({ok:true,inbounds:[{kind:'VMess',tag:'node',port:443,clash:config()}]}));
  await h.run('loadNodeList()');const stale=actionButton(h,'#nl-body','url').onclick;
  h.element('#nlm-host').value='second';h.element('#nlm-host').listeners.input();await stale();assert.equal(h.context.copied,undefined);
  const pending=deferred();h.setFetch(async()=>pending.promise);const read=h.run('loadNodeList()');await immediate();h.element('#nlm-host').value='third';h.element('#nlm-host').listeners.input();
  pending.resolve(response({ok:true,inbounds:[{kind:'VMess',tag:'late',port:443,clash:config()}]}));await read;
  assert.equal(h.element('#nl-body').innerHTML,'');assert.equal(h.run('nodeListSnapshot'),null);
});
test('replaced deployment results refuse previous export and share callbacks',async()=>{
  const h=setup();h.run('showNodeResult('+JSON.stringify({server:'A',links:['vmess://A'],clash:config()})+')');
  const exportOld=actionButton(h,'#node-result','url').onclick,shareOld=h.element('#node-result').querySelectorAll('[data-copy-node]')[0].onclick;
  h.run('showNodeResult('+JSON.stringify({server:'B',links:['vmess://B'],clash:config({yaml:'target: B'})})+')');
  await exportOld();await shareOld();assert.equal(h.context.copied,undefined);
  await actionButton(h,'#node-result','yaml').click();assert.equal(h.context.copied,'target: B');
});
test('an untrusted export URL is never displayed or copied, while YAML remains available',()=>{
  const h=setup(),unsafe='https://bad.example/<img>';
  h.run('showNodeResult('+JSON.stringify({server:'A',links:[],clash:config({url:unsafe})})+')');
  assert.equal(actionButton(h,'#node-result','url'),undefined);assert.equal(actionButton(h,'#node-result','import'),undefined);
  assert.ok(actionButton(h,'#node-result','download'));assert.ok(actionButton(h,'#node-result','yaml'));assert.ok(!h.element('#node-result').innerHTML.includes(unsafe));
});
test('protocol guidance distinguishes Reality version compatibility and ordinary versus SS2022 ciphers',()=>{
  const h=setup();h.element('#n-proto').value='vless-reality';h.run('nodeProto()');assert.match(h.element('#n-clash-compat').textContent,/核对 Mihomo 与 Xray 版本/);assert.match(h.element('#n-clash-compat').textContent,/旧版 Clash 不支持/);
  h.element('#n-proto').value='vmess-ws';h.run('nodeProto()');assert.match(h.element('#n-clash-compat').textContent,/兼容较广/);
  h.element('#n-proto').value='shadowsocks';h.element('#n-ssmethod').value='2022-blake3-aes-128-gcm';h.run('nodeProto()');assert.match(h.element('#n-clash-compat').textContent,/SS2022 需要/);
  h.element('#n-ssmethod').value='aes-128-gcm';h.run('nodeProto()');assert.match(h.element('#n-clash-compat').textContent,/非 SS2022/);
});
(async()=>{for(const {name,fn} of tests){await fn();console.log('PASS '+name);}console.log(`${tests.length} Clash frontend regression checks passed`);})().catch(error=>{console.error(error);process.exitCode=1;});
