'use strict';
// All endpoints, identities, nodes and DOM objects are fake. No service or SSH is started.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const operations=require('../static/clash-workspace.js');
const fixtureFile=path.join(__dirname,'test_frontend.js');
const fixtureSource=fs.readFileSync(fixtureFile,'utf8').split('const tests=[];')[0];
const fixture=vm.createContext({require,__dirname,console,setImmediate,Headers,URL,Blob});
vm.runInContext(fixtureSource+'\nglobalThis.fixtures={harness,response,deferred,immediate};',fixture);
const {harness,response,deferred,immediate}=fixture.fixtures;
const source=fs.readFileSync(path.join(__dirname,'../static/clash-workspace.js'),'utf8');
new vm.Script(source,{filename:'clash-workspace.js'});
const servers=[{id:'A',name:'North',host:'a.invalid',port:22,user:'root'},{id:'B',name:'West',host:'b.invalid',port:2222,user:'root'}];
const nodes=[{id:'nA',server_id:'A',server_name:'North',host:'a.invalid',name:'同名,节点',protocol:'vmess',port:443,available:true,compatibility:'classic'},{id:'nB',server_id:'B',server_name:'West',host:'b.invalid',name:'同名,节点',protocol:'vless',port:8443,available:true,compatibility:'mihomo'},{id:'nRelay',server_id:'B',server_name:'West',host:'b.invalid',name:'转发入口',protocol:'dokodemo-door',port:9000,available:false,notice:'不提供客户端节点'}];
const catalog=(values=nodes)=>({ok:true,snapshot_id:'snapshot-test',nodes:values,servers:servers.map(s=>({id:s.id,name:s.name,status:'ok',msg:'读取完成'}))});
const token='AbCd_efgh-IjklmnopQRSTuvwxyz0123456789ABcde';
const config=(overrides={})=>({available:true,yaml:'proxies:\n  - name: 测试节点\nproxy-groups: []\nrules: []\n',url:'http://127.0.0.1:8620/api/clash-export/'+token+'.yaml',filename:'G-Network.yaml',compatibility:'mihomo',notice:'最长 24 小时；同机导入需程序在线。',...overrides});
function modelWithNodes(){const m=operations.createModel();m.servers=servers;m.sourceIds=new Set(['A','B']);operations.acceptCatalog(m,catalog());return m;}
function ui(){
  const h=harness();h.context.window.document=h.context.document;h.context.window.navigator=h.context.navigator;h.context.window.confirm=()=>true;
  h.element('#clash-workspace').contains=()=>true;h.element('meta[name="fl-loopback-port"]').content='8620';
  h.run('fleet='+JSON.stringify(servers));h.run(source);
  h.run('globalThis.verified=[];window.ClashWorkspace.init({api,jsonPost,toast,getServers:()=>fleet,normalizeConfig:clashConfig,ensureIdentity:async id=>{verified.push(id)}})');
  h.click=(id,data={})=>{const button=h.element('#'+id);button.dataset={...button.dataset,...data};return h.element('#clash-workspace').listeners.click({target:{closest:()=>button}});};
  h.change=input=>h.element('#clash-workspace').listeners.change({target:input});
  return h;
}
async function loaded(){const h=ui();h.setFetch(async url=>{assert.equal(url,'/api/clash-workspace/read');return response(catalog());});await h.click('cw-read');return h;}
const tests=[];function test(name,fn){tests.push({name,fn});}

test('cross-server selection creates one draft with stable node IDs even when names contain commas or repeat',()=>{
  const m=modelWithNodes(),draft=operations.exportDraft(m);
  assert.deepEqual(draft.node_ids,['nA','nB']);assert.equal(draft.snapshot_id,'snapshot-test');
  assert.equal(draft.profile.groups.length,3);assert.ok(draft.profile.groups.every(g=>g.members.includes('nA')&&g.members.includes('nB')));
  assert.equal(draft.profile.mode,'rule');assert.equal(draft.profile.template,'custom');assert.equal(draft.profile.fallback,'节点选择');assert.ok(!('allow_lan' in draft.profile));
  assert.equal(draft.profile.rules.at(-1).type,'MATCH');assert.equal(draft.profile.rules.at(-1).target,'节点选择');
  m.rules.splice(0,0,{id:'directnode',type:'DOMAIN',value:'example.invalid',target:'node:nB'});assert.equal(operations.exportDraft(m).profile.rules[0].target,'nB');
});
test('group references use the same trimmed names as the exported group declarations',()=>{
  const m=modelWithNodes();m.groups[0].name='  节点选择  ';m.groups[1].name='  自动选择  ';
  const draft=operations.exportDraft(m).profile;assert.equal(draft.groups[0].name,'节点选择');assert.ok(draft.groups[0].members.includes('自动选择'));assert.equal(draft.fallback,'节点选择');assert.equal(draft.rules.at(-1).target,'节点选择');
});
test('invalid catalog sources, duplicate IDs and absent snapshots are rejected',()=>{
  for(const data of [{nodes},catalog([...nodes,{...nodes[0]}]),catalog([{...nodes[0],server_id:'unknown'}]),catalog(Array.from({length:257},(_,i)=>({...nodes[0],id:'node'+i})))]){
    const m=operations.createModel();m.sourceIds=new Set(['A','B']);assert.throws(()=>operations.acceptCatalog(m,data),/读取|来源|身份/);
  }
});
test('inventory may contain 256 entries but automatic selection and export are limited to 128',()=>{
  const m=operations.createModel();m.sourceIds=new Set(['A']);operations.acceptCatalog(m,catalog(Array.from({length:256},(_,i)=>({...nodes[0],id:'node'+i}))));
  assert.equal(m.nodes.length,256);assert.equal(m.selected.size,128);assert.equal(operations.exportDraft(m).node_ids.length,128);
  m.selected.add('node200');operations.syncMembers(m);assert.match(operations.validate(m).join(' '),/128/);
});
test('removing selected nodes clears only node membership and keeps valid group references',()=>{
  const m=modelWithNodes();m.selected.delete('nA');operations.syncMembers(m);assert.ok(m.groups.every(g=>!g.members.includes('node:nA')));assert.ok(m.groups[0].members.includes('group:g2'));
  assert.deepEqual(operations.exportDraft(m).node_ids,['nB']);m.selected.clear();operations.syncMembers(m);assert.match(operations.validate(m).join(' '),/至少选择|至少需要/);
});
test('strategy cycles, reserved names, duplicate groups and insecure test URLs cannot be exported',()=>{
  const cycle=modelWithNodes();cycle.groups[1].members.push('group:g1');assert.throws(()=>operations.exportDraft(cycle),/循环/);
  for(const name of ['DIRECT','节点选择','bad\nname','bad,name']){const m=modelWithNodes();m.groups[1].name=name;assert.ok(operations.validate(m).length);}
  for(const url of ['javascript:alert(1)','https://user:pass@example.invalid/','https://example.invalid/#fragment']){const m=modelWithNodes();m.groups[1].url=url;assert.match(operations.validate(m).join(' '),/HTTPS/);}
  const http=modelWithNodes();http.groups[1].url='http://example.invalid/generate_204';assert.deepEqual(operations.validate(http),[]);
});
test('rules reorder with keyboard controls while a unique MATCH remains last',()=>{
  const m=modelWithNodes();assert.equal(operations.moveRule(m,'r1',1),true);assert.equal(m.rules[0].id,'r2');assert.equal(operations.moveRule(m,'r3',1),false);assert.equal(operations.moveRule(m,'r4',-1),false);assert.equal(m.rules.at(-1).type,'MATCH');
  m.rules.push({...m.rules.at(-1),id:'bad'});assert.match(operations.validate(m).join(' '),/唯一/);
});
test('extended route types, no-resolve, tolerance and load-balance strategy map to backend fields',()=>{
  const m=modelWithNodes();m.groups[1].tolerance=80;m.groups[2].type='load-balance';m.groups[2].strategy='round-robin';
  m.rules.splice(0,0,{id:'ipv6',type:'IP-CIDR6',value:'::1/128',target:'DIRECT',no_resolve:false},{id:'src',type:'SRC-IP-CIDR',value:'192.168.1.0/24',target:'DIRECT'},{id:'port',type:'DST-PORT',value:'443',target:'group:g1'});
  const p=operations.exportDraft(m).profile;assert.equal(p.groups[1].tolerance,80);assert.equal(p.groups[2].strategy,'round-robin');assert.equal(p.rules[0].no_resolve,false);assert.equal(p.rules[1].no_resolve,true);assert.equal(p.rules[2].type,'DST-PORT');
  m.groups[1].tolerance='';assert.ok(!('tolerance' in operations.exportDraft(m).profile.groups[1]));
});
test('route templates replace only routing, preserve the current fallback and invalidate previous output',()=>{
  for(const [template,count] of [['lan',5],['cn',6],['global',1]]){const m=modelWithNodes(),groups=JSON.stringify(m.groups);m.rules.at(-1).target='group:g3';m.output=config();m.outputRevision=m.revision;operations.applyTemplate(m,template);assert.equal(m.rules.length,count);assert.equal(m.rules.at(-1).type,'MATCH');assert.equal(m.rules.at(-1).target,'group:g3');assert.equal(JSON.stringify(m.groups),groups);assert.equal(operations.currentOutput(m),null);assert.equal(operations.exportDraft(m).profile.fallback,'故障转移');if(template==='cn')assert.ok(m.rules.some(r=>r.type==='GEOIP'&&r.value==='CN'&&r.no_resolve===false));}
  assert.throws(()=>operations.applyTemplate(modelWithNodes(),'unknown'),/不支持/);
});
test('the route template controls change the exported rules without mutating selected nodes',async()=>{
  const h=await loaded();await h.click('apply-global',{cwTemplate:'global'});assert.equal(h.element('#cw-rule-count').textContent,'1');assert.equal(h.element('#cw-step-nodes').textContent,'2 个');h.setFetch(async()=>response({ok:true,clash:config()}));await h.click('cw-generate');assert.deepEqual(JSON.parse(h.requests.at(-1).options.body).profile.rules,[{type:'MATCH',value:'',target:'节点选择'}]);
  await h.click('apply-cn',{cwTemplate:'cn'});assert.equal(h.element('#cw-rule-count').textContent,'6');assert.match(h.element('#cw-output').innerHTML,/待更新/);
});
test('edits invalidate generated output and prevent exporting a stale draft',()=>{
  const m=modelWithNodes();m.output=config();m.outputRevision=m.revision;assert.equal(operations.currentOutput(m),m.output);operations.touch(m);assert.equal(operations.currentOutput(m),null);
});
test('read verifies each saved target before the one CSRF-protected aggregate request',async()=>{
  const h=await loaded();assert.deepEqual(Array.from(h.run('verified')),['A','B']);assert.equal(h.requests.length,1);
  assert.equal(h.requests[0].options.headers.get('X-CSRF-Token'),'test-csrf-token');assert.deepEqual(JSON.parse(h.requests[0].options.body),{server_ids:['A','B']});
  assert.equal(h.element('#cw-step-nodes').textContent,'2 个');assert.equal(h.element('#cw-generate').disabled,false);assert.match(h.element('#cw-nodes').innerHTML,/转发入口/);assert.match(h.element('#cw-nodes').innerHTML,/disabled/);
});
test('source changes discard late catalog responses and cannot export the previous target',async()=>{
  const h=ui(),late=deferred();h.setFetch(async()=>late.promise);const pending=h.click('cw-read');await immediate();h.change({dataset:{cwSource:'B'},checked:false});late.resolve(response(catalog()));await pending;
  assert.equal(h.element('#cw-step-nodes').textContent,'0 个');assert.equal(h.element('#cw-generate').disabled,true);assert.ok(!h.element('#cw-nodes').innerHTML.includes('同名'));
});
test('late generation after a draft edit is discarded and failed generation remains visible',async()=>{
  const h=await loaded(),late=deferred();h.setFetch(async()=>late.promise);const pending=h.click('cw-generate');await immediate();h.change({id:'cw-profile-name',dataset:{},value:'Changed'});late.resolve(response({ok:true,clash:config()}));await pending;assert.ok(!h.element('#cw-output').innerHTML.includes('完整配置已生成'));
  h.setFetch(async()=>response({ok:false,msg:'快照已过期，请重新读取'},400));await h.click('cw-generate');assert.match(h.element('#cw-validation').textContent,/快照已过期/);
});
test('generated configuration uses inline YAML, validated URL, and never auto launches a client',async()=>{
  const h=await loaded();let opened=0;h.context.window.open=()=>opened++;h.setFetch(async()=>response({ok:true,clash:config({import_url:'clash://evil'}),warnings:['版本请核对']}));await h.click('cw-generate');
  const request=JSON.parse(h.requests.at(-1).options.body);assert.deepEqual(request.node_ids,['nA','nB']);assert.equal(request.profile.groups.length,3);assert.equal(request.profile.rules.at(-1).type,'MATCH');
  await h.click('copy-import',{cwExport:'import'});assert.equal(h.context.copied,'clash://install-config?url='+encodeURIComponent(config().url));assert.equal(opened,0);
  await h.click('copy-yaml',{cwExport:'yaml'});assert.equal(h.context.copied,config().yaml);assert.ok(!h.element('#cw-output').innerHTML.includes('clash://evil'));
  const requests=h.requests.length;h.change({dataset:{cwNode:'nA'},checked:false});h.context.copied=undefined;await h.click('copy-yaml',{cwExport:'yaml'});assert.equal(h.context.copied,undefined);assert.equal(h.requests.length,requests);
});
test('export preview and sources escape untrusted labels, warnings and YAML',async()=>{
  const danger='</textarea><img src=x onerror="alert(1)"><script>bad</script>',h=ui();h.run('window.ClashWorkspace.setServers('+JSON.stringify([{...servers[0],name:danger}])+')');assert.ok(!h.element('#cw-sources').innerHTML.includes('<img'));
  h.setFetch(async()=>response(catalog([{...nodes[0],name:danger,notice:danger}])));await h.click('cw-read');assert.ok(!h.element('#cw-nodes').innerHTML.includes('<img'));
  h.setFetch(async()=>response({ok:true,clash:config({yaml:danger,notice:danger,url:'https://untrusted.invalid/'}),warnings:[danger]}));await h.click('cw-generate');const html=h.element('#cw-output').innerHTML;assert.ok(!html.includes('<img'));assert.ok(!html.includes('<script>'));assert.match(html,/&lt;\/textarea&gt;/);assert.ok(!html.includes('https://untrusted.invalid/'));
});
test('UTF-8 download removes the temporary anchor and revokes its Blob URL without fetching it',async()=>{
  const h=await loaded(),created=[],revoked=[],downloads=[];h.context.URL=class extends URL{static createObjectURL(blob){created.push(blob);return 'blob:workspace';}static revokeObjectURL(url){revoked.push(url);}};
  const original=h.context.document.createElement;h.context.document.createElement=tag=>{const node=original(tag);if(tag==='a'){node.click=()=>downloads.push({href:node.href,filename:node.download});node.remove=()=>{h.context.document.body.children=h.context.document.body.children.filter(n=>n!==node);};}return node;};
  h.setFetch(async()=>response({ok:true,clash:config()}));await h.click('cw-generate');const requests=h.requests.length;await h.click('download',{cwExport:'download'});assert.equal(await created[0].text(),config().yaml);assert.match(created[0].type,/charset=utf-8/);assert.deepEqual(downloads,[{href:'blob:workspace',filename:'G-Network.yaml'}]);assert.equal(h.context.document.body.children.length,0);assert.equal(h.requests.length,requests);await h.timer(1000);assert.deepEqual(revoked,['blob:workspace']);
});
test('saved-server identity edits revoke the inventory and output while changing selected dashboard target does not',async()=>{
  const h=await loaded();h.setFetch(async()=>response({ok:true,clash:config()}));await h.click('cw-generate');h.run('cur=fleet[1]');h.run('window.ClashWorkspace.activate()');assert.match(h.element('#cw-output').innerHTML,/完整配置已生成/);
  h.run('fleet[0]={...fleet[0],host:"changed.invalid"};window.ClashWorkspace.setServers(fleet)');assert.equal(h.element('#cw-step-nodes').textContent,'0 个');assert.equal(h.element('#cw-generate').disabled,true);assert.ok(!h.element('#cw-output').innerHTML.includes('完整配置已生成'));
});

(async()=>{let passed=0;for(const {name,fn} of tests){try{await fn();console.log('PASS '+name);passed++;}catch(e){console.error('FAIL '+name);console.error(e.stack);process.exitCode=1;}}console.log(passed+'/'+tests.length+' Clash workspace checks passed');})();
