'use strict';
// Domain policies, nodes, servers and responses are all synthetic. No SSH or real client runs.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const operations=require('../static/clash-workspace.js');
const fixtureFile=path.join(__dirname,'test_frontend.js');
const fixtureSource=fs.readFileSync(fixtureFile,'utf8').split('const tests=[];')[0];
const fixture=vm.createContext({require,__dirname,console,setImmediate,Headers,URL,Blob});
vm.runInContext(fixtureSource+'\nglobalThis.fixtures={harness,response,deferred,immediate};',fixture);
const {harness,response,deferred,immediate}=fixture.fixtures;
const source=fs.readFileSync(path.join(__dirname,'../static/clash-workspace.js'),'utf8');
const servers=[{id:'A',name:'North',host:'a.invalid',port:22,user:'root'},{id:'B',name:'West',host:'b.invalid',port:2222,user:'root'}];
const nodes=[{id:'nA',server_id:'A',server_name:'North',host:'a.invalid',name:'同名节点',protocol:'vmess',port:443,available:true,compatibility:'classic',routing:{enabled:true,direct_domains:['a.example'],revision:1}},{id:'nB',server_id:'B',server_name:'West',host:'b.invalid',name:'同名节点',protocol:'vless',port:8443,available:true,compatibility:'mihomo',routing:{enabled:true,direct_domains:['b.example'],revision:5}}];
const catalog=(values=nodes)=>({ok:true,snapshot_id:'snapshot-test',nodes:values,servers:servers.map(s=>({id:s.id,name:s.name,status:'ok'}))});
const token='AbCd_efgh-IjklmnopQRSTuvwxyz0123456789ABcde';
const clash=(overrides={})=>({available:true,yaml:'proxies:\n  - name: test\nrules:\n  - DOMAIN-SUFFIX,a.example,DIRECT\n  - MATCH,test\n',url:'http://127.0.0.1:8620/api/clash-export/'+token+'.yaml',filename:'G-Network-node.yaml',compatibility:'mihomo',notice:'规则模式生效。',...overrides});
const xray=(overrides={})=>({available:true,json:'{"outbounds":[{"tag":"proxy","protocol":"vless"}]}',filename:'G-Network-node.json',notice:'完整 JSON。',...overrides});
const exportResult=(routing,overrides={})=>({ok:true,routing,clash:clash(),xray:xray(),warnings:[],...overrides});
function modelWithNodes(){const m=operations.createModel();m.sourceIds=new Set(['A','B']);operations.acceptCatalog(m,catalog());return m;}
function ui(){
  const h=harness();h.context.window.document=h.context.document;h.context.window.navigator=h.context.navigator;
  h.element('#clash-workspace').contains=()=>true;h.element('meta[name="fl-loopback-port"]').content='8620';
  h.run('fleet='+JSON.stringify(servers));h.run(source);
  h.run('globalThis.verified=[];window.ClashWorkspace.init({api,jsonPost,toast,getServers:()=>fleet,normalizeConfig:clashConfig,ensureIdentity:async id=>{verified.push(id)}})');
  h.click=(id,data={})=>{const button=h.element('#'+id);button.dataset={...button.dataset,...data};return h.element('#clash-workspace').listeners.click({target:{closest:()=>button}});};
  h.change=input=>h.element('#clash-workspace').listeners.change({target:input});
  h.input=value=>{h.element('#cw-routing-domain-input').value=value;return h.element('#clash-workspace').listeners.input({target:{id:'cw-routing-domain-input',value,dataset:{}}});};
  h.route=id=>h.click('route-'+id,{cwRouteNode:id});
  return h;
}
async function loaded(values=nodes){const h=ui();h.setFetch(async()=>response(catalog(values)));await h.click('cw-read');h.requests.length=0;return h;}
function apiStore(h){
  const saved=new Map(nodes.map(n=>[n.id,structuredClone(n.routing)]));
  h.setFetch(async(url,options)=>{const data=JSON.parse(options.body);if(url==='/api/node-routing/save'){const previous=saved.get(data.node_id);assert.equal(data.expected_revision,previous.revision);const routing={enabled:data.enabled,direct_domains:data.direct_domains,revision:previous.revision+1};saved.set(data.node_id,routing);return response({ok:true,routing});}if(url==='/api/node-routing/export')return response(exportResult(saved.get(data.node_id)));if(url==='/api/clash-workspace/export')return response({ok:true,clash:clash()});throw new Error('Unexpected request '+url);});return saved;
}
const tests=[];function test(name,fn){tests.push({name,fn});}

test('domain batches normalize IDN, lowercase and a final dot, preserve order and deduplicate',()=>{
  const result=operations.parseDomainBatch('Example.COM.，例子.测试\nexample.com;second.example',['kept.example']);
  assert.deepEqual(result.domains,['kept.example','example.com','xn--fsqu00a.xn--0zwm56d','second.example']);assert.equal(result.duplicates,1);assert.deepEqual(result.errors,[]);
});
test('URL, IP, wildcard, invalid labels and excessive lists are rejected without partially adding domains',()=>{
  for(const value of ['https://example.com/path','*.example.com','192.168.1.1','localhost','-bad.example','bad-.example','bad..example','example.com:443','example.com?token=secret','example.com/@x','a'.repeat(64)+'.example','example.com..','a.example\u0000'])assert.throws(()=>operations.normalizeDomain(value),/域名|IP|标签/);
  const result=operations.parseDomainBatch('good.example,https://bad.example',['kept.example']);assert.deepEqual(result.domains,['kept.example']);assert.equal(result.errors.length,1);
  assert.match(operations.parseDomainBatch(Array.from({length:129},(_,i)=>'host'+i+'.example').join('\n')).errors[0],/128/);
});
test('same-named nodes keep independent drafts, dirty state, ports and saved revisions',()=>{
  const m=modelWithNodes(),a=operations.routingDraft(m,'nA'),b=operations.routingDraft(m,'nB');
  a.direct_domains.push('added.example');a.ports.mixed_port=7891;
  assert.equal(operations.routingDirty(a),true);assert.equal(operations.routingDirty(b),false);assert.deepEqual(b.direct_domains,['b.example']);assert.equal(b.saved.revision,5);assert.equal(b.ports.mixed_port,7890);assert.notStrictEqual(a,b);assert.equal(m.revision,1);
});
test('saved policy shape and local ports are validated; unsupported Xray omits credentials',()=>{
  for(const value of [{enabled:'true',direct_domains:[],revision:1},{enabled:true,direct_domains:['https://bad.example'],revision:1},{enabled:true,direct_domains:[],revision:-1}])assert.throws(()=>operations.normalizeRouting(value));
  const d=operations.routingDraft(modelWithNodes(),'nA');d.ports.socks_port=10809;assert.throws(()=>operations.routingPorts(d),/不能相同/);d.ports.socks_port=0;assert.throws(()=>operations.routingPorts(d),/1–65535/);
  assert.deepEqual(operations.normalizeXray({available:false,json:'credential',notice:'legacy alterId'}),{available:false,notice:'legacy alterId'});
  assert.equal(operations.normalizeXray(xray({filename:'../../secret.json'})).filename,'G-Network-node.json');assert.throws(()=>operations.normalizeXray(xray({json:'broken'})),/格式/);
});
test('node card entry opens the dedicated tab without changing selection, generic groups or rules',async()=>{
  const h=await loaded();assert.match(h.element('#cw-nodes').innerHTML,/data-cw-route-node="nA"/);assert.match(h.element('#cw-nodes').innerHTML,/data-cw-route-node="nB"/);
  const rules=h.element('#cw-rules').innerHTML,groups=h.element('#cw-groups').innerHTML;
  await h.route('nB');assert.equal(h.element('#cw-editor-node-routing').hidden,false);assert.equal(h.element('#cw-editor-rules').hidden,true);assert.equal(h.element('#cw-step-nodes').textContent,'2 个');assert.equal(h.element('#cw-rules').innerHTML,rules);assert.equal(h.element('#cw-groups').innerHTML,groups);
  assert.match(h.element('#cw-node-routing').innerHTML,/b\.example/);assert.match(h.element('#cw-node-routing').innerHTML,/West.*vless.*8443/);
});
test('opening node-routing during a catalog read restores save and generate buttons when that read completes',async()=>{
  const h=ui(),late=deferred();h.setFetch(async()=>late.promise);const pending=h.click('cw-read');await immediate();await h.click('routing-tab',{cwTab:'node-routing'});
  late.resolve(response(catalog(nodes.map(n=>({...n,routing:{enabled:false,direct_domains:[],revision:0}})))));await pending;
  assert.equal(h.element('#cw-editor-node-routing').hidden,false);assert.equal(h.element('#cw-routing-state').textContent,'未保存');assert.equal(h.element('#cw-routing-save').disabled,false);assert.equal(h.element('#cw-routing-generate').disabled,false);
  h.setFetch(async(url,options)=>{assert.equal(url,'/api/node-routing/save');const data=JSON.parse(options.body);assert.equal(data.expected_revision,0);return response({ok:true,routing:{enabled:data.enabled,direct_domains:data.direct_domains,revision:1}});});h.input('ready.example');await h.click('cw-routing-save');assert.equal(h.requests.at(-1).url,'/api/node-routing/save');assert.equal(h.element('#cw-routing-state').textContent,'已保存于本机');assert.equal(h.element('#cw-routing-generate').disabled,false);
});
test('editing and switching preserves each node’s unsaved buffer and chips without localStorage',async()=>{
  const h=await loaded();h.context.localStorage={setItem(){throw new Error('Must not persist drafts or credentials');}};
  await h.route('nA');h.input('pending-a.example');await h.route('nB');h.input('new-b.example');await h.click('cw-routing-add-domains');await h.route('nA');
  assert.match(h.element('#cw-node-routing').innerHTML,/pending-a\.example/);assert.ok(!h.element('#cw-node-routing').innerHTML.includes('new-b.example'));assert.equal(h.element('#cw-routing-state').textContent,'未保存');
  await h.route('nB');assert.match(h.element('#cw-node-routing').innerHTML,/new-b\.example/);assert.ok(!h.element('#cw-node-routing').innerHTML.includes('pending-a.example'));
});
test('invalid batches show a precise inline error and never issue a save or export request',async()=>{
  const h=await loaded();await h.route('nA');h.input('good.example,https://invalid.example/path');await h.click('cw-routing-generate');assert.equal(h.requests.length,0);assert.match(h.element('#cw-routing-message').textContent,/纯域名/);assert.ok(!h.element('#cw-node-routing').innerHTML.includes('cw-domain-chip"><span>good.example'));
});
test('save commits only the active node through CSRF and optimistic revision, then updates its card',async()=>{
  const h=await loaded(),saved=apiStore(h);await h.route('nB');h.input('Example.COM，例子.测试');await h.click('cw-routing-save');
  assert.equal(h.requests.length,1);const request=h.requests[0];assert.equal(request.url,'/api/node-routing/save');assert.equal(request.options.headers.get('X-CSRF-Token'),'test-csrf-token');
  assert.deepEqual(JSON.parse(request.options.body),{snapshot_id:'snapshot-test',node_id:'nB',enabled:true,direct_domains:['b.example','example.com','xn--fsqu00a.xn--0zwm56d'],expected_revision:5});
  assert.equal(h.element('#cw-routing-state').textContent,'已保存于本机');assert.match(h.element('#cw-nodes').innerHTML,/3 个直连域名/);assert.deepEqual(saved.get('nA').direct_domains,['a.example']);assert.equal(h.element('#cw-routing-save').disabled,true);
});
test('save-and-generate adds pending domains first, then exports only that saved node and current ports',async()=>{
  const h=await loaded();apiStore(h);await h.route('nA');h.input('added.example');h.change({dataset:{cwRoutePort:'mixed_port'},value:'7891'});await h.click('cw-routing-generate');
  assert.deepEqual(Array.from(h.requests,r=>r.url),['/api/node-routing/save','/api/node-routing/export']);assert.deepEqual(JSON.parse(h.requests[1].options.body),{snapshot_id:'snapshot-test',node_id:'nA',mixed_port:7891,socks_port:10808,http_port:10809});
  assert.match(h.element('#cw-routing-output').innerHTML,/当前节点的专属配置/);assert.match(h.element('#cw-routing-output').innerHTML,/Clash \/ Mihomo/);assert.equal(h.element('#cw-step-nodes').textContent,'2 个');
  await h.click('routing-copy',{cwRouteExport:'copy'});assert.equal(h.context.copied,clash().yaml);await h.click('format-xray',{cwRouteFormat:'xray'});await h.click('routing-copy',{cwRouteExport:'copy'});assert.equal(h.context.copied,xray().json);
});
test('policy saves do not inject node-specific domains into the generic multi-node export',async()=>{
  const h=await loaded();apiStore(h);await h.route('nA');h.input('only-a.example');await h.click('cw-routing-save');await h.click('cw-generate');const generic=JSON.parse(h.requests.at(-1).options.body);
  assert.equal(h.requests.at(-1).url,'/api/clash-workspace/export');assert.deepEqual(generic.node_ids,['nA','nB']);assert.ok(!JSON.stringify(generic.profile).includes('only-a.example'));assert.equal(generic.profile.rules.at(-1).type,'MATCH');
});
test('changing ports, adding a pending domain, disabling or deleting a domain blocks stale exports',async()=>{
  const h=await loaded();apiStore(h);await h.route('nA');await h.click('cw-routing-generate');h.input('not-added.example');h.context.copied=undefined;await h.click('copy-old',{cwRouteExport:'copy'});assert.equal(h.context.copied,undefined);
  h.input('');await h.click('cw-routing-generate');h.change({dataset:{cwRoutePort:'mixed_port'},value:'7892'});await h.click('copy-old',{cwRouteExport:'copy'});assert.equal(h.context.copied,undefined);
  await h.click('cw-routing-generate');h.change({id:'cw-routing-enabled',dataset:{},checked:false});await h.click('copy-old',{cwRouteExport:'copy'});assert.equal(h.context.copied,undefined);assert.match(h.element('#cw-node-routing').innerHTML,/分流已关闭/);
  await h.click('cw-routing-generate');await h.click('remove-domain',{cwRouteRemove:'a.example'});await h.click('copy-old',{cwRouteExport:'copy'});assert.equal(h.context.copied,undefined);assert.equal(h.element('#cw-routing-state').textContent,'未保存');
});
test('single-node format output validates URLs and escapes malicious notices, names, JSON and warnings',async()=>{
  const danger='</textarea><img src=x onerror="alert(1)"><script>unsafe</script>',h=await loaded([{...nodes[0],name:danger}]);await h.route('nA');
  h.setFetch(async()=>response(exportResult(nodes[0].routing,{clash:clash({url:'https://untrusted.example/',notice:danger,yaml:danger,import_url:'clash://evil'}),xray:xray({json:JSON.stringify({message:danger}),notice:danger}),warnings:[danger]})));await h.click('cw-routing-generate');
  let html=h.element('#cw-node-routing').innerHTML+h.element('#cw-routing-output').innerHTML;assert.ok(!html.includes('<img'));assert.ok(!html.includes('<script>'));assert.ok(!html.includes('https://untrusted.example/'));assert.ok(!html.includes('clash://evil'));assert.match(html,/&lt;\/textarea&gt;/);
  await h.click('format-xray',{cwRouteFormat:'xray'});html=h.element('#cw-routing-output').innerHTML;assert.ok(!html.includes('<img'));assert.match(html,/&lt;img/);
});
test('legacy Xray incompatibility is shown while the valid Clash result remains usable',async()=>{
  const h=await loaded();await h.route('nA');h.setFetch(async()=>response(exportResult(nodes[0].routing,{xray:{available:false,notice:'alterId 大于 0，Xray 不支持'}})));await h.click('cw-routing-generate');await h.click('format-xray',{cwRouteFormat:'xray'});assert.match(h.element('#cw-routing-output').innerHTML,/alterId 大于 0/);assert.ok(!h.element('#cw-routing-output').innerHTML.includes('data-cw-route-export'));
  await h.click('format-clash',{cwRouteFormat:'clash'});await h.click('routing-copy',{cwRouteExport:'copy'});assert.equal(h.context.copied,clash().yaml);
});
test('UTF-8 JSON downloads use inline output, remove the anchor and revoke its Blob URL',async()=>{
  const h=await loaded(),created=[],revoked=[],downloads=[];h.context.URL=class extends URL{static createObjectURL(blob){created.push(blob);return 'blob:node-routing';}static revokeObjectURL(url){revoked.push(url);}};
  const original=h.context.document.createElement;h.context.document.createElement=tag=>{const node=original(tag);if(tag==='a'){node.click=()=>downloads.push({href:node.href,filename:node.download});node.remove=()=>{h.context.document.body.children=h.context.document.body.children.filter(n=>n!==node);};}return node;};
  apiStore(h);await h.route('nA');await h.click('cw-routing-generate');await h.click('format-xray',{cwRouteFormat:'xray'});const requests=h.requests.length;await h.click('download',{cwRouteExport:'download'});
  assert.equal(await created[0].text(),xray().json);assert.equal(created[0].type,'application/json;charset=utf-8');assert.deepEqual(downloads,[{href:'blob:node-routing',filename:'G-Network-node.json'}]);assert.equal(h.context.document.body.children.length,0);assert.equal(h.requests.length,requests);await h.timer(1000);assert.deepEqual(revoked,['blob:node-routing']);
});
test('double-click save is blocked, and a late save updates its own draft after switching nodes',async()=>{
  const h=await loaded(),late=deferred();await h.route('nA');h.input('saved-a.example');h.setFetch(async()=>late.promise);const pending=h.click('cw-routing-save');await immediate();await h.click('cw-routing-save');assert.equal(h.requests.length,1);
  await h.route('nB');h.input('unsaved-b.example');late.resolve(response({ok:true,routing:{enabled:true,direct_domains:['a.example','saved-a.example'],revision:2}}));await pending;
  assert.equal(h.element('#cw-routing-domain-input').value,'unsaved-b.example');assert.ok(!h.element('#cw-node-routing').innerHTML.includes('saved-a.example'));assert.equal(h.element('#cw-routing-state').textContent,'未保存');await h.route('nA');assert.equal(h.element('#cw-routing-state').textContent,'已保存于本机');assert.match(h.element('#cw-node-routing').innerHTML,/saved-a\.example/);await h.route('nB');assert.match(h.element('#cw-node-routing').innerHTML,/unsaved-b\.example/);
});
test('late single-node generation cannot replace another node’s result or make its copy action usable',async()=>{
  const h=await loaded(),late=deferred();await h.route('nA');h.setFetch(async()=>late.promise);const pending=h.click('cw-routing-generate');await immediate();await h.route('nB');late.resolve(response(exportResult(nodes[0].routing)));await pending;
  assert.equal(h.element('#cw-routing-output').innerHTML,'');await h.click('wrong-copy',{cwRouteExport:'copy'});assert.equal(h.context.copied,undefined);await h.route('nA');assert.match(h.element('#cw-routing-output').innerHTML,/当前节点的专属配置/);
});
test('source invalidation discards a pending save and every prior generated output',async()=>{
  const h=await loaded(),late=deferred();await h.route('nA');h.input('late.example');h.setFetch(async()=>late.promise);const pending=h.click('cw-routing-save');await immediate();h.change({dataset:{cwSource:'B'},checked:false});late.resolve(response({ok:true,routing:{enabled:true,direct_domains:['a.example','late.example'],revision:2}}));await pending;
  assert.match(h.element('#cw-node-routing').innerHTML,/先读取你的节点/);assert.equal(h.element('#cw-step-nodes').textContent,'0 个');assert.ok(!h.element('#cw-node-routing').innerHTML.includes('late.example'));await h.click('copy-late',{cwRouteExport:'copy'});assert.equal(h.context.copied,undefined);
});
test('revision conflicts and expired snapshots preserve the unsaved list while refusing export',async()=>{
  for(const message of ['名单已被其他窗口修改，请重新读取','快照已过期，请重新读取']){const h=await loaded();await h.route('nB');h.input('keep.example');h.setFetch(async()=>response({ok:false,msg:message},409));await h.click('cw-routing-generate');assert.equal(h.requests.length,1);assert.match(h.element('#cw-routing-message').textContent,new RegExp(message));assert.match(h.element('#cw-node-routing').innerHTML,/keep\.example/);assert.equal(h.element('#cw-routing-state').textContent,'未保存');assert.equal(h.element('#cw-routing-output').innerHTML,'');}
});
test('exact node entry matches saved source, port, protocol and name, and refuses arbitrary fallback',async()=>{
  const h=await loaded();const success=await h.run('window.ClashWorkspace.focusRoutingNode("B",'+JSON.stringify({port:8443,protocol:'VLESS',name:'同名节点'})+')');assert.equal(success,true);assert.match(h.element('#cw-node-routing').innerHTML,/b\.example/);assert.equal(h.requests.length,0);
  h.setFetch(async()=>response(catalog([nodes[0]])));const missing=await h.run('window.ClashWorkspace.focusRoutingNode("A",'+JSON.stringify({port:9999,protocol:'vmess',name:'同名节点'})+')');assert.equal(missing,false);assert.deepEqual(JSON.parse(h.requests.at(-1).options.body),{server_ids:['A']});assert.deepEqual(Array.from(h.run('verified')),['A','B','A']);
  const count=h.requests.length;const manual=await h.run('window.ClashWorkspace.focusRoutingNode("__manual__",'+JSON.stringify({port:443,protocol:'vmess',name:'同名节点'})+')');assert.equal(manual,false);assert.equal(h.requests.length,count);
});
test('configuration format tabs support arrow and Home/End keys while keeping focus and copy format together',async()=>{
  const h=await loaded();apiStore(h);await h.route('nA');await h.click('cw-routing-generate');let prevented=0;
  const key=async value=>{const button=h.element('#cw-routing-format-clash');h.element('#clash-workspace').listeners.keydown({key:value,target:{closest:selector=>selector==='[data-cw-route-format]'?button:null},preventDefault:()=>prevented++});await h.click('keyboard-copy',{cwRouteExport:'copy'});};
  await key('End');assert.equal(h.context.copied,xray().json);assert.strictEqual(h.context.document.activeElement,h.element('#cw-routing-format-xray'));assert.match(h.element('#cw-routing-output').innerHTML,/data-cw-route-format="xray" class="active" aria-selected="true"/);
  await key('Home');assert.equal(h.context.copied,clash().yaml);assert.strictEqual(h.context.document.activeElement,h.element('#cw-routing-format-clash'));await key('ArrowRight');assert.equal(h.context.copied,xray().json);await key('ArrowLeft');assert.equal(h.context.copied,clash().yaml);assert.equal(prevented,4);
});
test('invalid local ports prevent both save and export while retaining pending domains for correction',async()=>{
  const h=await loaded();await h.route('nA');h.input('retained.example');h.change({dataset:{cwRoutePort:'socks_port'},value:'10809'});await h.click('cw-routing-generate');assert.equal(h.requests.length,0);assert.match(h.element('#cw-routing-message').textContent,/不能相同/);assert.match(h.element('#cw-node-routing').innerHTML,/retained\.example/);assert.equal(h.element('#cw-routing-state').textContent,'未保存');
});
test('export revision mismatch never presents an outdated configuration as current',async()=>{
  const h=await loaded();await h.route('nA');h.setFetch(async()=>response(exportResult({...nodes[0].routing,revision:2})));await h.click('cw-routing-generate');assert.match(h.element('#cw-routing-message').textContent,/其他窗口修改/);assert.equal(h.element('#cw-routing-output').innerHTML,'');await h.click('stale-copy',{cwRouteExport:'copy'});assert.equal(h.context.copied,undefined);
});
test('closing the workspace discards late configuration results and refuses prior copy callbacks',async()=>{
  const h=await loaded(),late=deferred();await h.route('nA');h.setFetch(async()=>late.promise);const pending=h.click('cw-routing-generate');await immediate();h.run('window.ClashWorkspace.destroy()');late.resolve(response(exportResult(nodes[0].routing)));await pending;await h.click('closed-copy',{cwRouteExport:'copy'});assert.equal(h.context.copied,undefined);assert.equal(h.element('#cw-routing-output').innerHTML,'');
});

(async()=>{let passed=0;for(const {name,fn} of tests){try{await fn();console.log('PASS '+name);passed++;}catch(e){console.error('FAIL '+name);console.error(e.stack);process.exitCode=1;}}console.log(passed+'/'+tests.length+' node-routing frontend checks passed');})();
