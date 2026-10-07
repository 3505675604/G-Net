'use strict';
// Only synthetic nodes, text and in-memory responses are used; no client, file or SSH runs.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const operations=require('../static/clash-workspace.js');
const fixtureSource=fs.readFileSync(path.join(__dirname,'test_frontend.js'),'utf8').split('const tests=[];')[0];
const fixture=vm.createContext({require,__dirname,console,setImmediate,Headers,URL,Blob});
vm.runInContext(fixtureSource+'\nglobalThis.fixtures={harness,response,deferred,immediate};',fixture);
const {harness,response,deferred,immediate}=fixture.fixtures;
const source=fs.readFileSync(path.join(__dirname,'../static/clash-workspace.js'),'utf8');
const servers=[{id:'A',name:'North',host:'a.invalid',port:22,user:'root'}];
const node=(id,origin='import')=>({id,origin,server_id:origin==='server'?'A':'',server_name:origin==='server'?'North':'本机配置',name:'演示 '+id,host:id+'.invalid',port:443,protocol:'vless',available:true,compatibility:'mihomo',routing:{enabled:true,direct_domains:[id.toLowerCase()+'.example'],revision:1}});
const catalog=(nodes=[node('n1'),node('n2')],extra={})=>({ok:true,snapshot_id:'snap-new',nodes,servers:[],imported_ids:nodes.map(n=>n.id),...extra});
const canonical={name:'示例配置',mixed_port:7899,mode:'rule',chains:[{name:'出口链',hops:['n1','n2'],enabled:true}],groups:[{name:'总开关',type:'select',members:['出口链','n1','DIRECT']},{name:'测速',type:'url-test',members:['n1','n2'],url:'http://example.invalid/generate_204',interval:300}],rules:[{type:'DOMAIN-SUFFIX',value:'ai.example',target:'出口链'},{type:'MATCH',value:'',target:'总开关'}],advanced:{dns:operations.splitDnsTemplate(),sniffer:{enable:true},tun:{enable:false}}};
function loadedModel(){const m=operations.createModel();operations.acceptCatalog(m,catalog());return m;}
function ui(){
  const h=harness();h.context.window.document=h.context.document;h.context.window.navigator=h.context.navigator;h.context.window.confirm=()=>true;
  h.element('#clash-workspace').contains=()=>true;h.element('meta[name="fl-loopback-port"]').content='8620';h.run('fleet='+JSON.stringify(servers));h.run(source);
  h.run('window.ClashWorkspace.init({api,jsonPost,toast,getServers:()=>fleet,normalizeConfig:clashConfig,ensureIdentity:async()=>{}})');
  h.click=(id,data={})=>{const b=h.element('#'+id);b.dataset={...b.dataset,...data};return h.element('#clash-workspace').listeners.click({target:{closest:()=>b}});};
  h.change=input=>h.element('#clash-workspace').listeners.change({target:input});
  h.input=(id,value,dataset={})=>{h.element('#'+id).value=value;return h.element('#clash-workspace').listeners.input({target:{id,value,dataset}});};
  return h;
}
const preview={ok:true,import_token:'preview-token',source_format:'yaml',node_count:2,group_count:2,rule_count:2,chain_count:1,can_replace:true,nodes:[node('n1'),node('n2')],errors:[],warnings:[],omitted_fields:[]};
const saved={id:'saved-one',name:'示例配置',revision:1,node_count:2,group_count:2,rule_count:2,chain_count:1};
async function imported(){const h=ui();h.setFetch(async url=>{if(url.endsWith('import-preview'))return response(preview);if(url.endsWith('/import'))return response(catalog(undefined,{profile:canonical}));throw new Error(url);});h.input('cw-import-text','proxies: []');await h.click('cw-import-preview');await h.click('cw-import-replace');h.requests.length=0;return h;}
const tests=[];function test(name,fn){tests.push({name,fn});}

test('seven studio tabs start with only the source panel visible',()=>{const h=ui();assert.equal(h.element('#cw-editor-source').hidden,false);for(const key of ['chains','groups','rules','node-routing','dns','output'])assert.equal(h.element('#cw-editor-'+key).hidden,true);assert.match(h.element('#clash-workspace').innerHTML,/cw-tab-dns/);});
test('imported catalog nodes do not require SSH sources but arbitrary source origins remain rejected',()=>{const m=loadedModel();assert.equal(m.nodes.length,2);const other=operations.createModel();assert.throws(()=>operations.acceptCatalog(other,catalog([node('rogue','server')])));});
test('node-only merge keeps rules, chain, advanced fields and independent dirty domain buffers',()=>{
  const m=loadedModel(),draft=operations.routingDraft(m,'n1');draft.direct_domains.push('pending.example');m.chains=[{id:'c1',name:'链',hops:['n1','n2'],enabled:true}];m.advanced={sniffer:{enable:true}};const rules=JSON.stringify(m.rules),chain=JSON.stringify(m.chains);
  operations.acceptStudioCatalog(m,catalog([node('n1'),node('n2'),node('n3')],{imported_ids:['n3']}),'merge');assert.equal(JSON.stringify(m.rules),rules);assert.equal(JSON.stringify(m.chains),chain);assert.deepEqual(m.advanced,{sniffer:{enable:true}});assert.strictEqual(m.routingDrafts.get('n1'),draft);assert.ok(m.selected.has('n3'));assert.ok(!JSON.stringify(m.rules).includes('pending.example'));
});
test('missing old capability refuses a merge without mutating the current draft',()=>{const m=loadedModel(),before=operations.exportDraft(m);assert.throws(()=>operations.acceptStudioCatalog(m,catalog([node('n3')]),'merge'),/失效/);assert.deepEqual(operations.exportDraft(m),before);});
test('complete canonical import resolves opaque node IDs, group names and chain names without flattening DNS',()=>{
  const m=operations.createModel();operations.acceptStudioCatalog(m,catalog(undefined,{profile:canonical}),'replace');const p=operations.exportDraft(m).profile;assert.equal(p.name,'示例配置');assert.equal(p.mixed_port,7899);assert.deepEqual(p.chains,canonical.chains);assert.deepEqual(p.advanced,canonical.advanced);assert.equal(p.groups[0].members[0],'出口链');assert.equal(p.rules[0].target,'出口链');assert.equal(p.fallback,'总开关');assert.deepEqual(operations.validate(m),[]);
});
test('bad canonical targets leave the previous valid model untouched',()=>{const m=loadedModel(),before=operations.exportDraft(m),bad=structuredClone(canonical);bad.rules[0].target='missing-group';assert.throws(()=>operations.acceptStudioCatalog(m,catalog(undefined,{profile:bad}),'replace'),/引用/);assert.deepEqual(operations.exportDraft(m),before);});
test('chain validation catches duplicate hops, lost selected nodes, name collisions and hop limits',()=>{
  for(const hops of [['n1'],['n1','n1'],['n1','missing'],Array.from({length:9},()=> 'n1')]){const m=loadedModel();m.chains=[{id:'c1',name:'链',hops,enabled:true}];assert.ok(operations.validate(m).length);}
  const m=loadedModel();m.chains=[{id:'c1',name:'节点选择',hops:['n1','n2'],enabled:true}];assert.match(operations.validate(m).join(' '),/重名/);
});
test('bulk domain rules append before MATCH, normalize IDN and deduplicate exact type/value/target',()=>{
  const m=loadedModel(),before=m.rules.slice();assert.equal(operations.appendDomainRules(m,'Example.COM，例子.中国\nexample.com','group:g1'),2);assert.equal(m.rules.at(-1).type,'MATCH');assert.equal(m.rules[before.length-1].value,'example.com');assert.equal(operations.appendDomainRules(m,'example.com','group:g1'),0);assert.equal(operations.appendDomainRules(m,'example.com','DIRECT'),1);assert.throws(()=>operations.appendDomainRules(m,'https://bad.example','DIRECT'),/域名/);
});
test('AI and streaming presets append unique independent selector groups and keep existing rules',()=>{
  const m=loadedModel(),first=JSON.stringify(m.rules[0]),saved=operations.routingDraft(m,'n1');saved.direct_domains.push('only-node.example');operations.applyServicePreset(m,'ai');operations.applyServicePreset(m,'stream');const count=m.rules.length;assert.equal(operations.applyServicePreset(m,'ai'),0);assert.equal(m.rules.length,count);assert.equal(JSON.stringify(m.rules[0]),first);assert.equal(m.rules.at(-1).type,'MATCH');assert.equal(m.groups.filter(g=>g.name==='AI 服务').length,1);assert.ok(!JSON.stringify(m.rules).includes('only-node.example'));assert.equal(operations.exportDraft(m).profile.groups.length,5);
});
test('DNS starts absent and split template binds loopback with bootstrap resolution for proxy hosts',()=>{const m=loadedModel();assert.ok(!('advanced' in operations.exportDraft(m).profile));m.advanced={dns:operations.splitDnsTemplate()};assert.equal(m.advanced.dns.listen,'127.0.0.1:1053');assert.deepEqual(operations.validate(m),[]);m.advanced.dns['proxy-server-nameserver']=[];assert.match(operations.validate(m).join(' '),/节点域名/);});
test('preview, replace and generation serialize the canonical profile through CSRF-protected endpoints',async()=>{
  const h=await imported();assert.equal(h.element('#cw-profile-name').value,'示例配置');assert.equal(Number(h.element('#cw-mixed-port').value),7899);assert.equal(h.element('#cw-editor-groups').hidden,false);assert.match(h.element('#cw-chains').innerHTML,/出口节点/);h.setFetch(async(url,options)=>{assert.equal(url,'/api/clash-workspace/export');const body=JSON.parse(options.body);assert.equal(body.profile.chains[0].name,'出口链');assert.equal(body.profile.advanced.dns['respect-rules'],true);assert.equal(options.headers.get('X-CSRF-Token'),'test-csrf-token');return response({ok:true,clash:{available:false,notice:'synthetic'}});});await h.click('cw-generate');
});
test('complete replacement requires confirmation and cancel keeps the current snapshot',async()=>{
  const h=await imported();let calls=0;h.setFetch(async url=>{calls++;if(url.endsWith('import-preview'))return response(preview);throw new Error('replace should not run');});h.input('cw-import-text','changed');await h.click('cw-import-preview');h.context.window.confirm=()=>false;await h.click('cw-import-replace');assert.equal(calls,1);assert.equal(h.element('#cw-step-nodes').textContent,'2 个');
});
test('changed preview text clears its capability and refuses an old import action',async()=>{
  const h=ui();h.setFetch(async()=>response(preview));h.input('cw-import-text','first');await h.click('cw-import-preview');const count=h.requests.length;h.input('cw-import-text','second');await h.click('cw-import-merge');assert.equal(h.requests.length,count);
});
test('oversized UTF-8 import text fails before a parsing request',async()=>{const h=ui();h.input('cw-import-text','界'.repeat(175000));await h.click('cw-import-preview');assert.equal(h.requests.length,0);});
test('chain hop controls preserve ordered base IDs in the generated payload',async()=>{
  const h=await imported();await h.click('move',{cwHopMove:'-1',chain:'c1',index:'1'});h.setFetch(async(url,options)=>{const body=JSON.parse(options.body);assert.deepEqual(body.profile.chains[0].hops,['n2','n1']);return response({ok:true,clash:{available:false}});});await h.click('cw-generate');
});
test('local encrypted save uses optimistic revision after opening and supports save-as-new',async()=>{
  const h=await imported();h.setFetch(async(url,options)=>{if(url.endsWith('/profiles/save'))return response({ok:true,profile:saved});throw new Error(url);});await h.click('cw-profile-save');let body=JSON.parse(h.requests.at(-1).options.body);assert.ok(!('profile_id' in body));assert.equal(body.snapshot_id,'snap-new');
  h.setFetch(async(url,options)=>{if(url.endsWith('/profiles/save')){const body=JSON.parse(options.body);assert.equal(body.profile_id,'saved-one');assert.equal(body.expected_revision,1);return response({ok:true,profile:{...saved,revision:2}});}throw new Error(url);});await h.click('cw-profile-save');
  h.setFetch(async(url,options)=>{const body=JSON.parse(options.body);assert.ok(!('profile_id' in body));assert.ok(!('expected_revision' in body));return response({ok:true,profile:{...saved,id:'saved-new'}});});await h.click('cw-profile-save-new');
});
test('profile open retains saved metadata and subsequent save sends its exact revision',async()=>{
  const h=ui();h.setFetch(async url=>url.endsWith('/profiles/open')?response(catalog(undefined,{profile:canonical,saved_profile:{...saved,revision:7}})):response({ok:true,profiles:[saved]}));await h.click('cw-profiles-refresh');await h.click('open',{cwProfileOpen:saved.id});h.setFetch(async(url,options)=>{assert.equal(JSON.parse(options.body).expected_revision,7);return response({ok:true,profile:{...saved,revision:8}});});await h.click('cw-profile-save');assert.match(h.element('#cw-output').innerHTML,/继续保存/);
});
test('late profile open after destruction cannot replace the discarded workspace',async()=>{const h=ui(),late=deferred();h.setFetch(async()=>late.promise);const pending=h.click('open',{cwProfileOpen:saved.id});await immediate();h.run('window.ClashWorkspace.destroy()');late.resolve(response(catalog(undefined,{profile:canonical,saved_profile:saved})));await pending;assert.equal(h.element('#cw-profile-name').value,'G-Network');});
test('untrusted preview labels, warnings and saved profile names are escaped',async()=>{const h=ui(),danger='<img src=x onerror=alert(1)>';h.input('cw-import-text','fake');h.setFetch(async()=>response({...preview,nodes:[{...node('n1'),name:danger}],warnings:[danger],omitted_fields:[danger]}));await h.click('cw-import-preview');assert.ok(!h.element('#cw-studio-source').innerHTML.includes('<img'));h.setFetch(async()=>response({ok:true,profiles:[{...saved,name:danger}]}));await h.click('cw-profiles-refresh');assert.ok(!h.element('#cw-studio-source').innerHTML.includes('<img'));});
test('explicit single-node MATCH survives full import and route template application',()=>{const m=operations.createModel(),p=structuredClone(canonical);p.rules.at(-1).target='n2';operations.acceptStudioCatalog(m,catalog(undefined,{profile:p}),'replace');assert.equal(operations.exportDraft(m).profile.rules.at(-1).target,'n2');assert.equal(operations.exportDraft(m).profile.fallback,'n2');operations.applyTemplate(m,'global');assert.equal(operations.exportDraft(m).profile.rules[0].target,'n2');});
test('DNS port is in the DNS panel only, edits invalidate previous generated output',async()=>{const h=await imported();assert.match(h.element('#cw-dns').innerHTML,/id="cw-mixed-port"/);assert.equal((h.element('#clash-workspace').innerHTML.match(/id="cw-mixed-port"/g)||[]).length,0);h.change({id:'cw-mixed-port',value:'8123',dataset:{}});h.setFetch(async(url,options)=>{assert.equal(JSON.parse(options.body).profile.mixed_port,8123);return response({ok:true,clash:{available:false}});});await h.click('cw-generate');});
test('advanced JSON cannot corrupt DNS structure or overwrite topology',()=>{for(const value of [{dns:1},{dns:{nameserver:'https://example.invalid/dns'}},{rules:[]},{'proxy-groups':[]}])assert.throws(()=>operations.parseAdvanced(JSON.stringify(value)));const advanced={dns:operations.splitDnsTemplate(),sniffer:{enable:true},tun:{enable:false}};assert.deepEqual(operations.parseAdvanced(JSON.stringify(advanced)),advanced);});
test('a service preset hitting the rule quota does not leave a half-created group',()=>{const m=loadedModel();m.rules=Array.from({length:199},(_,i)=>({id:'r'+i,type:'DOMAIN-SUFFIX',value:'h'+i+'.example',target:'DIRECT'})).concat([{id:'last',type:'MATCH',value:'',target:'group:g1'}]);const before=JSON.stringify(m.groups);assert.throws(()=>operations.applyServicePreset(m,'ai'),/200/);assert.equal(JSON.stringify(m.groups),before);});

(async()=>{let passed=0;for(const {name,fn} of tests){try{await fn();console.log('PASS '+name);passed++;}catch(e){console.error('FAIL '+name);console.error(e.stack);process.exitCode=1;}}console.log(passed+'/'+tests.length+' Clash studio checks passed');})();
