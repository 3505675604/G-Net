'use strict';
// Run with node tests/test_frontend.js. No browser, local service, or SSH connection is used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {TextEncoder}=require('node:util');
const template = fs.readFileSync(path.join(__dirname, '../templates/index.html'), 'utf8');
const source = template.slice(template.lastIndexOf('<script>') + 8, template.lastIndexOf('</script>'))
  .replace('{{ csrf_token|tojson }}', JSON.stringify('test-csrf-token'))
  .replace('loadServers().catch(e=>toast(e.message,false));renderTools();loadSettings();', '');
new vm.Script(source, {filename: 'index.html'});

const decode = text => String(text).replace(/&(?:amp|lt|gt|quot|#39);/g, x => ({'&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&#39;':"'"}[x]));
const strip = html => decode(String(html).replace(/<[^>]*>/g, ''));
function response(data, status=200){
  return {ok:status>=200&&status<300,status,headers:new Headers({'Content-Type':'application/json'}),json:async()=>data};
}
const protocols = {protocols:{'vless-reality':{label:'Reality',desc:'test'}},ss_methods:['aes-128-gcm']};
const serverA = {id:'A',name:'A',host:'a.example',user:'root',port:22};
const serverB = {id:'B',name:'B',host:'b.example',user:'root',port:22};
const info = label => ({os:label,kernel:'1',cpu:'cpu',load:'0',mem:'1',disk:'1',uptime:'1',bbr:'bbr',tools:{}});
const immediate = () => new Promise(resolve => setImmediate(resolve));
function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}

function harness(){
  const elements=new Map(), timers=new Map(), requests=[], sockets=[], events={};
  let timerId=0, fetchHandler=async url=>{
    if(url==='/api/servers')return response([serverA,serverB]);
    if(url==='/api/nodes/protocols')return response(protocols);
    if(url==='/api/settings')return response({deepseek_key_set:true,openai_key_set:false,anthropic_key_set:false});
    if(url.endsWith('/test'))return response({ok:true,msg:'connected'});
    if(url.endsWith('/info'))return response(info(url.includes('/B/')?'B':'A'));
    throw new Error('Unexpected request '+url);
  };
  class Element {
    constructor(tag='div'){this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this.style={};this.disabled=false;this.checked=false;this._html='';this._text='';this._value='';this.options=[];this.classes=new Set();this.listeners={};this.attributes={};this.classList={add:(...v)=>v.forEach(x=>this.classes.add(x)),remove:(...v)=>v.forEach(x=>this.classes.delete(x)),contains:v=>this.classes.has(v),toggle:(v,on)=>{if(on??!this.classes.has(v))this.classes.add(v);else this.classes.delete(v);}};}
    set className(value){this.classes=new Set(String(value).split(/\s+/).filter(Boolean));} get className(){return [...this.classes].join(' ');}
    set innerHTML(html){
      this._html=String(html);this._text=strip(html);this.children=[];
      this.options=[...this._html.matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g)].map(m=>({value:decode(m[1]),textContent:decode(m[2])}));
      if(this.options.length)this._value=this.options[0].value;
      for(const m of this._html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)){
        const id=m[1].match(/\bid="([^"]*)"/);const el=id?element('#'+id[1]):new Element('button');el.tagName='BUTTON';el.textContent=strip(m[2]);el.disabled=/\bdisabled\b/.test(m[1]);
        const className=m[1].match(/\bclass="([^"]*)"/);if(className)el.className=className[1];
        for(const a of m[1].matchAll(/data-([a-z-]+)="([^"]*)"/g)){const key=a[1].replace(/-([a-z])/g,(_,x)=>x.toUpperCase());el.dataset[key]=decode(a[2]);}
        this.children.push(el);
      }
    }
    get innerHTML(){return this._html;}
    set textContent(text){this._text=String(text??'');this._html='';this.children=[];} get textContent(){return this._text;}
    set value(value){this._value=String(value);} get value(){return this._value;}
    replaceChildren(...children){this._html='';this._text='';this.children=[...children];}
    appendChild(el){this.children.push(el);return el;}
    setAttribute(name,value){this.attributes[name]=String(value);}
    addEventListener(name,fn){this.listeners[name]=fn;}
    querySelectorAll(selector){return this.children.filter(el=>matches(el,selector));}
    scrollIntoView(){}
    focus(){document.activeElement=this;}
    click(){if(!this.disabled&&this.onclick)return this.onclick();}
    remove(){}
  }
  function matches(el,selector){
    if(selector==='button')return el.tagName==='BUTTON';
    if(selector.startsWith('.'))return el.classList.contains(selector.slice(1));
    const m=selector.match(/^\[data-([a-z-]+)(?:="([^"]*)")?\]$/);
    if(m){const key=m[1].replace(/-([a-z])/g,(_,x)=>x.toUpperCase());return key in el.dataset&&(m[2]===undefined||el.dataset[key]===m[2]);}
    return false;
  }
  function element(selector){if(!elements.has(selector)){const node=new Element(selector.includes('server')?'select':'div');if(selector.startsWith('#'))node.id=selector.slice(1);elements.set(selector,node);}return elements.get(selector);}
  for(const m of template.slice(0,template.lastIndexOf('<script>')).matchAll(/\bid="([^"]+)"/g))element('#'+m[1]);
  const pages=['dash','term','tool','node','file','set'].map(p=>{const el=element('#p-'+p);el.className='page'+(p==='dash'?' active':'');return el;});
  const tabs=pages.map((_,i)=>{const el=new Element();el.className='tab'+(i===0?' active':'');el.dataset.p=['dash','term','tool','node','file','set'][i];return el;});
  // Read the real category controls so tests exercise the template's click bindings and ARIA state.
  const chips=[...template.slice(0,template.lastIndexOf('<script>')).matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)]
    .filter(m=>/\bclass="[^"]*\bfilter-chip\b/.test(m[1])).map(m=>{
      const el=new Element('button');el.className=m[1].match(/\bclass="([^"]*)"/)[1];el.textContent=strip(m[2]);
      for(const a of m[1].matchAll(/data-([a-z-]+)="([^"]*)"/g)){const key=a[1].replace(/-([a-z])/g,(_,x)=>x.toUpperCase());el.dataset[key]=decode(a[2]);}
      for(const a of m[1].matchAll(/(aria-[a-z-]+)="([^"]*)"/g))el.setAttribute(a[1],decode(a[2]));
      return el;
    });
  ['#nlm-port','#nm-d-port','#nm-e-port','#nm-x-port','#a-port'].forEach(id=>element(id).value='22');
  ['#nlm-user','#nm-d-user','#nm-e-user','#nm-x-user','#a-user'].forEach(id=>element(id).value='root');
  element('#nl-server').value='A'; element('#n-server').value='A';element('#n-entry').value='A';element('#n-exit').value='B';
  element('#n-port').value='2089';element('#n-sni').value='www.amazon.com';element('#n-proto').value='vless-reality';
  element('#f-mode').value='name';
  const mode=element('input[name=n-mode]:checked');mode.value='direct';
  const document={body:new Element('body'),createElement:tag=>new Element(tag),getElementById:id=>element('#'+id),querySelector:selector=>{
    const match=selector.match(/^\.tab\[data-p="([^"]+)"\]$/);return match?tabs.find(t=>t.dataset.p===match[1]):element(selector);
  },querySelectorAll:selector=>{
    if(selector==='.tab')return tabs;if(selector==='.page')return pages;if(selector==='.filter-chip')return chips;
    if(selector==='#nl-man input')return ['#nlm-host','#nlm-port','#nlm-user','#nlm-pass'].map(element);
    const m=selector.match(/^(#[a-z-]+) (.+)$/);if(m)return element(m[1]).querySelectorAll(m[2]);
    if(selector.startsWith('['))return [...elements.values()].filter(el=>matches(el,selector));
    return elements.has(selector)?[element(selector)]:[];
  }};
  class WebSocket {
    constructor(url){this.url=url;this.readyState=0;this.sent=[];this.closed=false;sockets.push(this);}
    close(){this.closed=true;this.readyState=3;}
    send(value){this.sent.push(value);}
  }
  class Terminal {
    constructor(){this.writes=[];this.cols=80;this.rows=24;this.disposed=[];}
    loadAddon(){} open(){} reset(){this.writes=[];}write(value){this.writes.push(value);}writeln(value){this.write(value);}
    onData(fn){this.data=fn;return {dispose:()=>this.disposed.push('data')};}
    onResize(fn){this.resize=fn;return {dispose:()=>this.disposed.push('resize')};}
  }
  const context=vm.createContext({document,Headers,URL,Blob,TextEncoder,Terminal,WebSocket,FitAddon:{FitAddon:class{fit(){}}},QRCode:class{},location:{protocol:'http:',host:'127.0.0.1:8620'},navigator:{clipboard:{writeText:async value=>{context.copied=value;}}},window:{addEventListener:(name,fn)=>events[name]=fn,open:()=>{}},confirm:()=>true,prompt:()=>null,setTimeout:(fn,delay)=>{const id=++timerId;timers.set(id,{fn,delay});return id;},clearTimeout:id=>timers.delete(id),fetch:async(url,options)=>{requests.push({url,options});return fetchHandler(url,options);}});
  vm.runInContext(source,context);
  return {element,elements,requests,sockets,timers,events,context,run:code=>vm.runInContext(code,context),setFetch:fn=>fetchHandler=fn,async timer(delay){const [id,timer]=[...timers].find(([,v])=>v.delay===delay)||[];assert.ok(timer,'Timer '+delay+' exists');timers.delete(id);await timer.fn();}};
}

const tests=[];
function test(name,fn){tests.push({name,fn});}
test('HTTP, JSON, logical errors and CSRF headers are checked',async()=>{
  const h=harness();h.setFetch(async()=>response({msg:'denied'},403));
  await assert.rejects(h.run("api('/api/settings')"),/denied/);
  assert.equal(h.requests[0].options.headers.get('X-CSRF-Token'),'test-csrf-token');
  assert.equal(h.requests[0].options.credentials,'same-origin');
  h.setFetch(async()=>({ok:true,json:async()=>{throw new Error('bad JSON');}}));
  await assert.rejects(h.run("api('/api/settings')"),/返回格式错误/);
  h.setFetch(async()=>response({ok:false,errs:['bad port','bad uuid']}));
  await assert.rejects(h.run("api('/api/nodes/deploy')"),/bad port；bad uuid/);
  h.setFetch(async()=>{throw new Error('network');});
  await assert.rejects(h.run("api('/api/servers')"),/无法连接面板/);
});
test('server names, remote dashboard values, protocol options and result links are escaped',async()=>{
  const h=harness(),payload=`<img src=x onerror="window.pwn=1">'&`;
  h.setFetch(async url=>url==='/api/servers'?response([{...serverA,name:payload,host:payload,user:payload}]):url.endsWith('/info')?response({...info(payload),tools:{[payload]:payload}}):response({protocols:{[payload]:{label:payload,desc:payload}},ss_methods:[payload]}));
  await h.run('loadServers()');assert.match(h.element('#server-list').children[0].innerHTML,/&lt;img/);assert.ok(!h.element('#server-list').children[0].innerHTML.includes('<img'));
  h.run('cur='+JSON.stringify(serverA));await h.run('loadDash()');assert.ok(!h.element('#dash-content').innerHTML.includes('<img'));
  await h.run('initNode()');assert.ok(!h.element('#n-proto').innerHTML.includes('<img'));assert.ok(!h.element('#n-server').innerHTML.includes('<img'));
  h.run('showNodeResult('+JSON.stringify({server:payload,params:{[payload]:payload},links:[payload]})+')');assert.ok(!h.element('#node-result').innerHTML.includes('<img'));
});
test('server search matches name, host and user without mutating the fleet or interpreting dangerous text',async()=>{
  const h=harness(),danger=`<img src=x onerror="window.pwn=1">'&`,servers=[
    {...serverA,name:'North Beacon',host:'edge-one.example'},
    {...serverB,name:'Compute',host:'CACHE.TARGET.example',user:'runner'},
    {...serverA,id:'C',name:'Archive',host:'archive.example',user:'BackupOperator'},
    {...serverA,id:danger,name:danger,host:`unsafe'"<svg onload=alert(1)>&.example`,user:'operator'},
  ];
  h.setFetch(async url=>{assert.equal(url,'/api/servers');return response(servers);});
  h.run('scene={setServers(list){this.ids=list.map(s=>s.id);}}');
  await h.run('loadServers()');
  const fleet=h.run('fleet'),snapshot=JSON.parse(h.run('JSON.stringify(fleet)'));
  const input=h.element('#server-filter'),box=h.element('#server-list');
  for(const [keyword,index] of [['  NORTH  ',0],['cache.target',1],['BACKUPOPERATOR',2],['<img',3]]){
    input.value=keyword;input.listeners.input();
    assert.equal(box.children.length,1);assert.equal(box.children[0].classList.contains('srv'),true);
    assert.equal(box.children[0].attributes.title,servers[index].name+' · '+servers[index].host+'（右键删除）');
    assert.strictEqual(h.run('fleet'),fleet);
    assert.deepEqual(JSON.parse(h.run('JSON.stringify(fleet)')),snapshot);
    assert.deepEqual(JSON.parse(h.run('JSON.stringify(scene.ids)')),servers.map(s=>s.id));
    assert.equal(h.element('#fleet-count').textContent,'4');
    assert.equal(h.element('#summary-servers').innerHTML,'4 <small>台</small>');
  }
  const escaped=box.children[0].innerHTML;
  assert.match(escaped,/&lt;img/);assert.match(escaped,/&lt;svg/);assert.match(escaped,/&quot;/);
  assert.ok(!escaped.includes('<img'));assert.ok(!escaped.includes('<svg onload'));
  input.value='no matching server';input.listeners.input();
  assert.equal(box.children.length,1);assert.equal(box.children[0].textContent,'没有匹配的服务器');
  input.value='';input.listeners.input();assert.equal(box.children.length,4);
  assert.strictEqual(h.run('fleet'),fleet);assert.equal(h.requests.length,1);
});
test('tool keyword and category filters combine, update their controls and expose an empty state',async()=>{
  const h=harness(),input=h.element('#tool-filter'),box=h.element('#tools');
  const chips=h.context.document.querySelectorAll('.filter-chip');
  assert.deepEqual(chips.map(c=>c.dataset.toolCategory),['all','system','ai','network','desktop']);
  const choose=category=>{
    chips.find(c=>c.dataset.toolCategory===category).click();
    for(const chip of chips){const selected=chip.dataset.toolCategory===category;
      assert.equal(chip.classList.contains('active'),selected);
      assert.equal(chip.attributes['aria-pressed'],String(selected));
    }
  };
  const shown=()=>box.querySelectorAll('.tool');
  const search=value=>{input.value=value;input.listeners.input();};
  h.run('renderTools()');assert.equal(shown().length,8);assert.equal(h.element('#tool-count').textContent,'8 项工具');
  search('  KEY  ');assert.equal(shown().length,3);assert.ok(shown().every(t=>t.dataset.toolCategory==='ai'));
  choose('system');assert.equal(shown().length,0);assert.equal(h.element('#tool-count').textContent,'0 项工具');
  assert.equal(box.children[0].classList.contains('tools-empty'),true);
  assert.equal(box.children[0].textContent,'没有匹配的工具，请调整关键词或分类');
  search('  ai  ');assert.equal(shown().length,1);assert.match(shown()[0].innerHTML,/安装 Node\.js 22/);
  assert.equal(shown()[0].dataset.toolCategory,'system');assert.equal(h.element('#tool-count').textContent,'1 项工具');
  choose('ai');assert.equal(shown().length,1);assert.match(shown()[0].innerHTML,/安装 Codex CLI/);
  search('KEY');assert.equal(shown().length,3);assert.ok(shown().every(t=>t.dataset.toolCategory==='ai'));
  search('CODE');assert.equal(shown().length,2);assert.ok(shown().every(t=>/Claude Code|Codex CLI/.test(t.innerHTML)));
  choose('network');assert.equal(shown().length,0);
  search('TCP');assert.equal(shown().length,1);assert.match(shown()[0].innerHTML,/开启 BBR 加速/);
  choose('all');assert.equal(shown().length,1);search('');assert.equal(shown().length,8);
  assert.equal(h.requests.length,0);
});
test('empty server list exposes every manual entry form immediately',async()=>{
  const h=harness();h.setFetch(async url=>response(url==='/api/servers'?[]:protocols));
  await h.run('initNode()');
  for(const [sel,form] of [['#n-server','#n-man-direct'],['#n-entry','#n-man-entry'],['#n-exit','#n-man-exit'],['#nl-server','#nl-man']]){assert.equal(h.element(sel).value,'__manual__');assert.equal(h.element(form).style.display,'');}
});
test('remote file and search paths use text nodes or escaped HTML and bound functions',async()=>{
  const h=harness(),payload=`bad'"<&.txt`,full='/root/'+payload;
  h.run('cur='+JSON.stringify(serverA));
  h.setFetch(async url=>url.includes('/files?')?response({ok:true,path:'/root',items:[{name:payload,size:4,mtime:'<svg onload=alert(1)>',dir:false}]}):url.includes('/file?')?response({ok:true,content:'test'}):response({ok:true,results:[full]}));
  await h.run("loadFiles('/root')");const row=h.element('#fbody').children[0];assert.equal(typeof row.onclick,'function');assert.equal((row.innerHTML.match(/<svg\b/g)||[]).length,1);assert.ok(!row.innerHTML.includes('<svg onload'));assert.ok(row.innerHTML.includes('&lt;svg onload=alert(1)&gt;'));assert.ok(row.innerHTML.includes('<button type="button" class="fname'));assert.ok(row.innerHTML.includes('&lt;'));
  await row.onclick();assert.ok(h.requests.some(r=>r.url.includes(encodeURIComponent(full))));assert.equal(h.element('#pv-title').textContent,full);
  h.element('#f-search').value='<img onerror=alert(1)>';await h.run('doSearch()');const hit=h.element('#search-results').children[1];assert.equal(hit.textContent,full);assert.equal(typeof hit.onclick,'function');
  h.run('fpath='+JSON.stringify('/root/'+payload)+';renderCrumbs()');assert.equal(h.element('#crumbs').children.at(-1).textContent,payload);assert.equal(typeof h.element('#crumbs').children.at(-1).onclick,'function');
});
test('node deletion is bound to the loaded server and passes the immutable inbound token',async()=>{
  const h=harness(),deleted=deferred();h.setFetch(async(url,opts)=>url==='/api/nodes/list'?response({ok:true,host:'<img>',inbounds:[{kind:'<svg>',port:2089,tag:'<img>',extra:'<script>',link:'<img>',token:'signed-token'}]}):url==='/api/nodes/delete'?deleted.promise:response({ok:true}));
  await h.run('loadNodeList()');assert.ok(!h.element('#nl-body').innerHTML.includes('<img'));assert.ok(!h.element('#nl-body').innerHTML.includes('<svg>'));assert.ok(h.element('#nl-body').innerHTML.includes('&lt;svg&gt;'));
  h.element('#nl-server').value='B';await h.run('delNode(0)');assert.equal(h.requests.filter(r=>r.url==='/api/nodes/delete').length,0);
  h.element('#nl-server').value='A';const pending=h.run('delNode(0)');await immediate();
  const body=JSON.parse(h.requests.find(r=>r.url==='/api/nodes/delete').options.body);assert.deepEqual(body,{server:'A',tag:'<img>',token:'signed-token'});
  h.element('#nl-server').value='B';h.run("nodeSrvSel('#nl-server','#nl-man')");assert.equal(h.element('#nl-body').innerHTML,'');
  deleted.resolve(response({ok:true,msg:'deleted'}));await pending;assert.equal(h.requests.filter(r=>r.url==='/api/nodes/list').length,1);
});
test('in-flight node list responses are discarded after manual credential changes',async()=>{
  const h=harness(),pending=deferred();h.element('#nl-server').value='__manual__';h.element('#nlm-host').value='hostA';h.element('#nlm-pass').value='password';h.setFetch(async()=>pending.promise);
  const load=h.run('loadNodeList()');h.element('#nlm-host').value='hostB';h.element('#nlm-host').listeners.input();pending.resolve(response({ok:true,host:'hostA',inbounds:[{tag:'old',port:1234}]}));await load;
  assert.equal(h.element('#nl-body').innerHTML,'');assert.equal(h.run('nodeListSnapshot'),null);
});
test('late connection test for A cannot replace the dashboard or terminal for B',async()=>{
  const h=harness(),a=deferred();h.setFetch(async url=>url==='/api/servers'?response([serverA,serverB]):url==='/api/servers/A/test'?a.promise:url.endsWith('/test')?response({ok:true,msg:'B connected'}):response(info(url.includes('/B/')?'B dashboard':'A dashboard')));
  const selectA=h.run('select('+JSON.stringify(serverA)+')');await immediate();const selectB=h.run('select('+JSON.stringify(serverB)+')');await selectB;
  a.resolve(response({ok:true,msg:'A connected'}));await selectA;
  assert.equal(h.run('cur.id'),'B');assert.ok(h.element('#dash-content').innerHTML.includes('B dashboard'));assert.ok(!h.requests.some(r=>r.url==='/api/servers/A/info'));
});
test('successful SSH verification is not reclassified by a later local list refresh failure',async()=>{
  const h=harness();let listReads=0;
  h.setFetch(async url=>{
    if(url==='/api/servers'){
      if(++listReads>1)throw new Error('local list refresh unavailable');
      return response([serverA,serverB]);
    }
    if(url.endsWith('/test'))return response({ok:true,msg:'SSH verified'});
    if(url.endsWith('/info'))return response(info('A dashboard'));
    throw new Error('Unexpected request '+url);
  });
  await h.run('select('+JSON.stringify(serverA)+')');
  assert.equal(h.run("connectionStates.get('A')"),'connected');
  assert.equal(h.element('#summary-connection').textContent,'验证通过');
  assert.ok(h.element('#dash-content').innerHTML.includes('A dashboard'));
  // A local refresh can fail independently; it must not invalidate SSH evidence.
  await assert.rejects(h.run('loadServers()'),/无法连接面板/);
  assert.equal(h.run("connectionStates.get('A')"),'connected');
  assert.equal(h.element('#summary-connection').textContent,'验证通过');
});
test('a late SSH result updates its own network node without changing the selected server',async()=>{
  const h=harness(),a=deferred();
  h.setFetch(async url=>url==='/api/servers'?response([serverA,serverB]):
    url==='/api/servers/A/test'?a.promise:url.endsWith('/test')?response({ok:true,msg:'B connected'}):
    response(info(url.includes('/B/')?'B dashboard':'A dashboard')));
  const first=h.run('select('+JSON.stringify(serverA)+')');await immediate();
  assert.equal(h.run("connectionStates.get('A')"),'pending');
  await h.run('select('+JSON.stringify(serverB)+')');
  a.resolve(response({ok:true,msg:'A connected'}));await first;
  assert.equal(h.run("connectionStates.get('A')"),'connected');
  assert.equal(h.run("connectionStates.get('B')"),'connected');
  assert.equal(h.run('cur.id'),'B');
  assert.equal(h.element('#cur-name').textContent,'B (b.example)');
  assert.ok(h.element('#dash-content').innerHTML.includes('B dashboard'));
  assert.equal(h.element('#summary-connection').textContent,'验证通过');
  assert.ok(!h.requests.some(r=>r.url==='/api/servers/A/info'));
});
test('an older test of the same server cannot overwrite a newer success or failure',async()=>{
  for(const newestOK of [true,false]){
    const h=harness(),old=deferred();let aTests=0;
    h.setFetch(async url=>{
      if(url==='/api/servers')return response([serverA,serverB]);
      if(url==='/api/servers/A/test')return ++aTests===1?old.promise:
        response({ok:newestOK,msg:newestOK?'new A verified':'new A failure'});
      if(url.endsWith('/test'))return response({ok:true,msg:'B verified'});
      return response(info(url.includes('/B/')?'B dashboard':'new A dashboard'));
    });
    const first=h.run('select('+JSON.stringify(serverA)+')');await immediate();
    await h.run('select('+JSON.stringify(serverB)+')');
    await h.run('select('+JSON.stringify(serverA)+')');
    old.resolve(response({ok:!newestOK,msg:newestOK?'old A failure':'old A verified'}));await first;
    assert.equal(h.run('cur.id'),'A');
    assert.equal(h.run("connectionStates.get('A')"),newestOK?'connected':'error');
    assert.equal(h.element('#summary-connection').textContent,newestOK?'验证通过':'连接失败');
    assert.ok(h.element('#dash-content').innerHTML.includes(newestOK?'new A dashboard':'new A failure'));
    assert.ok(!h.element('#dash-content').innerHTML.includes('old A'));
  }
});
test('tab arrow keys wrap and Home/End keep selection, ARIA and focus together',async()=>{
  const h=harness(),tabs=h.context.document.querySelectorAll('.tab');let current=tabs[0];current.focus();
  for(const [key,page] of [['ArrowRight','term'],['End','set'],['ArrowRight','dash'],['ArrowLeft','set'],['Home','dash']]){
    let prevented=false;
    current.listeners.keydown({key,preventDefault(){prevented=true;}});await immediate();
    current=tabs.find(tab=>tab.dataset.p===page);
    assert.equal(prevented,true);
    assert.equal(h.context.document.activeElement,current);
    for(const tab of tabs){
      const selected=tab===current;
      assert.equal(tab.classList.contains('active'),selected);
      assert.equal(tab.attributes['aria-selected'],String(selected));
      assert.equal(tab.attributes.tabindex,selected?'0':'-1');
    }
    const pages=h.context.document.querySelectorAll('.page');
    assert.equal(pages.filter(panel=>panel.classList.contains('active')).length,1);
    assert.equal(h.element('#p-'+page).classList.contains('active'),true);
  }
});
test('server switch closes old WebSocket and ignores its saved callbacks',async()=>{
  const h=harness();h.run('cur='+JSON.stringify(serverA)+';openTerm()');const old=h.sockets[0],callback=old.onmessage,close=old.onclose;
  assert.ok(old.url.endsWith('?token=test-csrf-token'));old.readyState=1;old.onopen();
  h.run('resetServerView();cur='+JSON.stringify(serverB)+';openTerm()');const active=h.sockets[1];active.readyState=1;active.onopen();callback({data:'stale A output'});close();
  assert.equal(old.closed,true);assert.equal(h.run('term.writes.length'),0);assert.equal(h.element('#term-status').textContent,'已连接 b.example');
  h.events.beforeunload();assert.equal(active.closed,true);
});
test('new server is selected by returned id even if another entry shares its host',async()=>{
  const h=harness(),newServer={...serverB,id:'NEW',host:serverA.host,user:'deploy'};
  h.element('#a-name').value='new';h.element('#a-host').value=serverA.host;h.element('#a-pass').value='secret';h.setFetch(async(url,opts)=>url==='/api/servers'?(opts.method==='POST'?response({ok:true,id:'NEW'}):response([serverA,newServer])):url==='/api/nodes/protocols'?response(protocols):url.endsWith('/test')?response({ok:true,msg:'connected'}):response(info('new')));
  await h.run('addServer()');assert.equal(h.run('cur.id'),'NEW');assert.equal(h.element('#a-pass').value,'');
});
test('settings GET does not load plaintext; blanks preserve existing keys and clears are explicit',async()=>{
  const h=harness();h.setFetch(async(url,opts)=>opts.method==='POST'?response({ok:true}):response({deepseek_key_set:true,deepseek_key:'must-not-load',openai_key_set:false,anthropic_key_set:true}));
  await h.run('loadSettings()');assert.equal(h.element('#k-deepseek').value,'');assert.equal(h.element('#ks-deepseek').textContent,'已设置');
  h.element('#k-openai').value='new-key';h.element('#kc-anthropic').checked=true;await h.run('saveSettings()');
  const saved=JSON.parse(h.requests.find(r=>r.options.method==='POST').options.body);assert.deepEqual(saved,{clear_keys:['anthropic_key'],openai_key:'new-key'});
  assert.ok(!('deepseek_key' in saved));assert.equal(h.element('#k-openai').value,'');
});
test('repeated tool and deployment submissions are disabled until the job completes',async()=>{
  const h=harness();h.run('cur='+JSON.stringify(serverA)+';renderTools();nodeProtos='+JSON.stringify(protocols.protocols));
  h.setFetch(async url=>url.startsWith('/api/jobs/')?response({status:'done',output:'ok',result:{server:'A',links:[],params:{}}}):response({ok:true,job:'job1'}));
  await h.run("runTool('check_env')");await h.run("runTool('check_env')");assert.equal(h.requests.filter(r=>r.url.endsWith('/run')).length,1);assert.ok(h.element('#tools').children.every(el=>el.disabled));
  await h.timer(500);assert.ok(h.element('#tools').children.every(el=>!el.disabled));
  await h.run('nodeDeploy()');await h.run('nodeDeploy()');assert.equal(h.requests.filter(r=>r.url==='/api/nodes/deploy').length,1);assert.equal(h.element('#node-deploy').disabled,true);await h.timer(500);assert.equal(h.element('#node-deploy').disabled,false);
});
test('newly filtered tool buttons stay locked during submission and polling, then become usable after completion',async()=>{
  const h=harness(),submission=deferred();let done=false;
  const chips=h.context.document.querySelectorAll('.filter-chip'),input=h.element('#tool-filter');
  const buttons=()=>h.element('#tools').querySelectorAll('.tool');
  const runRequests=()=>h.requests.filter(r=>r.url.endsWith('/run'));
  h.run('cur='+JSON.stringify(serverA)+';renderTools()');
  h.setFetch(async url=>url.endsWith('/run')?submission.promise:
    response({status:done?'done':'running',output:done?'finished':'working'}));
  const start=buttons()[0].click();await immediate();
  assert.equal(runRequests().length,1);assert.equal(h.run("busy.has('tool-job')"),true);
  chips.find(c=>c.dataset.toolCategory==='network').click();
  assert.equal(buttons().length,2);assert.ok(buttons().every(b=>b.disabled&&b.classList.contains('busy')));
  input.value='Reality';input.listeners.input();
  assert.equal(buttons().length,1);assert.equal(buttons()[0].disabled,true);
  buttons()[0].click();assert.equal(runRequests().length,1);
  submission.resolve(response({job:'filtered-job'}));await start;
  await h.timer(500);assert.equal(h.run("busy.has('tool-job')"),true);
  input.value='Codex';input.listeners.input();assert.equal(buttons().length,0);
  chips.find(c=>c.dataset.toolCategory==='ai').click();
  assert.equal(buttons().length,1);assert.equal(buttons()[0].disabled,true);
  buttons()[0].click();assert.equal(runRequests().length,1);
  done=true;await h.timer(1000);
  assert.equal(h.run("busy.has('tool-job')"),false);
  assert.equal(buttons()[0].disabled,false);assert.equal(buttons()[0].classList.contains('busy'),false);
  assert.equal(buttons()[0].attributes['aria-disabled'],'false');
  await buttons()[0].click();assert.equal(runRequests().length,2);
  assert.equal(JSON.parse(runRequests()[1].options.body).action,'install_codex');
  await h.timer(500);assert.equal(buttons()[0].disabled,false);
});
test('downloads carry the CSRF header and save an opaque Blob instead of opening an unauthenticated API URL',async()=>{
  const h=harness();h.setFetch(async()=>({ok:true,status:200,headers:new Headers({'Content-Type':'application/octet-stream'}),blob:async()=>new Blob(['data'])}));
  await h.run("downloadFile('A','/root/a.txt')");
  assert.equal(h.requests[0].options.headers.get('X-CSRF-Token'),'test-csrf-token');
  const link=h.context.document.body.children[0];assert.match(link.href,/^blob:/);assert.equal(link.download,'a.txt');assert.equal(h.element('#pv-dl').disabled,false);
  await h.timer(1000);
});
test('failed submissions release buttons and transient polling errors keep the active task locked',async()=>{
  const h=harness();h.run('cur='+JSON.stringify(serverA)+';renderTools()');h.setFetch(async()=>response({ok:false,msg:'invalid request'},400));
  await h.run("runTool('check_env')");assert.ok(h.element('#tools').children.every(el=>!el.disabled));assert.ok(!h.run("busy.has('tool-job')"));assert.equal(h.run('pollTimer'),null);
  h.setFetch(async url=>url.includes('/jobs/')?Promise.reject(new Error('offline')):response({job:'retry-job'}));
  await h.run("runTool('check_env')");await h.timer(500);assert.ok(h.element('#tools').children.every(el=>el.disabled));assert.ok(h.element('#job-out').textContent.includes('正在重试'));
  await h.run("runTool('check_env')");assert.equal(h.requests.filter(r=>r.url.endsWith('/run')).length,2);
  h.setFetch(async()=>response({status:'done',output:'done'}));await h.timer(4000);assert.ok(h.element('#tools').children.every(el=>!el.disabled));
});
test('node ports allow privileged listeners and reject malformed numeric input',async()=>{
  const h=harness();h.run('nodeProtos='+JSON.stringify(protocols.protocols));h.setFetch(async()=>response({job:'port-job'}));
  h.element('#n-port').value='443';await h.run('nodeDeploy()');assert.equal(JSON.parse(h.requests[0].options.body).port,443);h.events.beforeunload();
  const other=harness();other.run('nodeProtos='+JSON.stringify(protocols.protocols));other.element('#n-port').value='2089abc';await other.run('nodeDeploy()');assert.equal(other.requests.length,0);assert.ok(other.element('#toast').textContent.includes('端口无效'));
});

(async()=>{
  for(const {name,fn} of tests){await fn();console.log('PASS '+name);}
  console.log(`${tests.length} frontend regression checks passed`);
})().catch(error=>{console.error(error);process.exitCode=1;});
