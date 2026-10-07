/* G-Network Clash workspace. Drafts and generated credentials stay in this page's memory. */
(function(global){
  'use strict';
  const RULE_TYPES=['DOMAIN-SUFFIX','DOMAIN','DOMAIN-KEYWORD','DOMAIN-REGEX','IP-CIDR','IP-CIDR6','SRC-IP-CIDR','SRC-IP-CIDR6','GEOIP','GEOSITE','PROCESS-NAME','PROCESS-PATH','DST-PORT','SRC-PORT','NETWORK','MATCH'];
  const GROUP_TYPES=['select','url-test','fallback','load-balance'];
  const BUILTINS=['DIRECT','REJECT'];
  const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const icon=name=>'<svg class="icon" aria-hidden="true"><use href="#i-'+name+'"></use></svg>';
  const cleanText=value=>String(value??'').trim();
  const validName=value=>Boolean(value&&value.length<=64&&!/[\x00-\x1f\x7f,]/.test(value));
  const sourceIdentity=s=>JSON.stringify([String(s.id),s.host,s.port,s.user,s.auth_type,s.credential_required===true]);
  const sourceEndpoint=s=>String(s.host||'').toLowerCase()+':'+String(s.port||22);
  const ROUTING_DOMAIN_LIMIT=128;
  const EDITORS=['source','chains','groups','rules','node-routing','dns','output'];
  function normalizeDomain(value){
    let domain=cleanText(value).toLowerCase();
    if(domain.endsWith('.'))domain=domain.slice(0,-1);
    if(!domain||domain.length>253||/[\s\x00-\x1f\x7f/:\\@?#*\[\],，;；%]/.test(domain))throw new Error('请填写纯域名，例如 example.com；不要带 https://、路径或 *。');
    try{domain=new URL('https://'+domain).hostname.toLowerCase();}catch(e){throw new Error('域名格式不正确。');}
    const labels=domain.split('.');
    if(domain.length>253||labels.length<2||labels.some(label=>!label||label.length>63||! /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))||labels.every(label=>/^\d+$/.test(label))||/^\d+$/.test(labels.at(-1)))throw new Error('请使用有效域名，不支持 IP 地址或单标签名称。');
    return domain;
  }
  function parseDomainBatch(value,existing=[]){
    const domains=[...existing],seen=new Set(domains),errors=[];let duplicates=0;
    for(const item of String(value??'').split(/[\s,，;；]+/).filter(Boolean)){
      try{const domain=normalizeDomain(item);if(seen.has(domain)){duplicates++;continue;}seen.add(domain);domains.push(domain);}catch(e){errors.push(item+'：'+e.message);}
    }
    if(domains.length>ROUTING_DOMAIN_LIMIT)errors.push('每个节点最多 '+ROUTING_DOMAIN_LIMIT+' 个域名。');
    return {domains:errors.length?[...existing]:domains,errors,duplicates};
  }
  function normalizeRouting(value){
    if(value==null)return {enabled:false,direct_domains:[],revision:0};
    if(typeof value.enabled!=='boolean'||!Number.isInteger(value.revision)||value.revision<0||!Array.isArray(value.direct_domains)||value.direct_domains.length>ROUTING_DOMAIN_LIMIT)throw new Error('节点分流状态格式不正确，请重新读取。');
    const domains=value.direct_domains.map(normalizeDomain);if(new Set(domains).size!==domains.length)throw new Error('节点分流域名状态含重复项，请重新读取。');
    return {enabled:value.enabled,direct_domains:domains,revision:value.revision};
  }
  function routingDraft(model,nodeId){
    const node=model.nodes.find(n=>n.id===nodeId&&n.available);if(!node)return null;
    if(!model.routingDrafts.has(nodeId)){const saved=normalizeRouting(node.routing);model.routingDrafts.set(nodeId,{enabled:saved.revision===0?true:saved.enabled,direct_domains:[...saved.direct_domains],saved,editRevision:0,input:'',error:'',ports:{mixed_port:7890,socks_port:10808,http_port:10809},output:null,outputSignature:null,format:'clash'});}
    return model.routingDrafts.get(nodeId);
  }
  function routingDirty(draft){return draft.enabled!==draft.saved.enabled||JSON.stringify(draft.direct_domains)!==JSON.stringify(draft.saved.direct_domains);}
  function routingSignature(draft){return JSON.stringify([draft.enabled,draft.direct_domains,draft.saved.revision,draft.ports]);}
  function routingCurrentOutput(draft){return draft?.output&&!routingDirty(draft)&&draft.outputSignature===routingSignature(draft)&&!cleanText(draft.input)?draft.output:null;}
  function routingPorts(draft){const ports={};for(const key of ['mixed_port','socks_port','http_port']){const value=Number(draft.ports[key]);if(!Number.isInteger(value)||value<1||value>65535)throw new Error('本机端口需要填写 1–65535 的整数。');ports[key]=value;}if(ports.socks_port===ports.http_port)throw new Error('Xray 的 SOCKS 与 HTTP 本机端口不能相同。');return ports;}
  function routingTouch(draft){draft.editRevision++;draft.error='';draft.output=null;draft.outputSignature=null;}
  function initialSources(servers){const seen=new Set(),ids=[];for(const s of servers){const address=sourceEndpoint(s);if(seen.has(address))continue;seen.add(address);ids.push(String(s.id));if(ids.length===16)break;}return new Set(ids);}
  function createModel(){
    return {servers:[],sourceIds:new Set(),nodes:[],selected:new Set(),snapshot:null,readAt:null,sourceResults:[],revision:0,serial:3,
      profile:{name:'G-Network',mixed_port:7890,mode:'rule'},chains:[],advanced:{},savedProfile:null,
      groups:[{id:'g1',name:'节点选择',type:'select',members:['group:g2','group:g3','DIRECT'],autoNodes:true,url:'https://www.gstatic.com/generate_204',interval:300},{id:'g2',name:'自动选择',type:'url-test',members:[],autoNodes:true,url:'https://www.gstatic.com/generate_204',interval:300},{id:'g3',name:'故障转移',type:'fallback',members:[],autoNodes:true,url:'https://www.gstatic.com/generate_204',interval:300}],
      rules:[{id:'r1',type:'IP-CIDR',value:'10.0.0.0/8',target:'DIRECT'},{id:'r2',type:'IP-CIDR',value:'172.16.0.0/12',target:'DIRECT'},{id:'r3',type:'IP-CIDR',value:'192.168.0.0/16',target:'DIRECT'},{id:'r4',type:'MATCH',value:'',target:'group:g1'}],output:null,outputRevision:null,routingDrafts:new Map(),routingNode:null};
  }
  function selectedNodes(model){return model.nodes.filter(n=>n.available===true&&model.selected.has(String(n.id)));}
  function syncMembers(model){
    const ids=new Set(selectedNodes(model).map(n=>'node:'+n.id)),groups=new Set(model.groups.map(g=>'group:'+g.id));
    model.chains.filter(c=>c.enabled!==false).forEach(c=>ids.add('chain:'+c.id));
    model.groups.forEach(g=>{
      g.members=g.members.filter(m=>BUILTINS.includes(m)||ids.has(m)||(groups.has(m)&&m!=='group:'+g.id));
      if(g.autoNodes)g.members=[...g.members,...[...ids].filter(id=>!g.members.includes(id))];
    });
  }
  function touch(model){model.revision++;}
  function targetName(model,target){if(BUILTINS.includes(target))return target;if(target.startsWith('group:'))return cleanText(model.groups.find(g=>'group:'+g.id===target)?.name);if(target.startsWith('chain:'))return cleanText(model.chains.find(c=>'chain:'+c.id===target&&c.enabled!==false)?.name);return model.nodes.find(n=>'node:'+n.id===target)?.name||'';}
  function validate(model){
    const errors=[],nodes=selectedNodes(model),names=new Set(BUILTINS.concat(['GLOBAL']));
    if(!model.snapshot)errors.push('先读取服务器节点，再生成配置。');
    if(!nodes.length)errors.push('至少选择一个可导出的节点。');
    if(!validName(cleanText(model.profile.name)))errors.push('配置名称需要 1–64 个字符，不能含逗号或换行。');
    if(!Number.isInteger(Number(model.profile.mixed_port))||Number(model.profile.mixed_port)<1||Number(model.profile.mixed_port)>65535)errors.push('本机混合端口须为 1–65535。');
    if(nodes.length>128)errors.push('每份配置最多选择 128 个节点。');
    if(model.groups.length>16)errors.push('每份配置最多 16 个策略组。');
    if(model.rules.length>200)errors.push('每份配置最多 200 条路由规则。');
    if(model.chains.length>16)errors.push('每份配置最多 16 条链式代理。');
    model.chains.forEach(c=>{if(c.enabled===false)return;const name=cleanText(c.name);if(!validName(name)||names.has(name))errors.push('链式名称需要唯一且不能含逗号或换行：'+name);names.add(name);if(!Array.isArray(c.hops)||c.hops.length<2||c.hops.length>8)errors.push('每条链需要 2–8 跳。');else if(c.hops.some(id=>!nodes.some(n=>n.id===id)))errors.push('“'+name+'”含未选中或已失效节点，请重新选择每一跳。');else if(new Set(c.hops).size!==c.hops.length)errors.push('“'+name+'”不能重复使用同一个节点。');});
    const dns=model.advanced.dns;if(dns?.enable&&dns['respect-rules']===true&&(!Array.isArray(dns['proxy-server-nameserver'])||!dns['proxy-server-nameserver'].length))errors.push('DNS 跟随路由时，需要填写节点域名解析服务器。');
    model.groups.forEach(g=>{
      const name=cleanText(g.name);
      if(!validName(name))errors.push('策略组名称需要 1–64 个字符，不能含逗号或换行。');
      if(names.has(name))errors.push('策略组名称不能重名：'+name);names.add(name);
      if(!GROUP_TYPES.includes(g.type))errors.push('策略组类型不支持。');
      if(!g.members.length)errors.push('“'+name+'”至少需要一个成员。');
      if(g.members.some(m=>!targetName(model,m)||m==='group:'+g.id))errors.push('“'+name+'”含无效或自身引用。');
      if(g.type!=='select'){
        try{const url=new URL(g.url);if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.hash||/[\x00-\x1f\x7f]/.test(g.url)||g.url.length>1024)throw new Error();}catch(e){errors.push('“'+name+'”需填写有效的 HTTP / HTTPS 测试地址。');}
        if(g.interval!==''&&(!Number.isInteger(Number(g.interval))||Number(g.interval)<10||Number(g.interval)>86400))errors.push('策略测试间隔须为 10–86400 秒。');
      }
      if(g.type==='url-test'&&g.tolerance!==undefined&&g.tolerance!==''&&(!Number.isInteger(Number(g.tolerance))||Number(g.tolerance)<0||Number(g.tolerance)>3000))errors.push('测速容差须为 0–3000 毫秒。');
      if(g.type==='load-balance'&&g.strategy&&!['consistent-hashing','round-robin'].includes(g.strategy))errors.push('负载均衡策略不支持。');
    });
    const visiting=new Set(),visited=new Set();
    function visit(id){if(visiting.has(id))return true;if(visited.has(id))return false;visiting.add(id);const g=model.groups.find(g=>g.id===id);if(g?.members.some(m=>m.startsWith('group:')&&visit(m.slice(6))))return true;visiting.delete(id);visited.add(id);return false;}
    if(model.groups.some(g=>visit(g.id)))errors.push('策略组存在循环引用，请调整成员。');
    const matches=model.rules.filter(r=>r.type==='MATCH');
    if(matches.length!==1||model.rules.at(-1)?.type!=='MATCH')errors.push('配置须保留唯一一条末尾 MATCH 兜底规则。');
    model.rules.forEach((r,i)=>{
      if(!RULE_TYPES.includes(r.type))errors.push('第 '+(i+1)+' 条规则类型不支持。');
      if(r.type!=='MATCH'&&(!cleanText(r.value)||r.value.length>2048||/[\x00-\x1f\x7f,]/.test(r.value)))errors.push('第 '+(i+1)+' 条规则需填写有效匹配内容。');
      if(!targetName(model,r.target))errors.push('第 '+(i+1)+' 条规则需选择有效策略。');
    });
    return [...new Set(errors)];
  }
  function moveRule(model,id,direction){
    const index=model.rules.findIndex(r=>r.id===id),next=index+direction;
    if(index<0||next<0||next>=model.rules.length||model.rules[index].type==='MATCH'||model.rules[next].type==='MATCH')return false;
    [model.rules[index],model.rules[next]]=[model.rules[next],model.rules[index]];touch(model);return true;
  }
  function applyTemplate(model,template){
    if(!['lan','cn','global'].includes(template))throw new Error('路由模板不支持。');
    const current=model.rules.find(r=>r.type==='MATCH')?.target;
    const fallback=current&&targetName(model,current)?current:model.groups[0]?'group:'+model.groups[0].id:'DIRECT';
    const ranges=template==='global'?[]:['127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'];
    model.rules=ranges.map(value=>({id:'r'+(++model.serial+10),type:'IP-CIDR',value,target:'DIRECT',no_resolve:true}));
    if(template==='cn')model.rules.push({id:'r'+(++model.serial+10),type:'GEOIP',value:'CN',target:'DIRECT',no_resolve:false});
    model.rules.push({id:'r'+(++model.serial+10),type:'MATCH',value:'',target:fallback});touch(model);
  }
  function exportDraft(model){
    const errors=validate(model);if(errors.length)throw new Error(errors[0]);
    const resolveTarget=value=>value.startsWith('node:')?value.slice(5):targetName(model,value);
    return {snapshot_id:model.snapshot,node_ids:selectedNodes(model).map(n=>String(n.id)),profile:{name:cleanText(model.profile.name),mixed_port:Number(model.profile.mixed_port),mode:'rule',template:'custom',fallback:resolveTarget(model.rules.at(-1).target),
      groups:model.groups.map(g=>({name:cleanText(g.name),type:g.type,members:g.members.map(m=>m.startsWith('node:')?m.slice(5):targetName(model,m)),...(g.type==='select'?{}:{url:g.url,...(g.interval===''?{}:{interval:Number(g.interval)})}),...(g.type==='url-test'&&g.tolerance!==undefined&&g.tolerance!==''?{tolerance:Number(g.tolerance)}:{}),...(g.type==='load-balance'&&g.strategy?{strategy:g.strategy}:{})})),
      rules:model.rules.map(r=>({type:r.type,value:r.type==='MATCH'?'':cleanText(r.value),target:resolveTarget(r.target),...(['IP-CIDR','IP-CIDR6','SRC-IP-CIDR','SRC-IP-CIDR6','GEOIP'].includes(r.type)?{no_resolve:r.no_resolve!==false}:{})})),...(model.chains.length?{chains:model.chains.map(c=>({name:cleanText(c.name),hops:[...c.hops],enabled:c.enabled!==false}))}:{}),...(Object.keys(model.advanced).length?{advanced:JSON.parse(JSON.stringify(model.advanced))}:{})}};
  }
  function acceptCatalog(model,data){
    if(!data||typeof data.snapshot_id!=='string'||!data.snapshot_id||!Array.isArray(data.nodes)||data.nodes.length>256)throw new Error('节点读取结果格式不正确，请重新读取。');
    const ids=new Set();
    const nodes=data.nodes.map(n=>{
      if(!n||typeof n.id!=='string'||!n.id||ids.has(n.id)||(!['import','saved'].includes(n.origin)&&!model.sourceIds.has(String(n.server_id))))throw new Error('节点来源或身份不正确，请重新读取。');
      ids.add(n.id);return {id:n.id,origin:n.origin||'server',server_id:String(n.server_id||''),server_name:String(n.server_name||(['import','saved'].includes(n.origin)?'本机配置':'服务器')),host:String(n.host||''),name:String(n.name||n.tag||'节点'),protocol:String(n.protocol||n.kind||'未知协议'),port:String(n.port||''),available:n.available===true,compatibility:String(n.compatibility||''),notice:String(n.notice||''),routing:normalizeRouting(n.routing)};
    });
    model.nodes=nodes;model.snapshot=data.snapshot_id;model.sourceResults=Array.isArray(data.servers)?data.servers:[];model.readAt=new Date();
    model.routingDrafts.clear();model.routingNode=nodes.find(n=>n.available)?.id||null;
    model.selected=new Set(nodes.filter(n=>n.available).slice(0,128).map(n=>n.id));model.output=null;model.outputRevision=null;syncMembers(model);touch(model);
  }
  function currentOutput(model){return model.output&&model.outputRevision===model.revision?model.output:null;}
  function acceptStudioCatalog(model,data,mode='merge'){
    const staged=createModel();staged.sourceIds=new Set(model.sourceIds);staged.servers=model.servers;acceptCatalog(staged,data);
    if(mode==='merge'){
      if(model.nodes.some(n=>!staged.nodes.some(next=>next.id===n.id)))throw new Error('现有节点身份已失效，请重新读取来源后重试；当前草稿保留。');
      model.nodes=staged.nodes;model.snapshot=staged.snapshot;model.readAt=staged.readAt;model.sourceResults=staged.sourceResults;
      const ids=Array.isArray(data.imported_ids)?data.imported_ids:[];ids.forEach(id=>{if(model.nodes.some(n=>n.id===id&&n.available)&&model.selected.size<128)model.selected.add(id);});
      for(const [id,draft] of model.routingDrafts){const next=model.nodes.find(n=>n.id===id);if(!next||JSON.stringify(next.routing)!==JSON.stringify(draft.saved))model.routingDrafts.delete(id);}
      model.output=null;model.outputRevision=null;syncMembers(model);touch(model);return;
    }
    const p=data.profile;if(!p||!Array.isArray(p.groups)||!Array.isArray(p.rules))throw new Error('完整配置缺少策略组或规则，当前草稿保留。');
    const nodeIds=new Set(staged.nodes.map(n=>n.id));
    staged.profile={name:cleanText(p.name)||'G-Network',mixed_port:p.mixed_port??7890,mode:'rule'};
    staged.chains=(p.chains||[]).map((c,i)=>({id:'c'+(i+1),name:String(c.name||''),hops:Array.isArray(c.hops)?[...c.hops]:[],enabled:c.enabled!==false}));
    staged.groups=p.groups.map((g,i)=>({id:'g'+(i+1),name:String(g.name||''),type:g.type||'select',members:[],autoNodes:false,url:g.url||'https://www.gstatic.com/generate_204',interval:g.interval??300,...(g.tolerance!==undefined?{tolerance:g.tolerance}:{}),...(g.strategy?{strategy:g.strategy}:{})}));
    const ref=value=>{if(BUILTINS.includes(value))return value;if(nodeIds.has(value))return 'node:'+value;const group=staged.groups.find(g=>g.name===value);if(group)return 'group:'+group.id;const chain=staged.chains.find(c=>c.name===value);if(chain)return 'chain:'+chain.id;throw new Error('配置含无法识别的策略引用：'+String(value));};
    staged.groups.forEach((g,i)=>{if(!Array.isArray(p.groups[i].members))throw new Error('配置的策略组成员格式不正确。');g.members=p.groups[i].members.map(ref);});
    staged.rules=p.rules.map((r,i)=>({id:'r'+(i+1),type:String(r.type||''),value:String(r.value||''),target:ref(r.target),...(r.no_resolve!==undefined?{no_resolve:r.no_resolve}:{})}));
    if(p.advanced!=null&&(typeof p.advanced!=='object'||Array.isArray(p.advanced)))throw new Error('高级配置格式不正确。');staged.advanced=JSON.parse(JSON.stringify(p.advanced||{}));staged.serial=Math.max(staged.groups.length,staged.chains.length,staged.rules.length)+10;
    const errors=validate(staged);if(errors.length)throw new Error('导入配置需要调整：'+errors[0]);
    Object.assign(model,staged);model.savedProfile=null;touch(model);
  }
  function appendDomainRules(model,text,target){
    if(!targetName(model,target))throw new Error('先选择有效的目标策略。');
    const parsed=parseDomainBatch(text);if(parsed.errors.length)throw new Error(parsed.errors[0]);if(!parsed.domains.length)throw new Error('先填写要添加的域名。');
    const added=parsed.domains.filter(value=>!model.rules.some(r=>r.type==='DOMAIN-SUFFIX'&&r.value===value&&r.target===target));if(model.rules.length+added.length>200)throw new Error('规则总数不能超过 200 条。');
    const at=Math.max(0,model.rules.findIndex(r=>r.type==='MATCH'));model.rules.splice(at,0,...added.map(value=>({id:'r'+(++model.serial+10),type:'DOMAIN-SUFFIX',value,target})));if(added.length)touch(model);return added.length;
  }
  const SERVICE_PRESETS={ai:{name:'AI 服务',domains:['openai.com','chatgpt.com','oaistatic.com','oaiusercontent.com','anthropic.com','claude.ai','gemini.google.com']},stream:{name:'流媒体',domains:['youtube.com','googlevideo.com','ytimg.com','netflix.com','nflxvideo.net','nflximg.net','disneyplus.com']}};
  function applyServicePreset(model,key){
    const preset=SERVICE_PRESETS[key];if(!preset)throw new Error('服务预设不存在。');let group=model.groups.find(g=>g.name===preset.name);
    const target=group?'group:'+group.id:null,needed=preset.domains.filter(value=>!target||!model.rules.some(r=>r.type==='DOMAIN-SUFFIX'&&r.value===value&&r.target===target)).length;if(model.rules.length+needed>200)throw new Error('规则总数不能超过 200 条。');
    if(!group){if(model.groups.length>=16)throw new Error('策略组总数不能超过 16 个。');group={id:'g'+(++model.serial),name:preset.name,type:'select',members:selectedNodes(model).map(n=>'node:'+n.id),autoNodes:true,url:'https://www.gstatic.com/generate_204',interval:300};model.groups.push(group);syncMembers(model);touch(model);}
    return appendDomainRules(model,preset.domains.join('\n'),'group:'+group.id);
  }
  function splitDnsTemplate(){return {enable:true,listen:'127.0.0.1:1053',ipv6:false,'enhanced-mode':'fake-ip','fake-ip-range':'198.18.0.1/16','respect-rules':true,'default-nameserver':['223.5.5.5','119.29.29.29'],nameserver:['https://1.1.1.1/dns-query'],'proxy-server-nameserver':['https://223.5.5.5/dns-query','https://doh.pub/dns-query'],'direct-nameserver':['https://223.5.5.5/dns-query','https://doh.pub/dns-query'],'fake-ip-filter':['*.lan','*.local','localhost']};}
  function parseAdvanced(text){
    const value=JSON.parse(text);if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('高级配置需要 JSON 对象。');
    if(['proxies','proxy-groups','rules','proxy-providers','rule-providers','__proto__','constructor','prototype'].some(key=>Object.hasOwn(value,key)))throw new Error('高级设置不能覆写节点、策略组或路由。');
    const dns=value.dns;if(dns!==undefined){if(!dns||typeof dns!=='object'||Array.isArray(dns))throw new Error('dns 需要 JSON 对象。');for(const key of ['nameserver','default-nameserver','proxy-server-nameserver','direct-nameserver'])if(dns[key]!==undefined&&(!Array.isArray(dns[key])||dns[key].some(item=>typeof item!=='string')))throw new Error(key+' 需要 DNS 地址数组。');}
    return value;
  }

  let host=null,model=createModel(),root=null,activeEditor='source',readEpoch=0,exportEpoch=0,routeEpoch=0,routeBusy=null,focusEpoch=0,reading=false,generating=false,destroyed=false,lastError='';
  let studioEpoch=0,studioBusy=false,importPreview=null,importText='',importFormat='auto',profiles=[],studioMessage='',studioWarnings=[];
  const blobUrls=new Set();
  const el=id=>global.document.getElementById(id);
  const options=(values,value)=>values.map(([id,name])=>'<option value="'+escape(id)+'" '+(id===value?'selected':'')+'>'+escape(name)+'</option>').join('');
  function targets(allowNodes=true){return model.groups.map(g=>['group:'+g.id,g.name]).concat(model.chains.filter(c=>c.enabled!==false).map(c=>['chain:'+c.id,c.name+' · 链式出口']),BUILTINS.map(v=>[v,v]),allowNodes?selectedNodes(model).map(n=>['node:'+n.id,n.name+' · '+n.protocol+' :'+n.port+' · '+n.server_name]):[]);}
  function shell(){return `<div class="cw-workflow" aria-label="配置步骤"><span><b>01</b>选择节点 <small id="cw-step-nodes">0 个</small></span><i></i><span><b>02</b>编排策略 <small id="cw-step-groups">3 组</small></span><i></i><span><b>03</b>生成配置 <small id="cw-step-output">待生成</small></span></div>
    <div class="cw-layout"><aside class="cw-panel cw-library" aria-labelledby="cw-library-title"><div class="cw-panel-head"><div><span class="eyebrow">NODE LIBRARY</span><h3 id="cw-library-title">你的节点库</h3></div><span class="cw-orb">${icon('network')}</span></div>
      <div class="cw-source-area"><div class="cw-label-row"><strong>读取来源</strong><button type="button" class="cw-text-btn" id="cw-source-all">选择全部</button></div><div id="cw-sources" class="cw-sources"></div><button type="button" class="btn btn-p cw-read-btn" id="cw-read">${icon('refresh')}读取所选服务器节点</button><div id="cw-read-status" class="cw-read-status" role="status" aria-live="polite">选择已保存服务器，再读取现有节点。</div><div id="cw-source-results" class="cw-source-results"></div></div>
      <div class="cw-node-area"><label class="cw-search" for="cw-node-search">${icon('search')}<input id="cw-node-search" type="search" autocomplete="off" placeholder="搜索节点、协议或来源…"></label><div class="cw-label-row"><span id="cw-node-count">还未读取节点</span><div><button type="button" class="cw-text-btn" id="cw-node-all">选中可用节点</button><button type="button" class="cw-text-btn" id="cw-node-none">清空</button></div></div><div id="cw-nodes" class="cw-nodes"></div></div>
      <div class="cw-library-note">${icon('shield')}<p>仅读取已部署节点。来源状态是本次读取结果，不代表公网测速。</p></div></aside>
    <section class="cw-panel cw-builder" aria-label="配置编辑器"><div class="cw-builder-heading"><div><span class="eyebrow">CONFIGURATION STUDIO</span><h3>把节点，编排成你的网络</h3></div><span class="cw-state" id="cw-state" role="status" aria-live="polite">等待节点</span></div><div class="cw-editor-tabs cw-studio-tabs" role="tablist" aria-label="Clash 配置编辑步骤">${[['source','file','配置来源'],['chains','network','链式代理'],['groups','cube','策略组'],['rules','activity','路由规则'],['node-routing','shield','节点分流'],['dns','settings','DNS 与端口'],['output','download','生成与保存']].map(([key,symbol,title])=>`<button type="button" class="${key==='source'?'active':''}" id="cw-tab-${key}" data-cw-tab="${key}" role="tab" aria-selected="${key==='source'}" tabindex="${key==='source'?0:-1}" aria-controls="cw-editor-${key}">${icon(symbol)}${title}${key==='groups'?'<span id="cw-group-count">3</span>':key==='rules'?'<span id="cw-rule-count">4</span>':''}</button>`).join('')}</div>
      <div id="cw-editor-source" class="cw-editor" role="tabpanel" aria-labelledby="cw-tab-source"><div id="cw-studio-source"></div></div>
      <div id="cw-editor-chains" class="cw-editor" role="tabpanel" aria-labelledby="cw-tab-chains" hidden><div class="cw-section-head"><div><span class="eyebrow">MULTI-HOP / NETWORK</span><h4>让每一跳，各司其职</h4><p>连接按从左到右的顺序建立；最后一跳是访问网站的出口。</p></div><button type="button" class="btn btn-g" id="cw-add-chain">${icon('plus')}新建链式</button></div><div id="cw-chains"></div><div class="cw-inline-note">${icon('network')}链式出口可加入策略组或用作规则目标。启用的链需要 2–8 个不同的已选节点。</div></div>
      <div id="cw-editor-groups" class="cw-editor" role="tabpanel" aria-labelledby="cw-tab-groups"><div class="cw-section-head"><div><h4>策略组</h4><p>手动切换、自动测速与故障转移，由你组合。</p></div><button type="button" class="btn btn-g" id="cw-add-group">${icon('plus')}新建策略组</button></div><div id="cw-groups" class="cw-groups"></div><div class="cw-inline-note">${icon('network')}选择的节点自动加入默认组；手动调整成员后，该组按你的选择保留。</div></div>
      <div id="cw-editor-rules" class="cw-editor" role="tabpanel" aria-labelledby="cw-tab-rules" hidden><div class="cw-section-head"><div><h4>路由规则</h4><p>按从上到下的顺序匹配，MATCH 始终保留在末尾。</p></div><button type="button" class="btn btn-g" id="cw-add-rule">${icon('plus')}添加规则</button></div><div class="cw-bulk-rules"><div class="cw-label-row"><strong>批量添加域名</strong><span>追加到末尾兜底之前</span></div><textarea id="cw-bulk-domains" rows="3" spellcheck="false" placeholder="example.com&#10;another.example"></textarea><div class="cw-bulk-actions"><select id="cw-bulk-target" aria-label="批量域名目标策略"></select><button type="button" class="btn btn-g" id="cw-add-domain-rules">${icon('plus')}添加域名规则</button></div><div class="cw-service-presets"><span>服务快捷分组</span><button type="button" class="cw-template-btn" data-cw-service="ai">AI 服务</button><button type="button" class="cw-template-btn" data-cw-service="stream">流媒体</button><small>添加常见域名与独立选择组，保留现有规则；可继续补充域名。</small></div></div><div class="cw-template-bar"><div><strong>路由快捷模板</strong><span>应用会替换当前路由规则，保留末尾默认策略。</span></div><div class="cw-template-actions"><button type="button" class="cw-template-btn" data-cw-template="lan">应用局域网直连</button><button type="button" class="cw-template-btn" data-cw-template="cn">应用国内 + 局域网直连</button><button type="button" class="cw-template-btn" data-cw-template="global">应用全部走所选策略</button></div><p>国内模板需要客户端 GeoIP 地理库；未配置时可先用局域网模板。</p></div><div class="cw-rule-legend"><span>匹配类型 / 内容</span><span>流量去向</span><span>调整顺序</span></div><div id="cw-rules" class="cw-rules"></div><div class="cw-inline-note">${icon('shield')}全局规则在客户端的规则模式下生效。节点分流名单保存在独立专属配置中。</div></div>
      <div id="cw-editor-node-routing" class="cw-editor cw-routing-editor" role="tabpanel" aria-labelledby="cw-tab-node-routing" hidden><div id="cw-node-routing"></div></div>
      <div id="cw-editor-dns" class="cw-editor" role="tabpanel" aria-labelledby="cw-tab-dns" hidden><div id="cw-dns"></div></div>
      <div id="cw-editor-output" class="cw-editor" role="tabpanel" aria-labelledby="cw-tab-output" hidden><div class="cw-section-head"><div><h4>一份配置，带走整张网络</h4><p>选中的全部节点、策略组与路由，一次导入。</p></div><span class="cw-format-tag">YAML / UTF-8</span></div><div class="cw-profile-fields"><label>配置名称<input id="cw-profile-name" type="text" maxlength="64" autocomplete="off" value="G-Network"></label></div><div class="cw-export-summary" id="cw-export-summary"></div><button type="button" class="btn btn-p cw-generate" id="cw-generate">${icon('spark')}生成完整配置</button><div class="cw-validation" id="cw-validation" role="status" aria-live="polite"></div><div id="cw-output" class="cw-output"></div></div>
      <footer class="cw-builder-footer"><span id="cw-footer-note">${icon('shield')}本机保存可在下次继续编辑</span><button type="button" class="cw-text-btn" id="cw-next">下一步：链式代理 ${icon('arrow')}</button></footer></section></div>`;}
  function renderSources(){
    el('cw-sources').innerHTML=model.servers.length?model.servers.map(s=>`<label class="cw-source ${model.sourceIds.has(String(s.id))?'selected':''}"><input type="checkbox" data-cw-source="${escape(s.id)}" ${model.sourceIds.has(String(s.id))?'checked':''}><span class="cw-source-icon">${icon('server')}</span><span><strong>${escape(s.name)}</strong><small>${escape(s.host)} · :${escape(s.port)}</small></span>${s.credential_required?'<span class="cw-mini-status">待补凭据</span>':''}</label>`).join(''):'<div class="cw-empty">'+icon('server')+'<strong>从一台服务器开始</strong><p>先在左侧添加 SSH 连接，再读取已部署节点。</p></div>';
    el('cw-read').disabled=reading||generating||!model.sourceIds.size;
  }
  function renderStudioSource(){
    const preview=importPreview,disabled=studioBusy?'disabled':'';
    el('cw-studio-source').innerHTML=`<div class="cw-section-head"><div><span class="eyebrow">SOURCE / NETWORK LIBRARY</span><h4>从链接，到一张完整网络</h4><p>读入服务器、分享链接或本地 YAML，继续编辑你自己的配置。</p></div><span class="cw-format-tag">LOCAL STUDIO</span></div><div class="cw-source-intro"><div>${icon('server')}<strong>你的服务器</strong><p>左侧选择已保存的 SSH 连接，再读取已有节点。</p><button type="button" class="cw-text-btn" id="cw-studio-read" ${disabled}>读取所选服务器 ${icon('arrow')}</button></div><label for="cw-import-file">${icon('file')}<strong>已有配置</strong><p>上传 YAML 还原节点、链式、策略组与支持的规则。</p><span class="cw-file-label">选择 YAML / TXT 文件</span><input id="cw-import-file" type="file" accept=".yaml,.yml,.txt" ${disabled}></label></div><div class="cw-import-box"><div class="cw-label-row"><strong>粘贴节点或配置</strong><select id="cw-import-format" aria-label="导入文本类型" ${disabled}>${options([['auto','自动识别'],['links','链接 / Base64 订阅'],['yaml','完整 YAML 配置']],importFormat)}</select></div><textarea id="cw-import-text" rows="6" spellcheck="false" autocomplete="off" placeholder="vless://…&#10;vmess://…&#10;也可以粘贴 base64 订阅内容或 YAML" ${disabled}>${escape(importText)}</textarea><div class="cw-import-actions"><span>内容仅在本机解析，不抓取远程订阅。</span><button type="button" class="btn btn-p" id="cw-import-preview" ${disabled}>${icon('search')}${studioBusy?'正在处理…':'解析并预览'}</button></div></div>${preview?`<div class="cw-import-preview"><div class="cw-label-row"><strong>导入预览</strong><span>${escape(preview.source_format||'配置')}</span></div><div class="cw-import-metrics">${[['node_count','节点'],['chain_count','链式'],['group_count','策略组'],['rule_count','规则']].map(([key,title])=>`<span><b>${Number(preview[key])||0}</b>${title}</span>`).join('')}</div><div class="cw-preview-node-list">${(preview.nodes||[]).map(n=>`<span><b>${escape(n.name||'节点')}</b><small>${escape(n.protocol||n.type||'')} · ${escape(n.host||n.server||'')}:${escape(n.port||'')}</small></span>`).join('')}</div>${[...(preview.errors||[]),...(preview.warnings||[])].length?'<ul class="cw-warnings">'+[...(preview.errors||[]),...(preview.warnings||[])].map(v=>'<li>'+escape(v)+'</li>').join('')+'</ul>':''}${preview.omitted_fields?.length?'<p class="cw-import-omitted">暂不支持的配置项：'+preview.omitted_fields.map(escape).join('、')+'</p>':''}<div class="cw-output-actions"><button type="button" class="btn btn-p" id="cw-import-merge" ${disabled}>仅合并节点</button><button type="button" class="btn btn-g" id="cw-import-replace" ${disabled||!preview.can_replace?'disabled':''}>作为完整配置编辑</button></div><p class="cw-local-notice">${icon('shield')}合并保留现有分组、规则与独立节点名单；完整编辑会替换当前全局草稿。</p></div>`:''}<div id="cw-studio-message" class="cw-studio-message" role="status" aria-live="polite">${escape(studioMessage)}</div>${studioWarnings.length?'<ul class="cw-warnings">'+studioWarnings.map(v=>'<li>'+escape(v)+'</li>').join('')+'</ul>':''}<div class="cw-profile-library"><div class="cw-label-row"><strong>本机已保存配置</strong><button type="button" class="cw-text-btn" id="cw-profiles-refresh" ${disabled}>${icon('refresh')}读取列表</button></div><div>${profiles.length?profiles.map(p=>`<article class="cw-saved-profile"><div><strong>${escape(p.name)}</strong><small>${Number(p.node_count)||0} 节点 · ${Number(p.chain_count)||0} 链式 · ${Number(p.rule_count)||0} 规则</small></div><button type="button" class="btn btn-g" data-cw-profile-open="${escape(p.id)}" ${disabled}>继续编辑</button><button type="button" class="icon-btn danger" data-cw-profile-delete="${escape(p.id)}" ${disabled} aria-label="删除本机配置 ${escape(p.name)}">${icon('trash')}</button></article>`).join(''):'<p class="cw-muted-copy">点击读取列表查看之前保存的配置；生成页可以将当前配置加密保存于本机。</p>'}</div></div>`;
  }
  function renderChains(){
    const nodes=selectedNodes(model);
    el('cw-chains').innerHTML=model.chains.length?model.chains.map((c,index)=>`<article class="cw-chain ${c.enabled===false?'cw-chain-disabled':''}"><div class="cw-chain-heading"><span class="cw-group-number">${String(index+1).padStart(2,'0')}</span><input type="text" data-cw-chain-field="name" data-id="${escape(c.id)}" value="${escape(c.name)}" maxlength="64" aria-label="链式代理名称"><label><input type="checkbox" data-cw-chain-field="enabled" data-id="${escape(c.id)}" ${c.enabled!==false?'checked':''}>启用</label><button type="button" class="icon-btn danger" data-cw-chain-delete="${escape(c.id)}" aria-label="删除链式 ${escape(c.name)}">${icon('trash')}</button></div><div class="cw-chain-path"><span class="cw-chain-origin">${icon('desktop')}本机</span>${c.hops.map((id,hop)=>`<div class="cw-chain-hop"><span class="cw-hop-caption">${hop===c.hops.length-1?'出口节点':'第 '+(hop+1)+' 跳'}</span><select data-cw-hop-chain="${escape(c.id)}" data-index="${hop}" aria-label="${escape(c.name)} 第 ${hop+1} 跳">${!nodes.some(n=>n.id===id)?'<option value="'+escape(id)+'">节点未选中或已失效</option>':''}${options(nodes.map(n=>[n.id,n.name+' · '+n.protocol]),id)}</select><div><button type="button" class="cw-text-btn" data-cw-hop-move="-1" data-chain="${escape(c.id)}" data-index="${hop}" ${hop===0?'disabled':''} aria-label="前移第 ${hop+1} 跳">${icon('up')}</button><button type="button" class="cw-text-btn cw-down" data-cw-hop-move="1" data-chain="${escape(c.id)}" data-index="${hop}" ${hop===c.hops.length-1?'disabled':''} aria-label="后移第 ${hop+1} 跳">${icon('up')}</button><button type="button" class="cw-text-btn" data-cw-hop-remove="${hop}" data-chain="${escape(c.id)}" ${c.hops.length<=2?'disabled':''} aria-label="移除第 ${hop+1} 跳">${icon('close')}</button></div></div>`).join('')}<button type="button" class="cw-chain-add" data-cw-hop-add="${escape(c.id)}" ${c.hops.length>=8?'disabled':''}>${icon('plus')}增加一跳</button></div></article>`).join(''):'<div class="cw-output-empty">'+icon('network')+'<strong>给出口，多一条抵达路径</strong><p>选中至少两个节点，建立中转到出口的连接顺序。</p></div>';
  }
  function renderDns(){
    const dns=model.advanced.dns||{},fields=[['nameserver','常规 DNS'],['default-nameserver','启动解析 · IP 地址'],['proxy-server-nameserver','节点域名解析'],['direct-nameserver','直连域名解析']];
    el('cw-dns').innerHTML=`<div class="cw-section-head"><div><span class="eyebrow">DNS / LOCAL CONNECTION</span><h4>解析与接入，同样清晰</h4><p>高级设置随完整配置导出；默认沿用客户端的 DNS。</p></div><button type="button" class="btn btn-g" id="cw-dns-template">应用本机分流 DNS</button></div><div class="cw-dns-card"><label class="cw-routing-toggle"><input type="checkbox" data-cw-dns-field="enable" ${dns.enable===true?'checked':''}><span><strong>在配置中启用 DNS</strong><small>客户端可能覆盖配置内 DNS；导入后请核对客户端设置。</small></span></label><div class="cw-dns-basics"><label>混合代理端口<input id="cw-mixed-port" type="number" min="1" max="65535" value="${escape(model.profile.mixed_port)}" inputmode="numeric"></label><label>本机监听地址<input data-cw-dns-field="listen" type="text" placeholder="127.0.0.1:1053" value="${escape(dns.listen||'')}"></label><label>解析模式<select data-cw-dns-field="enhanced-mode">${options([['','沿用默认'],['fake-ip','Fake IP'],['redir-host','真实 IP']],dns['enhanced-mode']||'')}</select></label><label><input type="checkbox" data-cw-dns-field="respect-rules" ${dns['respect-rules']===true?'checked':''}>DNS 连接跟随路由</label><label><input type="checkbox" data-cw-dns-field="ipv6" ${dns.ipv6===true?'checked':''}>返回 IPv6 结果</label></div><div class="cw-dns-fields">${fields.map(([key,title])=>`<label>${title}<textarea rows="3" data-cw-dns-list="${key}" spellcheck="false" placeholder="一行一个 DNS 地址">${escape((dns[key]||[]).join('\n'))}</textarea></label>`).join('')}</div><p class="cw-muted-copy">启用 DNS 跟随路由时，必须配置节点域名解析服务器，避免建立代理连接时循环依赖。</p></div><details class="cw-advanced-json"><summary>${icon('code')}完整高级配置 <span>导入的 DNS / Sniffer / TUN 等内容保留在这里</span></summary><textarea id="cw-advanced-json" rows="12" spellcheck="false" aria-label="完整高级配置 JSON">${escape(JSON.stringify(model.advanced,null,2))}</textarea><button type="button" class="btn btn-g" id="cw-advanced-apply">校验并应用 JSON</button></details>`;
  }
  function renderNodes(){
    const keyword=el('cw-node-search').value.trim().toLocaleLowerCase(),nodes=model.nodes.filter(n=>[n.name,n.server_name,n.host,n.protocol].join(' ').toLocaleLowerCase().includes(keyword));
    el('cw-node-count').textContent=model.snapshot?'已选 '+selectedNodes(model).length+' / '+model.nodes.filter(n=>n.available).length+' 个可用节点':'还未读取节点';
    el('cw-nodes').innerHTML=nodes.length?nodes.map(n=>`<article class="cw-node ${model.selected.has(n.id)?'selected':''} ${n.available?'':'unavailable'}"><label class="cw-node-line"><input type="checkbox" data-cw-node="${escape(n.id)}" ${model.selected.has(n.id)?'checked':''} ${n.available?'':'disabled'}><span class="cw-node-mark">${icon('network')}</span><span class="cw-node-copy"><strong>${escape(n.name)}</strong><small>${escape(n.server_name)} · ${escape(n.host)}:${escape(n.port)}</small><span class="cw-node-tags"><b>${escape(n.protocol)}</b><b>${n.compatibility==='mihomo'?'需 Mihomo / Meta':n.available?'Clash 兼容':'不可导出'}</b></span></span></label>${n.available?'<button type="button" class="cw-node-route-btn" data-cw-route-node="'+escape(n.id)+'">'+icon('activity')+'专属域名分流 <span>'+((n.routing.enabled?n.routing.direct_domains.length:0)+' 个直连域名')+'</span></button>':''}${n.notice?'<details class="cw-node-info"><summary>兼容性与读取说明</summary><p class="cw-node-notice">'+escape(n.notice)+'</p></details>':''}</article>`).join(''):'<div class="cw-empty">'+icon(model.snapshot?'search':'network')+'<strong>'+(model.snapshot?(keyword?'没有匹配的节点':'没有可读取的节点'):'等待你的网络')+'</strong><p>'+(model.snapshot?'检查来源状态，或先在“节点搭建”部署节点。':'可一次读取多台服务器，汇入同一份配置。')+'</p></div>';
  }
  function renderGroups(){
    el('cw-groups').innerHTML=model.groups.map((g,i)=>`<article class="cw-group" data-group="${escape(g.id)}"><div class="cw-group-top"><span class="cw-group-number">${String(i+1).padStart(2,'0')}</span><label class="cw-group-name"><span class="sr-only">策略组名称</span><input data-cw-group-field="name" data-id="${escape(g.id)}" value="${escape(g.name)}" maxlength="64" aria-label="策略组名称"></label><label class="cw-group-type"><span class="sr-only">策略组类型</span><select data-cw-group-field="type" data-id="${escape(g.id)}" aria-label="策略组类型">${options([['select','手动选择'],['url-test','自动测速'],['fallback','故障转移'],['load-balance','负载均衡']],g.type)}</select></label><button type="button" class="icon-btn danger" data-cw-remove-group="${escape(g.id)}" aria-label="删除策略组 ${escape(g.name)}" title="删除策略组">${icon('trash')}</button></div>${g.type!=='select'?`<div class="cw-group-testing"><label>测试 URL<input data-cw-group-field="url" data-id="${escape(g.id)}" type="url" value="${escape(g.url)}" aria-label="测试 URL"></label><label>间隔 · 秒<input data-cw-group-field="interval" data-id="${escape(g.id)}" type="number" min="10" max="86400" value="${escape(g.interval)}"></label></div>${g.type==='url-test'?`<div class="cw-group-advanced"><label>测速容差 · 毫秒<input data-cw-group-field="tolerance" data-id="${escape(g.id)}" type="number" min="0" max="3000" placeholder="默认 50" value="${escape(g.tolerance??'')}"></label><span>差距在容差内时保留当前节点，减少切换。</span></div>`:g.type==='load-balance'?`<div class="cw-group-advanced"><label>负载均衡方式<select data-cw-group-field="strategy" data-id="${escape(g.id)}">${options([['','使用默认'],['consistent-hashing','一致性散列'],['round-robin','轮询']],g.strategy||'')}</select></label><span>由兼容客户端按所选策略分配新连接。</span></div>`:''}`:''}<details class="cw-members" ${i===0?'open':''}><summary><span>${icon('network')}组内成员</span><span>${g.members.length} 个 ${icon('arrow')}</span></summary><div class="cw-member-grid">${targets().filter(([id])=>id!=='group:'+g.id).map(([id,name])=>`<label><input type="checkbox" data-cw-member="${escape(id)}" data-group-id="${escape(g.id)}" ${g.members.includes(id)?'checked':''}><span>${escape(name)}</span><small>${id.startsWith('node:')?'节点':id.startsWith('group:')?'组':'策略'}</small></label>`).join('')}</div></details></article>`).join('');
  }
  function renderRules(){
    const bulk=el('cw-bulk-target'),previous=bulk.value;bulk.innerHTML=options(targets(),targetName(model,previous)?previous:model.groups[0]?'group:'+model.groups[0].id:'DIRECT');
    el('cw-rules').innerHTML=model.rules.map((r,i)=>`<div class="cw-rule ${r.type==='MATCH'?'cw-rule-match':''}"><span class="cw-rule-number">${String(i+1).padStart(2,'0')}</span><div class="cw-rule-match-fields"><label class="sr-only" for="cw-rule-type-${r.id}">第 ${i+1} 条匹配类型</label><select id="cw-rule-type-${r.id}" data-cw-rule-field="type" data-id="${r.id}" ${r.type==='MATCH'?'disabled':''}>${options((r.type==='MATCH'?['MATCH']:RULE_TYPES.filter(v=>v!=='MATCH')).map(v=>[v,v]),r.type)}</select>${r.type==='MATCH'?'<span class="cw-match-caption">其余所有流量 · 最后一条</span>':`<label class="sr-only" for="cw-rule-value-${r.id}">第 ${i+1} 条匹配内容</label><input id="cw-rule-value-${r.id}" data-cw-rule-field="value" data-id="${r.id}" value="${escape(r.value)}" maxlength="2048" placeholder="${['IP-CIDR','SRC-IP-CIDR'].includes(r.type)?'例如 192.168.0.0/16':['IP-CIDR6','SRC-IP-CIDR6'].includes(r.type)?'例如 ::1/128':r.type==='GEOIP'?'例如 CN':r.type==='DST-PORT'?'例如 443 或 8000-8100':'例如 example.com'}">`}${['IP-CIDR','IP-CIDR6','SRC-IP-CIDR','SRC-IP-CIDR6','GEOIP'].includes(r.type)?`<label class="cw-rule-noresolve"><input type="checkbox" data-cw-rule-field="no_resolve" data-id="${r.id}" ${r.no_resolve!==false?'checked':''}><span>no-resolve · 不为匹配额外解析 DNS</span></label>`:''}</div><label class="cw-rule-target"><span class="sr-only">第 ${i+1} 条目标策略</span><select data-cw-rule-field="target" data-id="${r.id}">${options(targets(),r.target)}</select></label><div class="cw-rule-controls"><button type="button" class="icon-btn" data-cw-move="-1" data-id="${r.id}" aria-label="上移第 ${i+1} 条规则" ${i===0||r.type==='MATCH'?'disabled':''}>${icon('up')}</button><button type="button" class="icon-btn cw-down" data-cw-move="1" data-id="${r.id}" aria-label="下移第 ${i+1} 条规则" ${i>=model.rules.length-2?'disabled':''}>${icon('up')}</button><button type="button" class="icon-btn danger" data-cw-remove-rule="${r.id}" aria-label="删除第 ${i+1} 条规则" ${r.type==='MATCH'?'disabled':''}>${icon('trash')}</button></div></div>`).join('');
  }
  function renderRouting(){
    const nodes=model.nodes.filter(n=>n.available),node=nodes.find(n=>n.id===model.routingNode),draft=node?routingDraft(model,node.id):null;
    const selector=nodes.length?`<label class="cw-routing-select" for="cw-routing-node"><span>只设置这个节点</span><select id="cw-routing-node">${options(nodes.map(n=>[n.id,n.name+' · '+n.server_name+' · '+n.protocol+' :'+n.port]),model.routingNode)}</select></label>`:'';
    if(!draft){el('cw-node-routing').innerHTML=`<div class="cw-section-head"><div><span class="eyebrow">NODE / SPLIT ROUTING</span><h4>给每个节点，自己的通行名单</h4><p>添加的域名走本机网络，其余流量经当前节点。</p></div></div><div class="cw-output-empty">${icon('network')}<strong>先读取你的节点</strong><p>读取已保存服务器后，从节点卡片点击“专属域名分流”。</p></div>`;return;}
    const busy=routeBusy?.id===node.id,disabled=busy?'disabled':'';
    el('cw-node-routing').innerHTML=`<div class="cw-section-head"><div><span class="eyebrow">NODE / SPLIT ROUTING</span><h4>给这个节点，自己的通行名单</h4><p>名单内的域名直连，其余流量经当前节点。</p></div><span class="cw-routing-state" id="cw-routing-state" role="status" aria-live="polite"></span></div>${selector}
      <div class="cw-routing-flow"><div class="cw-routing-flow-direct">${icon('desktop')}<span><strong>${draft.enabled?'名单内域名':'分流已关闭'}</strong><small>${draft.enabled?'本机网络 · DIRECT':'当前名单暂不生效'}</small></span></div><span class="cw-routing-flow-separator">／</span><div class="cw-routing-flow-proxy">${icon('network')}<span><strong>${draft.enabled?'其余流量':'全部流量'}</strong><small>经 ${escape(node.name)}</small></span></div></div>
      <div class="cw-routing-settings"><label class="cw-routing-toggle"><input id="cw-routing-enabled" type="checkbox" ${draft.enabled?'checked':''} ${disabled}><span><strong>启用这个节点的域名分流</strong><small>域名及全部子域名直连，例如 example.com 包含 www.example.com。</small></span></label>
      <label class="cw-routing-domain-label" for="cw-routing-domain-input">直连域名名单 <span id="cw-routing-domain-count">${draft.direct_domains.length} / ${ROUTING_DOMAIN_LIMIT}</span></label><div class="cw-routing-domain-entry"><textarea id="cw-routing-domain-input" rows="3" spellcheck="false" autocomplete="off" placeholder="example.com&#10;另一个域名.com" ${disabled}>${escape(draft.input)}</textarea><button type="button" class="btn btn-g" id="cw-routing-add-domains" ${disabled}>${icon('plus')}添加域名</button></div><p class="cw-routing-input-help">可粘贴多个域名，用换行、空格或逗号分隔。只填写域名；中文域名会自动转换。</p><div class="cw-routing-domain-list" id="cw-routing-domain-list">${draft.direct_domains.length?draft.direct_domains.map(domain=>`<span class="cw-domain-chip"><span>${escape(domain)}</span><button type="button" data-cw-route-remove="${escape(domain)}" ${disabled} aria-label="移除 ${escape(domain)}">${icon('close')}</button></span>`).join(''):'<span class="cw-routing-list-empty">还未添加域名；当前配置的流量全部经这个节点。</span>'}</div></div>
      <details class="cw-routing-ports"><summary>本机接入端口 <span>可按客户端调整</span></summary><div><label>Clash 混合端口<input type="number" min="1" max="65535" inputmode="numeric" data-cw-route-port="mixed_port" value="${escape(draft.ports.mixed_port)}" ${disabled}></label><label>Xray SOCKS 端口<input type="number" min="1" max="65535" inputmode="numeric" data-cw-route-port="socks_port" value="${escape(draft.ports.socks_port)}" ${disabled}></label><label>Xray HTTP 端口<input type="number" min="1" max="65535" inputmode="numeric" data-cw-route-port="http_port" value="${escape(draft.ports.http_port)}" ${disabled}></label></div></details>
      <div class="cw-routing-actions"><button type="button" class="btn btn-g" id="cw-routing-save">${icon('check')}保存于本机</button><button type="button" class="btn btn-p" id="cw-routing-generate">${icon('spark')}保存并生成专属配置</button></div><div id="cw-routing-message" class="cw-routing-message" role="status" aria-live="polite"></div><div id="cw-routing-output"></div>
      <div class="cw-inline-note cw-routing-note">${icon('shield')}<p>DIRECT 使用客户端所在电脑的网络。每份专属配置只绑定这个节点，切换节点请使用它对应的配置。普通 VLESS / VMess 分享链接不携带分流规则，需要导入完整配置；此名单不会改变多节点配置的全局路由。</p></div>`;
    renderRoutingStatus();renderRoutingOutput();
  }
  function renderRoutingStatus(){
    const draft=routingDraft(model,model.routingNode);if(!draft)return;
    const state=el('cw-routing-state'),dirty=routingDirty(draft)||Boolean(cleanText(draft.input)),busy=routeBusy?.id===model.routingNode;
    state.textContent=busy?(routeBusy.operation==='save'?'正在保存…':'正在生成…'):dirty?'未保存':draft.saved.revision?'已保存于本机':'尚未设置';state.dataset.state=busy?'pending':dirty?'draft':'saved';
    el('cw-routing-save').disabled=Boolean(routeBusy)||reading||studioBusy||!model.snapshot||!dirty;el('cw-routing-generate').disabled=Boolean(routeBusy)||reading||studioBusy||!model.snapshot;
    el('cw-routing-message').textContent=draft.error||(busy?'正在处理当前节点，请稍候。':cleanText(draft.input)?'输入框还有待添加域名；保存时会一起添加。':dirty?'名单已修改。保存后生成配置，再导入客户端生效。':draft.saved.revision?'名单已保存在这台电脑；生成专属配置后导入客户端生效。':'添加域名并开启分流，然后保存生成。');
    el('cw-routing-message').dataset.state=draft.error?'error':busy?'pending':'normal';
    root.querySelectorAll('[data-cw-route-export]').forEach(button=>button.disabled=reading||studioBusy||!routingCurrentOutput(draft));
  }
  function renderRoutingOutput(){
    const draft=routingDraft(model,model.routingNode),result=draft?.output;if(!draft||!result){el('cw-routing-output').innerHTML='';return;}
    const current=Boolean(routingCurrentOutput(draft)),format=draft.format==='xray'?'xray':'clash',output=result[format],available=output?.available===true,content=format==='xray'?output?.json:output?.yaml;
    el('cw-routing-output').innerHTML=`<div class="cw-routing-result"><div class="cw-routing-result-heading"><strong>${current?'当前节点的专属配置':'名单或端口已修改，请重新生成'}</strong><span class="cw-format-tag">ONE NODE</span></div><div class="cw-routing-format-tabs" role="tablist" aria-label="专属配置格式">${[['clash','Clash / Mihomo'],['xray','Xray / V2Ray']].map(([key,title])=>`<button type="button" role="tab" id="cw-routing-format-${key}" data-cw-route-format="${key}" class="${key===format?'active':''}" aria-selected="${key===format}" tabindex="${key===format?0:-1}" aria-controls="cw-routing-format-panel">${escape(title)}</button>`).join('')}</div><div id="cw-routing-format-panel" role="tabpanel" aria-labelledby="cw-routing-format-${format}">${output?.notice?'<p class="cw-export-notice">'+escape(output.notice)+'</p>':''}${result.warnings.length?'<ul class="cw-warnings">'+result.warnings.map(w=>'<li>'+escape(w)+'</li>').join('')+' </ul>':''}${available?`<div class="cw-output-actions"><button type="button" class="btn btn-p" data-cw-route-export="download" ${current?'':'disabled'}>${icon('download')}下载 ${format==='xray'?'JSON':'YAML'}</button><button type="button" class="btn btn-g" data-cw-route-export="copy" ${current?'':'disabled'}>${icon('code')}复制完整配置</button>${format==='clash'&&output.url?`<button type="button" class="btn btn-g" data-cw-route-export="url" ${current?'':'disabled'}>复制同机 URL</button><button type="button" class="btn btn-g" data-cw-route-export="import" ${current?'':'disabled'}>复制导入链接</button>`:''}</div><details class="cw-preview"><summary>${icon('file')}查看完整配置 <span>包含节点凭据，请妥善保管</span></summary><textarea readonly rows="14" spellcheck="false" aria-label="当前节点 ${format==='xray'?'Xray JSON':'Clash YAML'} 配置">${escape(content)}</textarea></details>`:'<div class="cw-routing-unavailable">'+icon('file')+'<span>当前节点暂不支持此格式，请使用另一种可用格式。</span></div>'}</div><p class="cw-local-notice">${icon('desktop')}${format==='xray'?'JSON 需在支持完整 Xray 配置的客户端中导入，再开启客户端代理。':'Clash 配置请使用规则模式；同机 URL 需要 G-Network 保持运行。'}</p></div>`;
  }
  function renderOutputContent(){
    const c=model.output,current=Boolean(currentOutput(model));
    el('cw-output').innerHTML=c?`<div class="cw-result-header"><span class="cw-result-symbol">${icon(current?'check':'refresh')}</span><div><strong>${current?'完整配置已生成':'草稿已修改，输出待更新'}</strong><p>${c.compatibility==='mihomo'?'需支持所选协议的 Mihomo / Meta 客户端':'请使用支持所选协议的 Clash 客户端'}</p></div><span class="cw-format-tag">${selectedNodes(model).length} NODES</span></div><p class="cw-export-notice">${escape(c.notice)}</p>${model.outputWarnings?.length?'<ul class="cw-warnings">'+model.outputWarnings.map(v=>'<li>'+escape(v)+'</li>').join('')+'</ul>':''}${c.url?`<label class="cw-output-label" for="cw-config-url">同机临时配置 URL</label><textarea id="cw-config-url" class="cw-url" readonly rows="3" spellcheck="false">${escape(c.url)}</textarea>`:'<p class="cw-export-notice">本机 URL 不可用；可以下载 YAML 或复制配置。</p>'}<div class="cw-output-actions"><button type="button" class="btn btn-p" data-cw-export="download" ${current?'':'disabled'}>${icon('download')}下载完整 YAML</button><button type="button" class="btn btn-g" data-cw-export="yaml" ${current?'':'disabled'}>${icon('code')}复制配置</button>${c.url?`<button type="button" class="btn btn-g" data-cw-export="url" ${current?'':'disabled'}>复制配置 URL</button><button type="button" class="btn btn-g" data-cw-export="import" ${current?'':'disabled'}>复制 Clash 导入链接</button>`:''}</div><details class="cw-preview" open><summary>${icon('file')}配置预览 <span>包含节点凭据，请妥善保管</span></summary><textarea id="cw-yaml" readonly rows="15" spellcheck="false" aria-label="完整 Clash YAML 配置">${escape(c.yaml)}</textarea></details><p class="cw-local-notice">${icon('desktop')}同机 URL 需要 G-Network 运行；跨设备用 YAML。复制导入链接后在兼容客户端中使用。</p>`:'<div class="cw-output-empty">'+icon('file')+'<strong>完整配置将在这里呈现</strong><p>先选择节点，检查策略和路由，再点击“生成完整配置”。</p></div>';
  }
  function renderSaveControls(){
    const saved=model.savedProfile;el('cw-output').innerHTML+=`<div class="cw-local-save"><div><strong>${saved?'继续保存：'+escape(saved.name):'把这份配置，留在本机'}</strong><p>节点凭据由程序加密保存，下次可从配置来源页继续编辑。</p></div><div class="cw-output-actions"><button type="button" class="btn btn-g" id="cw-profile-save" ${studioBusy?'disabled':''}>${icon('shield')}${saved?'保存修改':'加密保存于本机'}</button>${saved?'<button type="button" class="btn btn-g" id="cw-profile-save-new" '+(studioBusy?'disabled':'')+'>另存为新配置</button>':''}</div><div id="cw-profile-save-message" class="cw-studio-message" role="status" aria-live="polite">${escape(studioMessage)}</div></div>`;
  }
  function renderOutput(){renderOutputContent();renderSaveControls();}
  function renderStatus(){
    const count=selectedNodes(model).length,errors=validate(model);
    el('cw-step-nodes').textContent=count+' 个';el('cw-step-groups').textContent=model.groups.length+' 组';el('cw-step-output').textContent=currentOutput(model)?'已生成':'待生成';el('cw-group-count').textContent=model.groups.length;el('cw-rule-count').textContent=model.rules.length;
    el('cw-state').textContent=studioBusy?'正在处理':reading?'正在读取':generating?'正在生成':currentOutput(model)?'配置已就绪':model.output?'待重新生成':model.snapshot?'草稿编辑中':'等待节点';el('cw-state').dataset.state=currentOutput(model)?'ready':reading||generating||studioBusy?'pending':'draft';
    el('cw-export-summary').innerHTML=`<span><strong>${count}</strong>节点</span><span><strong>${new Set(selectedNodes(model).map(n=>n.server_id)).size}</strong>来源</span><span><strong>${model.groups.length}</strong>策略组</span><span><strong>${model.rules.length}</strong>路由规则</span>`;
    el('cw-validation').textContent=generating?'正在生成并校验完整配置…':lastError|| (errors.length?errors[0]:model.output&&!currentOutput(model)?'内容已修改，请重新生成后再导出。':'配置草稿可生成。');el('cw-validation').dataset.state=errors.length||lastError?'warning':'ready';
    el('cw-generate').disabled=reading||generating||studioBusy||errors.length>0;el('cw-generate').innerHTML=icon(generating?'refresh':'spark')+(generating?'正在生成…':model.output?'重新生成完整配置':'生成完整配置');
    el('cw-read').disabled=reading||generating||studioBusy||!model.sourceIds.size;
    root.querySelectorAll('[data-cw-export]').forEach(b=>b.disabled=!currentOutput(model));
  }
  function renderAll(){renderSources();renderNodes();renderStudioSource();renderChains();renderGroups();renderRules();renderRouting();renderDns();renderOutput();el('cw-profile-name').value=model.profile.name;el('cw-mixed-port').value=model.profile.mixed_port;renderStatus();}
  function changed(){lastError='';touch(model);renderStatus();if(model.output)renderOutput();}
  function selectEditor(name){
    if(!EDITORS.includes(name))return;activeEditor=name;
    root.querySelectorAll('[data-cw-tab]').forEach(b=>{const selected=b.dataset.cwTab===name;b.classList.toggle('active',selected);b.setAttribute('aria-selected',String(selected));b.tabIndex=selected?0:-1;});
    EDITORS.forEach(key=>el('cw-editor-'+key).hidden=key!==name);el('cw-next').hidden=name==='output'||name==='node-routing';const next=EDITORS[EDITORS.indexOf(name)+1],labels={chains:'链式代理',groups:'策略组',rules:'路由规则','node-routing':'节点分流',dns:'DNS 与端口',output:'生成与保存'};el('cw-next').innerHTML='下一步：'+(labels[next]||'生成与保存')+' '+icon('arrow');el('cw-footer-note').innerHTML=icon('shield')+(name==='node-routing'?'节点名单独立保存；不会合并到全局规则':'本机加密保存可在下次继续编辑');renderStatus();
  }
  function invalidateRouting(){routeEpoch++;routeBusy=null;model.routingDrafts.clear();model.routingNode=null;}
  function invalidateSources(){readEpoch++;exportEpoch++;studioEpoch++;studioBusy=false;invalidateRouting();reading=false;generating=false;model.nodes=model.nodes.filter(n=>['import','saved'].includes(n.origin));model.selected=new Set([...model.selected].filter(id=>model.nodes.some(n=>n.id===id)));if(!model.nodes.length)model.snapshot=null;model.output=null;model.outputRevision=null;model.readAt=null;model.sourceResults=[];syncMembers(model);touch(model);renderAll();el('cw-source-results').replaceChildren();el('cw-read-status').textContent='读取范围已改变，请重新读取服务器节点；本机导入的节点保留。';}
  async function readNodes(){
    if(reading||generating||studioBusy||routeBusy||!model.sourceIds.size)return;
    const request=++readEpoch,ids=[...model.sourceIds],snapshot=model.snapshot,oldDrafts=new Map(model.routingDrafts),localSelection=new Set(model.nodes.filter(n=>['import','saved'].includes(n.origin)&&model.selected.has(n.id)).map(n=>n.id));routeEpoch++;routeBusy=null;reading=true;lastError='';model.output=null;model.outputRevision=null;touch(model);renderAll();el('cw-source-results').replaceChildren();el('cw-read-status').textContent='正在读取 '+ids.length+' 台服务器…';
    try{
      // Identity dialogs are deliberately sequential: a single modal verifies one target.
      for(const id of ids){if(request!==readEpoch||destroyed)return;await host.ensureIdentity?.(id);}
      if(request!==readEpoch||destroyed)return;
      const result=await host.api('/api/clash-workspace/read',host.jsonPost({server_ids:ids,...(snapshot&&model.nodes.some(n=>['import','saved'].includes(n.origin))?{snapshot_id:snapshot}:{})}));
      if(request!==readEpoch||destroyed)return;acceptCatalog(model,result);model.nodes.filter(n=>['import','saved'].includes(n.origin)).forEach(n=>{if(!localSelection.has(n.id))model.selected.delete(n.id);const draft=oldDrafts.get(n.id);if(draft&&JSON.stringify(draft.saved)===JSON.stringify(n.routing))model.routingDrafts.set(n.id,draft);});syncMembers(model);renderAll();
      el('cw-read-status').textContent='已读取 '+model.nodes.length+' 个节点 · '+model.readAt.toLocaleTimeString('zh-CN',{hour12:false});
      el('cw-source-results').innerHTML=model.sourceResults.map(s=>`<div class="cw-source-result" data-state="${s.status==='ok'?'ok':'error'}"><span>${icon(s.status==='ok'?'check':'close')}${escape(s.name||s.id)}</span><small>${escape(s.msg||(s.status==='ok'?'读取成功':s.status==='error'?'读取失败':'状态未知'))}</small></div>`).join('');
      host.toast(model.nodes.filter(n=>n.available).length>128?'节点库已更新；已选前 128 个可用节点，可取消后换选其他节点。':'节点库已更新；默认选中全部可用节点。');
    }catch(e){if(request===readEpoch&&!destroyed){el('cw-read-status').textContent=e.message||'节点读取失败';host.toast(e.message||'节点读取失败',false);}}
    finally{if(request===readEpoch&&!destroyed){reading=false;renderStatus();renderRoutingStatus();}}
  }
  async function generate(){
    if(reading||generating||studioBusy)return;let draft;try{draft=exportDraft(model);}catch(e){host.toast(e.message,false);return;}
    const request=++exportEpoch,revision=model.revision,snapshot=model.snapshot;generating=true;lastError='';renderStatus();
    try{const result=await host.api('/api/clash-workspace/export',host.jsonPost(draft));if(request!==exportEpoch||revision!==model.revision||snapshot!==model.snapshot||destroyed)return;const c=host.normalizeConfig(result.clash);if(!c.available)throw new Error(c.notice||'未能生成完整配置');model.output=c;model.outputRevision=revision;model.outputWarnings=Array.isArray(result.warnings)?result.warnings.map(String):[];renderOutput();host.toast('完整 Clash 配置已生成。');}
    catch(e){if(request===exportEpoch&&!destroyed){lastError=e.message||'配置生成失败';host.toast(lastError,false);}}
    finally{if(request===exportEpoch&&!destroyed){generating=false;renderStatus();}}
  }
  async function studioTask(operation){
    if(studioBusy||reading||generating||routeBusy)return;const request=++studioEpoch;studioBusy=true;studioMessage='正在处理，请稍候…';renderStudioSource();renderOutput();renderStatus();renderRoutingStatus();
    const valid=()=>!destroyed&&studioEpoch===request;
    try{await operation(valid);}catch(e){if(valid()){studioMessage=e.message||'配置处理失败';host.toast(studioMessage,false);}}
    finally{if(valid()){studioBusy=false;renderStudioSource();renderOutput();renderStatus();renderRoutingStatus();}}
  }
  async function previewImport(){
    if(!cleanText(importText))return host.toast('先粘贴节点链接或上传配置。',false);if(new Blob([importText]).size>524288)return host.toast('导入内容不能超过 512 KiB。',false);
    await studioTask(async valid=>{const result=await host.api('/api/clash-workspace/import-preview',host.jsonPost({text:importText,format:importFormat}));if(!valid())return;if(!result||typeof result.import_token!=='string'||!result.import_token||!Array.isArray(result.nodes))throw new Error('导入预览格式不正确，请重新解析。');importPreview=result;studioMessage='解析完成，检查预览后选择合并节点或完整编辑。';});
  }
  async function applyImport(mode){
    if(!importPreview||mode==='replace'&&!importPreview.can_replace)return;
    if(mode==='replace'&&model.snapshot&&!global.confirm('完整配置编辑会替换当前全局草稿。独立节点名单仍保存在本机。继续？'))return;
    const token=importPreview.import_token,snapshot=model.snapshot;
    await studioTask(async valid=>{const result=await host.api('/api/clash-workspace/import',host.jsonPost({import_token:token,snapshot_id:snapshot||null,mode}));if(!valid())return;acceptStudioCatalog(model,result,mode);routeEpoch++;routeBusy=null;exportEpoch++;importPreview=null;importText='';studioWarnings=Array.isArray(result.warnings)?result.warnings.map(String):[];studioMessage=mode==='replace'?'完整配置已还原为可编辑草稿。':'节点已合并，原有规则和专属域名名单保留。';lastError='';renderAll();selectEditor(mode==='replace'?'groups':'chains');host.toast(studioMessage);});
  }
  function normalizeSavedProfile(value){if(!value||typeof value.id!=='string'||!value.id||typeof value.name!=='string'||!Number.isInteger(value.revision)||value.revision<1)throw new Error('本机配置记录格式不正确。');return {...value};}
  async function refreshProfiles(){await studioTask(async valid=>{const result=await host.api('/api/clash-workspace/profiles');if(!valid())return;if(!Array.isArray(result.profiles))throw new Error('本机配置列表格式不正确。');profiles=result.profiles.map(normalizeSavedProfile);studioMessage=profiles.length?'选择一份配置继续编辑。':'还没有本机保存的配置。';});}
  async function openProfile(id){
    if(model.snapshot&&!global.confirm('打开本机配置会替换当前全局草稿。继续？'))return;
    await studioTask(async valid=>{const result=await host.api('/api/clash-workspace/profiles/open',host.jsonPost({profile_id:id}));if(!valid())return;const saved=normalizeSavedProfile(result.saved_profile);acceptStudioCatalog(model,result,'replace');model.savedProfile=saved;routeEpoch++;routeBusy=null;exportEpoch++;importPreview=null;importText='';studioWarnings=Array.isArray(result.warnings)?result.warnings.map(String):[];studioMessage='已打开本机配置：'+saved.name;lastError='';renderAll();el('cw-profile-name').value=model.profile.name;el('cw-mixed-port').value=model.profile.mixed_port;selectEditor('groups');host.toast(studioMessage);});
  }
  async function saveProfile(asNew=false){
    let payload;try{payload=exportDraft(model);}catch(e){return host.toast(e.message,false);}const saved=!asNew&&model.savedProfile;if(saved){payload.profile_id=saved.id;payload.expected_revision=saved.revision;}
    await studioTask(async valid=>{const result=await host.api('/api/clash-workspace/profiles/save',host.jsonPost(payload));if(!valid())return;const metadata=normalizeSavedProfile(result.profile);model.savedProfile=metadata;profiles=profiles.filter(p=>p.id!==metadata.id);profiles.unshift(metadata);studioMessage='配置已加密保存于本机：'+metadata.name;host.toast(studioMessage);});
  }
  async function deleteProfile(id){
    const profile=profiles.find(p=>p.id===id);if(!profile||!global.confirm('删除本机保存的配置“'+profile.name+'”？已经下载的 YAML 不受影响。'))return;
    await studioTask(async valid=>{await host.api('/api/clash-workspace/profiles/delete',host.jsonPost({profile_id:id,expected_revision:profile.revision}));if(!valid())return;profiles=profiles.filter(p=>p.id!==id);if(model.savedProfile?.id===id)model.savedProfile=null;studioMessage='本机配置已删除。';host.toast(studioMessage);});
  }
  async function loadImportFile(file){
    if(!file)return;if(file.size>524288)return host.toast('文件不能超过 512 KiB。',false);if(!/\.(yaml|yml|txt)$/i.test(file.name||''))return host.toast('请选择 YAML、YML 或 TXT 文件。',false);
    const epoch=++studioEpoch;try{const text=await file.text();if(destroyed||studioEpoch!==epoch)return;if(new Blob([text]).size>524288)throw new Error('文件不能超过 512 KiB。');importText=text;importFormat=/\.(yaml|yml)$/i.test(file.name)?'yaml':'auto';importPreview=null;studioMessage='文件已读入，点击“解析并预览”。';renderStudioSource();}catch(e){if(studioEpoch===epoch){studioMessage=e.message||'读取文件失败';renderStudioSource();host.toast(studioMessage,false);}}
  }
  function selectRoutingNode(nodeId){
    const node=model.nodes.find(n=>n.id===nodeId&&n.available);if(!node)return host.toast('节点不可用，请重新读取。',false);
    model.routingNode=node.id;routingDraft(model,node.id);renderRouting();selectEditor('node-routing');
  }
  function addRoutingDomains(draft,notify=true){
    if(!cleanText(draft.input))return true;
    const parsed=parseDomainBatch(draft.input,draft.direct_domains);
    if(parsed.errors.length){draft.error=parsed.errors.join('\n');renderRoutingStatus();return false;}
    const changed=JSON.stringify(parsed.domains)!==JSON.stringify(draft.direct_domains);draft.input='';draft.direct_domains=parsed.domains;if(changed)routingTouch(draft);else draft.error='';
    renderRouting();if(notify)host.toast(changed?'域名已加入当前节点的名单，保存后导入专属配置生效。':'域名已在名单中，已自动去重。');return true;
  }
  function normalizeXray(value){
    if(!value||value.available!==true)return {available:false,notice:String(value?.notice||'此节点暂不支持 Xray 完整配置。')};
    if(typeof value.json!=='string'||!value.json||value.json.length>2097152)throw new Error('Xray 配置格式不正确，请重新生成。');
    let json;try{json=JSON.parse(value.json);}catch(e){throw new Error('Xray 配置格式不正确，请重新生成。');}if(!json||typeof json!=='object'||Array.isArray(json))throw new Error('Xray 配置格式不正确，请重新生成。');
    const filename=String(value.filename||'');return {available:true,json:value.json,filename:/^[^\x00-\x1f\x7f/\\:*?"<>|]{1,120}\.json$/i.test(filename)&&!filename.startsWith('.')?filename:'G-Network-node.json',notice:String(value.notice||'')};
  }
  async function saveRouting(generateConfig=false){
    if(routeBusy||reading||studioBusy||!model.snapshot)return;
    const id=model.routingNode,draft=routingDraft(model,id);if(!draft||!addRoutingDomains(draft,false))return;
    let ports;try{if(generateConfig)ports=routingPorts(draft);}catch(e){draft.error=e.message;renderRoutingStatus();return;}
    const request=++routeEpoch,snapshot=model.snapshot,editRevision=draft.editRevision;
    const valid=()=>!destroyed&&request===routeEpoch&&model.snapshot===snapshot&&model.routingDrafts.get(id)===draft&&model.nodes.some(n=>n.id===id&&n.available);
    routeBusy={id,request,operation:generateConfig?'export':'save'};draft.error='';if(generateConfig){draft.output=null;draft.outputSignature=null;}renderRouting();
    try{
      if(routingDirty(draft)){
        const expected=draft.saved.revision,payload={snapshot_id:snapshot,node_id:id,enabled:draft.enabled,direct_domains:[...draft.direct_domains],expected_revision:expected};
        const saved=await host.api('/api/node-routing/save',host.jsonPost(payload));if(!valid())return;
        const routing=normalizeRouting(saved.routing);
        if(routing.enabled!==payload.enabled||JSON.stringify(routing.direct_domains)!==JSON.stringify(payload.direct_domains)||routing.revision<=expected)throw new Error('保存状态与当前名单不一致，请重新读取节点后重试。');
        draft.saved=routing;const node=model.nodes.find(n=>n.id===id);node.routing=routing;draft.output=null;draft.outputSignature=null;renderNodes();
      }
      if(!valid())return;
      if(generateConfig){
        if(draft.editRevision!==editRevision)throw new Error('名单已修改，请重新生成。');
        const exported=await host.api('/api/node-routing/export',host.jsonPost({snapshot_id:snapshot,node_id:id,...ports}));if(!valid()||draft.editRevision!==editRevision)return;
        const routing=normalizeRouting(exported.routing);if(JSON.stringify(routing)!==JSON.stringify(draft.saved))throw new Error('名单已被其他窗口修改，请重新读取当前节点。');
        const clash=host.normalizeConfig(exported.clash),xray=normalizeXray(exported.xray);
        if(!clash.available&&!xray.available)throw new Error([clash.notice,xray.notice].filter(Boolean).join('\n')||'当前节点无法生成专属配置。');
        draft.output={clash,xray,warnings:Array.isArray(exported.warnings)?exported.warnings.map(String):[]};draft.outputSignature=routingSignature(draft);draft.format=clash.available?'clash':'xray';
        host.toast(clash.available&&xray.available?'当前节点的 Clash 与 Xray 专属配置已生成。':clash.available?'Clash 专属配置已生成；Xray 不支持此节点，请查看格式说明。':'Xray 专属配置已生成；Clash 不支持此节点，请查看格式说明。');
      }else host.toast('当前节点的域名分流名单已保存于本机。');
    }catch(e){if(valid()){draft.error=e.message||'节点分流处理失败';host.toast(draft.error,false);}}
    finally{if(valid()){routeBusy=null;if(model.routingNode===id)renderRouting();else renderRoutingStatus();}}
  }
  async function routingExportAction(action){
    const draft=routingDraft(model,model.routingNode),result=routingCurrentOutput(draft);if(!result)return host.toast('名单、端口或读取来源已改变，请重新生成专属配置。',false);
    const format=draft.format==='xray'?'xray':'clash',output=result[format];if(!output?.available)return host.toast(output?.notice||'此格式不可用。',false);
    try{
      const content=format==='xray'?output.json:output.yaml;
      if(action==='download'){const url=URL.createObjectURL(new Blob([content],{type:format==='xray'?'application/json;charset=utf-8':'application/yaml;charset=utf-8'})),link=global.document.createElement('a');blobUrls.add(url);try{link.href=url;link.download=output.filename;global.document.body.appendChild(link);link.click();}finally{link.remove();setTimeout(()=>{URL.revokeObjectURL(url);blobUrls.delete(url);},1000);}host.toast('已发起当前节点专属配置下载。');return;}
      const value=action==='copy'?content:format==='clash'&&output.url?(action==='url'?output.url:action==='import'?'clash://install-config?url='+encodeURIComponent(output.url):null):null;if(!value)throw new Error('配置链接不可用，请下载完整配置。');
      await global.navigator.clipboard.writeText(value);host.toast('当前节点的专属配置'+(action==='copy'?'内容':'链接')+'已复制。');
    }catch(e){host.toast(e.message||'导出失败，可从配置预览中手动复制。',false);}
  }
  async function focusRoutingNode(serverId,identity={}){
    const request=++focusEpoch,id=String(serverId||'');selectEditor('node-routing');
    if(!model.servers.some(s=>String(s.id)===id)){host.toast('先将这个 SSH 目标保存为服务器，再设置节点专属分流。',false);return false;}
    const find=()=>model.nodes.filter(n=>n.available&&n.server_id===id&&String(n.port)===String(identity.port)&&String(n.protocol).toLowerCase()===String(identity.protocol||'').toLowerCase()&&n.name===String(identity.name||''));
    let matches=model.snapshot?find():[];
    if(matches.length!==1){if(reading||generating||routeBusy){host.toast('正在读取或保存配置，请完成后再打开这个节点。',false);return false;}model.sourceIds=new Set([id]);invalidateSources();await readNodes();if(request!==focusEpoch||destroyed)return false;matches=find();}
    if(matches.length!==1){host.toast(matches.length?'有多个同名且相同端口的节点，请在节点库中选择确切节点。':'未找到对应节点，请确认节点已部署后重新读取。',false);return false;}
    selectRoutingNode(matches[0].id);return true;
  }
  async function exportAction(action){
    const output=currentOutput(model);if(!output)return host.toast('配置已修改或来源已改变，请重新生成。',false);
    try{if(action==='download'){const url=URL.createObjectURL(new Blob([output.yaml],{type:'application/yaml;charset=utf-8'})),link=global.document.createElement('a');blobUrls.add(url);try{link.href=url;link.download=output.filename;global.document.body.appendChild(link);link.click();}finally{link.remove();setTimeout(()=>{URL.revokeObjectURL(url);blobUrls.delete(url);},1000);}return host.toast('已发起完整 YAML 下载。');}
      const text=action==='yaml'?output.yaml:action==='url'?output.url:action==='import'&&output.url?'clash://install-config?url='+encodeURIComponent(output.url):null;if(!text)throw new Error('本机配置链接不可用，请下载 YAML。');await global.navigator.clipboard.writeText(text);host.toast(action==='yaml'?'完整配置已复制。':action==='import'?'导入链接已复制，请在客户端中导入。':'配置 URL 已复制。');
    }catch(e){host.toast(e.message||'导出失败，可以在配置预览中手动复制。',false);}
  }
  function onClick(event){
    const b=event.target.closest('button');if(!b||!root.contains(b)||b.disabled)return;
    if(studioBusy&&!b.dataset.cwTab)return;
    if(b.id==='cw-studio-read'){selectEditor('source');return readNodes();}
    if(b.id==='cw-import-preview')return previewImport();
    if(b.id==='cw-import-merge')return applyImport('merge');
    if(b.id==='cw-import-replace')return applyImport('replace');
    if(b.id==='cw-profiles-refresh')return refreshProfiles();
    if(b.dataset.cwProfileOpen)return openProfile(b.dataset.cwProfileOpen);
    if(b.dataset.cwProfileDelete)return deleteProfile(b.dataset.cwProfileDelete);
    if(b.id==='cw-profile-save'||b.id==='cw-profile-save-new')return saveProfile(b.id==='cw-profile-save-new');
    if(b.id==='cw-add-domain-rules'){try{const count=appendDomainRules(model,el('cw-bulk-domains').value,el('cw-bulk-target').value||'group:'+model.groups[0]?.id);el('cw-bulk-domains').value='';changed();renderRules();host.toast('已追加 '+count+' 条域名规则。');}catch(e){host.toast(e.message,false);}return;}
    if(b.dataset.cwService){try{const count=applyServicePreset(model,b.dataset.cwService);lastError='';renderGroups();renderRules();renderStatus();renderOutput();host.toast('已追加 '+count+' 条常见服务域名；可继续调整独立策略组。');}catch(e){host.toast(e.message,false);}return;}
    if(b.id==='cw-dns-template'){if(model.advanced.dns&&Object.keys(model.advanced.dns).length&&!global.confirm('用本机分流 DNS 模板替换当前 DNS 设置？其余高级配置保留。'))return;model.advanced.dns=splitDnsTemplate();changed();renderDns();host.toast('DNS 模板已应用；生成并导入后生效。');return;}
    if(b.id==='cw-advanced-apply'){try{const value=parseAdvanced(el('cw-advanced-json').value);model.advanced=value;changed();renderDns();host.toast('高级配置 JSON 已应用，生成时由后端继续校验。');}catch(e){host.toast('高级配置 JSON 不正确：'+e.message,false);}return;}
    if(b.id==='cw-add-chain'){const nodes=selectedNodes(model);if(nodes.length<2)return host.toast('先选中至少两个节点。',false);if(model.chains.length>=16)return host.toast('最多 16 条链式代理。',false);let suffix=1;while(model.chains.some(c=>c.name==='链式 '+suffix)||model.groups.some(g=>g.name==='链式 '+suffix))suffix++;model.chains.push({id:'c'+(++model.serial),name:'链式 '+suffix,hops:nodes.slice(0,2).map(n=>n.id),enabled:true});syncMembers(model);changed();renderChains();renderGroups();renderRules();return;}
    if(b.dataset.cwChainDelete){const id=b.dataset.cwChainDelete,chain=model.chains.find(c=>c.id===id);if(!chain||!global.confirm('删除链式“'+chain.name+'”？引用它的规则将改为 DIRECT。'))return;model.chains=model.chains.filter(c=>c.id!==id);model.rules.forEach(r=>{if(r.target==='chain:'+id)r.target='DIRECT';});syncMembers(model);changed();renderChains();renderGroups();renderRules();return;}
    if(b.dataset.cwHopAdd){const c=model.chains.find(c=>c.id===b.dataset.cwHopAdd);if(!c||c.hops.length>=8)return;const n=selectedNodes(model).find(n=>!c.hops.includes(n.id));if(!n)return host.toast('先选中另一个尚未在链中的节点。',false);c.hops.push(n.id);changed();renderChains();return;}
    if(b.dataset.cwHopRemove!==undefined){const c=model.chains.find(c=>c.id===b.dataset.chain),index=Number(b.dataset.cwHopRemove);if(c&&c.hops.length>2&&Number.isInteger(index)&&index>=0&&index<c.hops.length){c.hops.splice(index,1);changed();renderChains();}return;}
    if(b.dataset.cwHopMove){const c=model.chains.find(c=>c.id===b.dataset.chain),index=Number(b.dataset.index),next=index+Number(b.dataset.cwHopMove);if(c&&Number.isInteger(index)&&next>=0&&next<c.hops.length){[c.hops[index],c.hops[next]]=[c.hops[next],c.hops[index]];changed();renderChains();}return;}
    if(b.dataset.cwTab)return selectEditor(b.dataset.cwTab);
    if(b.dataset.cwRouteNode)return selectRoutingNode(b.dataset.cwRouteNode);
    if(b.dataset.cwRouteFormat){const draft=routingDraft(model,model.routingNode);if(draft&&['clash','xray'].includes(b.dataset.cwRouteFormat)){draft.format=b.dataset.cwRouteFormat;renderRoutingOutput();}return;}
    if(b.dataset.cwRouteExport)return routingExportAction(b.dataset.cwRouteExport);
    if(b.dataset.cwRouteRemove){const draft=routingDraft(model,model.routingNode);if(draft&&routeBusy?.id!==model.routingNode){draft.direct_domains=draft.direct_domains.filter(d=>d!==b.dataset.cwRouteRemove);routingTouch(draft);renderRouting();}return;}
    if(b.id==='cw-routing-add-domains'){const draft=routingDraft(model,model.routingNode);if(draft&&routeBusy?.id!==model.routingNode)addRoutingDomains(draft);return;}
    if(b.id==='cw-routing-save')return saveRouting(false);
    if(b.id==='cw-routing-generate')return saveRouting(true);
    if(b.dataset.cwExport)return exportAction(b.dataset.cwExport);
    if(b.dataset.cwTemplate){applyTemplate(model,b.dataset.cwTemplate);lastError='';renderRules();renderStatus();if(model.output)renderOutput();host.toast('路由已替换为所选模板；其他配置保留。');return;}
    if(b.dataset.cwMove){if(moveRule(model,b.dataset.id,Number(b.dataset.cwMove))){renderRules();renderStatus();}return;}
    if(b.dataset.cwRemoveRule){model.rules=model.rules.filter(r=>r.id!==b.dataset.cwRemoveRule||r.type==='MATCH');changed();renderRules();return;}
    if(b.dataset.cwRemoveGroup){const id=b.dataset.cwRemoveGroup,g=model.groups.find(g=>g.id===id);if(!g)return;if(!global.confirm('删除策略组“'+g.name+'”？引用它的路由将改为 DIRECT。'))return;model.groups=model.groups.filter(g=>g.id!==id);model.rules.forEach(r=>{if(r.target==='group:'+id)r.target='DIRECT';});syncMembers(model);changed();renderGroups();renderRules();return;}
    if(b.id==='cw-read')return readNodes();if(b.id==='cw-generate')return generate();
    if(b.id==='cw-next')return selectEditor(EDITORS[EDITORS.indexOf(activeEditor)+1]||'output');
    if(b.id==='cw-source-all'){model.sourceIds=initialSources(model.servers);invalidateSources();if(model.sourceIds.size<model.servers.length)host.toast('本次已选择前 16 个不同 SSH 地址；可取消后换选其他来源。');return;}
    if(b.id==='cw-node-all'||b.id==='cw-node-none'){model.selected=new Set(b.id==='cw-node-all'?model.nodes.filter(n=>n.available).slice(0,128).map(n=>n.id):[]);syncMembers(model);changed();renderNodes();renderChains();renderGroups();renderRules();return;}
    if(b.id==='cw-add-group'){if(model.groups.length>=16)return host.toast('每份配置最多 16 个策略组。',false);const id='g'+(++model.serial);let suffix=1;while(model.groups.some(g=>g.name==='策略组 '+suffix))suffix++;model.groups.push({id,name:'策略组 '+suffix,type:'select',members:selectedNodes(model).map(n=>'node:'+n.id),autoNodes:true,url:'https://www.gstatic.com/generate_204',interval:300});changed();renderGroups();renderRules();return;}
    if(b.id==='cw-add-rule'){if(model.rules.length>=200)return host.toast('每份配置最多 200 条路由规则。',false);model.rules.splice(Math.max(0,model.rules.length-1),0,{id:'r'+(++model.serial+10),type:'DOMAIN-SUFFIX',value:'',target:model.groups[0]?'group:'+model.groups[0].id:'DIRECT'});changed();renderRules();}
  }
  function onChange(event){
    const input=event.target;
    if(studioBusy)return;
    if(input.id==='cw-import-file')return loadImportFile(input.files?.[0]);
    if(input.id==='cw-import-format'){importFormat=input.value;importPreview=null;return;}
    if(input.dataset.cwChainField){const c=model.chains.find(c=>c.id===input.dataset.id);if(!c)return;c[input.dataset.cwChainField]=input.dataset.cwChainField==='enabled'?input.checked:input.value;syncMembers(model);changed();renderChains();renderGroups();renderRules();return;}
    if(input.dataset.cwHopChain){const c=model.chains.find(c=>c.id===input.dataset.cwHopChain),i=Number(input.dataset.index);if(c&&Number.isInteger(i)&&i>=0&&i<c.hops.length){c.hops[i]=input.value;changed();renderChains();}return;}
    if(input.dataset.cwDnsField||input.dataset.cwDnsList){const dns=model.advanced.dns||(model.advanced.dns={}),key=input.dataset.cwDnsField||input.dataset.cwDnsList;if(input.dataset.cwDnsList)dns[key]=input.value.split(/[\s,，;；]+/).map(cleanText).filter(Boolean);else if(['enable','respect-rules','ipv6'].includes(key))dns[key]=input.checked;else if(cleanText(input.value))dns[key]=cleanText(input.value);else delete dns[key];changed();el('cw-advanced-json').value=JSON.stringify(model.advanced,null,2);return;}
    if(input.id==='cw-routing-node'){selectRoutingNode(input.value);return;}
    if(input.id==='cw-routing-enabled'){const draft=routingDraft(model,model.routingNode);if(draft&&routeBusy?.id!==model.routingNode){draft.enabled=input.checked===true;routingTouch(draft);renderRouting();}return;}
    if(input.dataset.cwRoutePort){const draft=routingDraft(model,model.routingNode);if(draft&&routeBusy?.id!==model.routingNode&&['mixed_port','socks_port','http_port'].includes(input.dataset.cwRoutePort)){draft.ports[input.dataset.cwRoutePort]=input.value;routingTouch(draft);renderRoutingStatus();renderRoutingOutput();}return;}
    if(input.dataset.cwSource){const id=input.dataset.cwSource;if(input.checked){if(model.sourceIds.size>=16){input.checked=false;return host.toast('每次最多读取 16 台服务器。',false);}const source=model.servers.find(s=>String(s.id)===id);if(source&&model.servers.some(s=>model.sourceIds.has(String(s.id))&&sourceEndpoint(s)===sourceEndpoint(source))){input.checked=false;return host.toast('同一 SSH 地址和端口只需选择一次，请先取消重复来源。',false);}model.sourceIds.add(id);}else model.sourceIds.delete(id);invalidateSources();return;}
    if(input.dataset.cwNode){const id=input.dataset.cwNode,n=model.nodes.find(n=>n.id===id);if(!n?.available)return;if(input.checked){if(model.selected.size>=128){input.checked=false;return host.toast('每份配置最多选择 128 个节点。',false);}model.selected.add(id);}else model.selected.delete(id);syncMembers(model);changed();renderNodes();renderChains();renderGroups();renderRules();return;}
    if(input.dataset.cwMember){const g=model.groups.find(g=>g.id===input.dataset.groupId);if(!g)return;g.autoNodes=false;g.members=input.checked?[...new Set([...g.members,input.dataset.cwMember])]:g.members.filter(m=>m!==input.dataset.cwMember);changed();return;}
    if(input.dataset.cwGroupField){const g=model.groups.find(g=>g.id===input.dataset.id);if(!g)return;g[input.dataset.cwGroupField]=input.value;changed();if(['name','type'].includes(input.dataset.cwGroupField)){renderGroups();renderRules();}return;}
    if(input.dataset.cwRuleField){const r=model.rules.find(r=>r.id===input.dataset.id);if(!r||r.type==='MATCH'&&input.dataset.cwRuleField!=='target')return;r[input.dataset.cwRuleField]=input.dataset.cwRuleField==='no_resolve'?input.checked:input.value;changed();if(input.dataset.cwRuleField==='type')renderRules();return;}
    if(input.id==='cw-profile-name')model.profile.name=input.value;else if(input.id==='cw-mixed-port')model.profile.mixed_port=input.value;else return;changed();
  }
  function setServers(servers){
    if(!host||destroyed||!Array.isArray(servers))return;
    const previous=new Map(model.servers.map(s=>[String(s.id),sourceIdentity(s)]));
    const changedSource=(model.snapshot||reading)&&[...model.sourceIds].some(id=>!servers.some(s=>String(s.id)===id&&sourceIdentity(s)===previous.get(id)));
    const first=model.servers.length===0;model.servers=servers.map(s=>({...s}));model.sourceIds=new Set([...model.sourceIds].filter(id=>servers.some(s=>String(s.id)===id)));if(first)model.sourceIds=initialSources(servers);
    if(changedSource)invalidateSources();else{renderSources();renderStatus();}
  }
  function onInput(event){
    if(studioBusy)return;const input=event.target;
    if(input.id==='cw-node-search')renderNodes();
    else if(input.id==='cw-import-text'){importText=input.value;importPreview=null;studioMessage='内容已修改，请重新解析。';const p=root.querySelector?.('.cw-import-preview');if(p)p.remove();}
    else if(input.id==='cw-routing-domain-input'){const draft=routingDraft(model,model.routingNode);if(draft&&routeBusy?.id!==model.routingNode){draft.input=input.value;draft.error='';renderRoutingStatus();renderRoutingOutput();}}
    else if(input.dataset.cwDnsList||input.dataset.cwDnsField&&input.type!=='checkbox'||input.dataset.cwRoutePort||['cw-profile-name','cw-mixed-port'].includes(input.id))onChange(event);
    else if(input.dataset.cwGroupField||input.dataset.cwRuleField||input.dataset.cwChainField){const isGroup=Boolean(input.dataset.cwGroupField),isChain=Boolean(input.dataset.cwChainField),item=(isGroup?model.groups:isChain?model.chains:model.rules).find(v=>v.id===input.dataset.id),field=input.dataset.cwGroupField||input.dataset.cwChainField||input.dataset.cwRuleField;if(item&&!['type','target','enabled'].includes(field)){item[field]=input.value;changed();}}
  }
  function destroy(){destroyed=true;readEpoch++;exportEpoch++;focusEpoch++;studioEpoch++;studioBusy=false;importText='';importPreview=null;profiles=[];invalidateRouting();model.output=null;model.nodes=[];model.selected.clear();model.snapshot=null;blobUrls.forEach(url=>URL.revokeObjectURL(url));blobUrls.clear();}
  function init(context){if(host)return;host=context;root=el('clash-workspace');if(!root)return;root.innerHTML=shell();root.addEventListener('click',onClick);root.addEventListener('change',onChange);root.addEventListener('input',onInput);root.addEventListener('keydown',event=>{const formatTab=event.target.closest('[data-cw-route-format]');if(formatTab){if(['ArrowRight','ArrowLeft','Home','End'].includes(event.key)){event.preventDefault();const draft=routingDraft(model,model.routingNode);if(draft){draft.format=event.key==='Home'?'clash':event.key==='End'?'xray':draft.format==='clash'?'xray':'clash';renderRoutingOutput();el('cw-routing-format-'+draft.format).focus();}}return;}const tab=event.target.closest('[data-cw-tab]');if(!tab)return;const tabs=[...root.querySelectorAll('[data-cw-tab]')];let i=tabs.indexOf(tab);if(event.key==='ArrowRight')i=(i+1)%tabs.length;else if(event.key==='ArrowLeft')i=(i+tabs.length-1)%tabs.length;else if(event.key==='Home')i=0;else if(event.key==='End')i=tabs.length-1;else return;event.preventDefault();selectEditor(tabs[i].dataset.cwTab);tabs[i].focus();});setServers(context.getServers?.()||[]);renderAll();selectEditor(activeEditor);global.addEventListener?.('beforeunload',destroy);}
  const api={init,setServers,focusRoutingNode,activate:()=>{if(host)setServers(host.getServers?.()||model.servers);},invalidate:()=>{if(host)invalidateSources();},destroy};
  global.ClashWorkspace=api;
  // Pure draft operations are independently testable with fake data and no browser or SSH.
  if(typeof module!=='undefined'&&module.exports)module.exports={createModel,selectedNodes,syncMembers,touch,validate,moveRule,applyTemplate,exportDraft,acceptCatalog,acceptStudioCatalog,appendDomainRules,applyServicePreset,splitDnsTemplate,parseAdvanced,currentOutput,escape,normalizeDomain,parseDomainBatch,normalizeRouting,routingDraft,routingDirty,routingSignature,routingCurrentOutput,routingPorts,normalizeXray,normalizeSavedProfile};
})(typeof window!=='undefined'?window:globalThis);
