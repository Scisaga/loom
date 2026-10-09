import {canonical,targetDependencies} from './model.js';

const rows = value => Array.isArray(value) ? value : [];
const requestURL = (id,generation) => `/api/control/website/${encodeURIComponent(id)}/${generation}/request`;

export function websiteManagementHTML(projection,{esc,table,draftAttributes,canOperate}) {
 const owner=rows(projection.members).find(v=>v.node_id===projection.local_node_id)?.control_id;
 const entries=rows(projection.website_generations),requests=rows(projection.website_requests),connection=projection.website_connection;
 const writable=canOperate('endpoint.put');
 const expected=new URLSearchParams(location.search),expectedID=expected.get('website'),expectedGeneration=expected.get('generation');
 const verified=connection&&connection.id===expectedID&&String(connection.generation)===expectedGeneration;
 const proof=expectedID?`<p data-website-verification="${verified?'verified':'unverified'}">${verified?'New website entry verified through this authenticated browser connection.':'Requested entry has not been verified: this connection reached another entry, generation, or a debug interface.'}</p>`:'';
 const observed=connection?`<p data-website-connection>${esc(connection.id)} · generation ${esc(connection.generation)} · ${esc(connection.certificate_digest)}</p>`:'<p>This connection has no authenticated control.loom entry readback. Debug access does not verify a website certificate.</p>';
 const button=(entry,action,label)=>`<button type="button" data-website-action="${action}" data-endpoint="${esc(JSON.stringify(entry))}" ${draftAttributes()}>${label}</button>`;
 const entriesHTML=entries.map(entry=>{
  const local=entry.owner_control_id===owner,latest=!entries.some(v=>v.id===entry.id&&BigInt(v.generation)>BigInt(entry.generation));
  let actions='';
  if(local){
   const base=`/api/control/website/${encodeURIComponent(entry.id)}/${entry.generation}`;
   actions=`<a class="button" href="${base}/leaf" download>Download certificate</a><a class="button" href="${base}/chain" download>Download chain</a>`;
   if(writable){
    if(latest&&entry.state==='serving')actions+=button(entry,'request','Prepare renewal');
    if(entry.state==='prepared')actions+=button(entry,'serve','Activate after TLS preflight');
    if(entry.state==='serving'){
     actions+=`<a class="button" href="https://control.loom:${entry.port}/settings?website=${encodeURIComponent(entry.id)}&generation=${entry.generation}">Verify this entry in browser</a>`;
     if(connection?.id===entry.id&&BigInt(connection.generation)>BigInt(entry.generation))actions+=button(entry,'drain-previous','Drain previous generation');
     actions+=button(entry,'stop','Stop this generation');
    }
    if(entry.state==='draining')actions+=button(entry,connection?.id===entry.id&&BigInt(connection.generation)>BigInt(entry.generation)?'retire-previous':'retire','Retire after sessions end');
   }
  }else actions='Inspect the owning control for certificate operations.';
  return `<tr data-website-entry="${esc(entry.id)}" data-generation="${entry.generation}" data-state="${entry.state}"><td><b>${esc(entry.id)}</b><small>${esc(entry.owner_control_id)} · generation ${entry.generation}</small><small>${esc(entry.host)}:${entry.port}</small></td><td>${esc(entry.state)}${entry.state==='prepared'?'<small>Actual address and TLS protocol are checked again before activation.</small>':''}</td><td><div class="actions">${actions}</div></td></tr>`;
 }).join('');
 const requestRows=requests.filter(v=>!entries.some(e=>e.id===v.endpoint_id&&e.generation===v.generation&&e.state!=='prepared')).map(request=>{
  const label=`${request.endpoint_id} · generation ${request.generation}`;
  if(!request.available)return `<p>${esc(label)}: original request cannot be verified. Inspect protected local material; no key was regenerated.</p>`;
  const existing=entries.find(e=>e.id===request.endpoint_id&&e.generation===request.generation);
  const choices=rows(projection.public_trust).map(v=>`<option value="${esc(v.id)}" ${v.id===existing?.website_trust_id?'selected':''}>${esc(v.id)}</option>`).join('');
  return `<details data-key="website-request-${esc(request.endpoint_id)}-${request.generation}" data-website-request="${esc(request.endpoint_id)}" data-generation="${request.generation}"><summary>${esc(label)} · signing request available</summary><p><a class="button" href="${requestURL(request.endpoint_id,request.generation)}" download>Download bound signing request</a></p><p>Verify the network anchor, current membership and entry independently before signing offline. The leaf key remains here. Return only the public certificate or its authorized chain.</p>${writable&&!existing?`<form data-website-form="import" data-endpoint-id="${esc(request.endpoint_id)}" data-generation="${request.generation}" ${draftAttributes()}>
   <div class="field"><label>Authorized website root</label><select name="website_trust_id" required><option value="">Select the independently verified root</option>${choices}</select></div>
   <div class="field"><label>Signed public certificate</label><input type="file" name="certificate" accept=".pem,.crt" required></div>
   <div class="field"><label>Advertised address</label><input name="host" required placeholder="demo-control.example.com"><small>Use the operator-provided IP or underlay hostname.</small></div>
   <div class="field"><label>Advertised TCP port</label><input name="port" type="number" min="1" max="65535" required></div>
   <div class="field"><label>Local listener (IP:port)</label><input name="listen" required placeholder="192.0.2.10:443"><small>Renewal needs a separate address from the current certificate. No NAT or firewall is changed.</small></div>
   <p>The verified certificate and these execution inputs are immutable for this generation. Review the addresses before preparing.</p>
   <div class="service-save"><span role="alert"></span><button class="primary" type="submit">Validate and prepare entry</button></div></form>`:''}</details>`;
 }).join('');
 return `<section class="card" id="website-management"><h2>Website certificate operations</h2>${proof}${observed}${table(['ENTRY / OWNER','STAGE',''],entriesHTML)}${requestRows}${writable?`<details><summary>Prepare a new website entry</summary><form data-website-form="request" ${draftAttributes()}><div class="field"><label>New entry ID</label><input name="endpoint_id" required></div><div class="service-save"><span role="alert"></span><button type="submit">Generate bound signing request</button></div></form></details>`:''}<p>Website roots sign offline. A prepared entry is not available to ordinary clients. Keep the previous valid entry until the new entry has been verified in the browser.</p></section>`;
}

export async function submitWebsiteForm(element,{api,operate,refresh,toast,projection}) {
 if(element.submitting)return;
 element.submitting=true;
 const output=element.querySelector('[role=alert]'),form=new FormData(element);
 output.textContent='Submitting…';
 try{
  if(element.dataset.websiteForm==='request'){
   const id=String(form.get('endpoint_id'));
   if(rows(projection.website_generations).some(v=>v.id===id))throw Error('Select Prepare renewal on the existing entry.');
   await api(requestURL(id,1),{method:'POST'});
   toast('Original signing request is ready. Download it for offline verification and signing.');
  }else{
   const file=form.get('certificate');
   if(!(file instanceof File)||!file.size||file.size>65536)throw Error('Select a public PEM leaf certificate or chain.');
   const payload=await api('/api/control/website/certificate',{method:'POST',headers:{'Content-Type':'application/json'},body:canonical({endpoint_id:element.dataset.endpointId,generation:element.dataset.generation,website_trust_id:String(form.get('website_trust_id')),host:String(form.get('host')),port:Number(form.get('port')),listen:String(form.get('listen')),certificate_pem:await file.text()})});
   const targets=JSON.parse(element.dataset.targets),dependencies=[...targetDependencies(targets,'endpoint',payload.id),...targetDependencies(targets,'public_trust',payload.website_trust_id,true)];
   await operate('endpoint.put',payload,element.dataset.requestId,dependencies);
   toast('Certificate verified and entry prepared. Activation still requires a successful TLS preflight.');
  }
  element.submitting=false;await refresh();
 }catch(error){output.textContent=error.message;element.submitting=false}
}

export async function clickWebsiteAction(button,{api,operate,refresh,toast,operationBody}) {
 if(button.disabled)return;
 button.disabled=true;
 try{
  const entry=JSON.parse(button.dataset.endpoint),action=button.dataset.websiteAction;
  if(action==='request'){
   await api(requestURL(entry.id,String(BigInt(entry.generation)+1n)),{method:'POST'});
   toast('Signing request ready. The current certificate remains serving.');
  }else{
   const payload={...entry};
   if(action==='serve'){payload.state='serving';payload.drain_until=0}
   else if(action==='stop'||action==='drain-previous'){
    if(!confirm(action==='stop'?'Stop new connections to this generation and close remaining sessions after 60 seconds? Other generations keep their current state.':'The new generation is verified by this browser connection. Drain the previous generation for up to 60 seconds?'))return;
    payload.state='draining';payload.drain_until=Date.now()+60000;
   }else {payload.state='retired';payload.drain_until=0}
   const targets=JSON.parse(button.dataset.targets),dependencies=[...targetDependencies(targets,'endpoint',entry.id)];
   if(payload.state==='serving')dependencies.push(...targetDependencies(targets,'public_trust',entry.website_trust_id,true));
   if(action.endsWith('-previous'))await api('/api/control/website/retire-previous',{method:'POST',headers:{'Content-Type':'application/json'},body:operationBody('endpoint.put',payload,button.dataset.requestId,dependencies)});
   else await operate('endpoint.put',payload,button.dataset.requestId,dependencies);
   toast(payload.state==='serving'?'Entry is serving. Verify the actual certificate in the target browser before retiring the previous generation.':`Entry is ${payload.state}.`);
  }
  await refresh();
 }catch(error){toast(error.message,true)}finally{button.disabled=false}
}
