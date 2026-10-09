export const list=value=>Array.isArray(value)?value:[];
export const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

export const reportIsCurrent=(value,now)=>value?.freshness==='current'&&value.current_until>now;

// Only reduce the received display projection. Original reported fields remain
// intact, and a later local clock reading can never revive an excluded sample.
export function expireEvidence(snapshot,now){
  const devices=list(snapshot.devices).map(device=>{
    const value=device.evidence;if(!value)return device;
    const future=Date.parse(value.reported_at)>now+5000,current=reportIsCurrent(value,now)&&!future;
    const evidence={...value,freshness:current?'current':value.freshness==='current'?(future?'clock_unknown':'stale'):value.freshness,current_until:current?value.current_until:0,
      measurements:list(value.measurements).map(sample=>({...sample,current_until:current&&sample.current_until>now&&sample.observed_at<=now+5000?sample.current_until:0}))};
    return {...device,evidence,runtime_state:current?device.runtime_state:'unknown'};
  });
  const byID=new Map(devices.map(device=>[device.id,device]));
  const bounded=(value,owner,qualifies)=>reportIsCurrent(byID.get(owner)?.evidence,now)&&value.current_until>now&&qualifies(list(byID.get(owner)?.evidence?.measurements))?value:{...value,availability:'unknown',current_until:0};
  const valid=sample=>sample.current_until>now;
  return {...snapshot,devices,paths:list(snapshot.paths).map(value=>bounded(value,value.device,samples=>list(value.targets).every(target=>samples.some(sample=>valid(sample)&&sample.level==='service'&&sample.service_id===value.service_id&&sample.candidate_id===value.candidate_id&&sample.spec_digest===value.spec_digest&&sample.target===target&&sample.result===value.availability)))),links:list(snapshot.links).map(value=>bounded(value,value.from,samples=>samples.some(sample=>valid(sample)&&sample.level==='link'&&sample.link_id===value.id&&sample.result===value.availability)))};
}

export function nextEvidenceExpiry(snapshot,now){
  const ends=[...list(snapshot.paths),...list(snapshot.links)].map(v=>v.current_until);
  for(const device of list(snapshot.devices)){
    ends.push(device.evidence?.current_until);
    for(const sample of list(device.evidence?.measurements))ends.push(sample.current_until);
  }
  return ends.filter(value=>Number.isSafeInteger(value)&&value>now).reduce((left,right)=>left===0?right:Math.min(left,right),0);
}

// A report is an observation at its timestamp, not an installation receipt.
export function componentComparisons(device,report){
  const key=value=>value.component_id+'\0'+value.platform,expected=new Map(list(device?.expected_components).map(v=>[key(v),v])),actual=new Map(list(report?.components).map(v=>[key(v),v]));
  return [...new Set([...expected.keys(),...actual.keys()])].sort().map(id=>{
    const wanted=expected.get(id),observed=actual.get(id),value=wanted||observed;
    const result=device?.component_error?'unavailable':!wanted?'unconfigured':!observed?'missing':!wanted.artifact_digest||!observed.artifact_digest?'unknown':wanted.artifact_digest===observed.artifact_digest&&wanted.version===observed.version?'reported_match':'reported_mismatch';
    return {component_id:value.component_id,platform:value.platform,expected:wanted,actual:observed,result};
  });
}
export async function expectedComponentID(value){
  const identity={node_id:value.node_id,component_id:value.component_id,platform:value.platform},bytes=new TextEncoder().encode('loom-expected-component-v3\0'+canonical(identity));
  const digest=await crypto.subtle.digest('SHA-256',bytes);
  return 'sha256:'+Array.from(new Uint8Array(digest),v=>v.toString(16).padStart(2,'0')).join('');
}
export function topologyPositions(nodes){
  const sorted=[...nodes].sort((a,b)=>Number(!!b.Control)-Number(!!a.Control)||a.ID.localeCompare(b.ID));
  let inner=sorted.filter(n=>n.Direction!=='reverse_only'),outer=sorted.filter(n=>n.Direction==='reverse_only');
  if(!outer.length&&inner.length>1)outer=inner.splice(Math.ceil(inner.length/2));
  const positions=new Map();
  [inner,outer].forEach((group,ring)=>group.forEach((node,index)=>{
    const angle=-90+(ring?180/group.length:0)+index*360/group.length,radians=angle*Math.PI/180;
    positions.set(node.ID,{x:480+(ring?310:170)*Math.cos(radians),y:180+(ring?130:75)*Math.sin(radians),angle,ring:ring?'outer':'inner'});
  }));
  return positions;
}

// Canonical command encoding shares the contract's JSON rules. It does not
// repair authority values: UI fields construct and sort their own draft sets.
export function canonical(value){
  if(typeof value==='string'){
    if(value.isWellFormed&&!value.isWellFormed())throw Error('Text contains an invalid Unicode sequence.');
    return '"'+value.replace(/["\\\u0000-\u001f]/g,c=>c==='"'?'\\"':c==='\\'?'\\\\':'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))+'"';
  }
  if(typeof value==='boolean')return String(value);
  if(typeof value==='number'&&Number.isSafeInteger(value)&&!Object.is(value,-0))return String(value);
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  if(value&&Object.getPrototypeOf(value)===Object.prototype)return '{'+Object.keys(value).sort().map(key=>canonical(key)+':'+canonical(value[key])).join(',')+'}';
  throw Error('Unsupported command value.');
}
export function targetDependencies(targets,kind,id,required=false){
  const target=list(targets).find(v=>v.target_kind===kind&&v.target_id===id);
  if(required&&(!target||target.deleted||target.conflicted))throw Error(`${kind} ${id} is unavailable in this reviewed draft.`);
  return list(target?.material_ids);
}
export function parseMatchers(text){
  return String(text).split(/\n/).map(v=>v.trim()).filter(Boolean).map(line=>{
    const parts=line.split(/\s+/);if(parts.length!==2||!['dns_exact','dns_suffix','ip_prefix'].includes(parts[0]))throw Error('Use one “kind value” matcher per line.');
    return {kind:parts[0],value:parts[1]};
  }).sort((a,b)=>a.kind<b.kind?-1:a.kind>b.kind?1:a.value<b.value?-1:a.value>b.value?1:0);
}
