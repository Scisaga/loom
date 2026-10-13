import {esc,list,reportIsCurrent} from './model.js';

function originalTransfer(sample){
 const value=sample?.hy2_transfer;
 if(sample?.level!=='resource'||sample.action!=='hysteria2_tls'||sample.result!=='available'||!value||!Number.isSafeInteger(value.duration_ns)||value.duration_ns<=0)return null;
 try{
  const bytes=[value.tx_bytes,value.rx_bytes].map(raw=>typeof raw==='string'&&/^[1-9][0-9]*$/.test(raw)?BigInt(raw):0n);
  if(bytes.some(raw=>raw<=0n||raw>18446744073709551615n))return null;
  return {tx:bytes[0],rx:bytes[1],ns:value.duration_ns};
 }catch{return null}
}

const rate=(bytes,ns)=>{const value=8000*Number(bytes)/ns;return value<.001?'<0.001 Mbps':`${value.toFixed(3)} Mbps`};

export function hy2TransferHTML(sample,now){
 const value=originalTransfer(sample);
 return `<div data-hy2-transfer>${esc(hy2TransferRateText(sample,now))}<small>Small authentication exchange · UDP payload includes QUIC/TLS overhead and retransmissions · not capacity or business usage</small>${value?`<small>Reported TX ${esc(String(value.tx))} B · RX ${esc(String(value.rx))} B · ${(value.ns/1e6).toFixed(3)} ms</small>`:''}</div>`;
}

export function hy2TransferRateText(sample,now){
 const value=originalTransfer(sample);
 return value&&sample.current_until>now?`Hy2 probe TX: ${rate(value.tx,value.ns)} · RX: ${rate(value.rx,value.ns)}`:'Hy2 authentication probe rate: Unknown';
}

// Public first-hop rows follow certified candidates, never fabricated LinkIDs.
export function hy2FirstHopRows(projection,now){
 const rows=[],devices=new Map(list(projection.devices).map(device=>[device.id,device]));
 for(const device of devices.values()){
  if(!device.authorized)continue;
  const resources=new Map();
  for(const path of list(projection.paths)){
   if(path.device!==device.id||path.first_transport!=='hysteria2'||!path.first_resource_id||!list(path.chain).length||path.chain[0]===device.id)continue;
   resources.set(path.first_resource_id,path.chain[0]);
  }
  for(const [resource,owner]of [...resources].sort(([a],[b])=>a<b?-1:a>b?1:0)){
   const samples=list(device.evidence?.measurements).filter(sample=>sample.level==='resource'&&sample.action==='hysteria2_tls'&&sample.resource_id===resource);
   const sample=samples.length===1?samples[0]:null;
   const bounded=reportIsCurrent(device.evidence,now)?sample:sample?{...sample,current_until:0}:null;
   const current=bounded?.current_until>now;
   const scope=`${device.id} → ${owner}`;
   rows.push(`<tr data-hy2-resource="${esc(resource)}" data-hy2-device="${esc(device.id)}"><td><a href="/devices/${encodeURIComponent(device.id)}#device-measurements" data-nav>${esc(device.name||device.id)} → ${esc(devices.get(owner)?.name||owner)}</a><small class="mono">${esc(resource)}</small></td><td>${current?esc(sample.result):'unknown'}<small>Selected credential authentication only; Service outcomes remain separate</small></td><td>${hy2TransferHTML(bounded,now)}</td><td class="mono">${esc(sample?.target||'Unknown')}<small>${esc(scope)} · ${esc(sample?.network_generation||'Unknown network generation')}</small><small>${sample?esc(new Date(sample.observed_at).toISOString()):'No reported sample'}</small><small>${esc(sample?.spec_digest||'Unknown specification')}</small></td></tr>`);
  }
 }
 return rows.join('');
}
