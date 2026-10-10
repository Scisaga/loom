import{esc,list}from'./model.js';

const integer=value=>typeof value==='bigint'?value:typeof value==='number'&&Number.isSafeInteger(value)&&value>=0?BigInt(value):typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value)?BigInt(value):null;
export function trafficBytes(value){
 let amount=integer(value);if(amount===null)return 'Unknown';
 let divisor=1n,unit='B';for(const next of ['KiB','MiB','GiB','TiB','PiB','EiB']){if(amount/divisor<1024n)break;divisor*=1024n;unit=next}
 const tenths=amount*10n/divisor;
 return `${tenths/10n}${unit==='B'?'':'.'+tenths%10n} ${unit}`;
}
export function trafficHistoryRequest(projection,scope){
 const cut=scope.indexOf(':'),kind=scope.slice(0,cut),id=scope.slice(cut+1);let devices=[],binding='';
 if(kind==='network'&&id===projection.network_id)devices=list(projection.devices).filter(v=>v.authorized);
 else if(kind==='device'){const value=list(projection.devices).find(v=>v.id===id&&v.authorized);if(!value)return null;devices=[value]}
 else if(kind==='link'){const link=list(projection.links).find(v=>v.id===id&&v.authorized&&v.spec_digest);if(!link)return null;devices=[link.from,link.to].map(id=>list(projection.devices).find(v=>v.id===id&&v.authorized));if(devices.some(v=>!v))return null;binding=[link.from,link.to,link.resource_id,link.spec_digest]}
 else return null;
 return {key:JSON.stringify([projection.network_id,projection.control_config_id,scope,binding,devices.map(v=>[v.id,v.authorized,list(v.dependencies)])]),version:JSON.stringify(devices.map(v=>[v.id,v.last_report_at])),url:'/api/control/ui/traffic-history?'+new URLSearchParams({[kind]:id})};
}
export function trafficSummary(projection,scope,entry){
 const request=trafficHistoryRequest(projection,scope),record=request&&entry?.key===request.key?entry:null;
 const data=record?.data?.scope===scope?record.data:null;
 const result={scope:request?scope:null,rx:null,tx:null,forward:null,buckets:[],known:false,covered:0,data,error:record?.error,current:!!record&&record.version===request.version};
 if(!data)return result;
 for(let i=0;i<24;i++){
  const hour=data.from+i*3600000,values=list(data.devices).flatMap(v=>list(v.buckets).filter(b=>b.hour===hour&&b.delta).map(b=>b.delta));
  const bucket={hour,rx:null,tx:null,coveredMS:0,intervals:0};
  if(values.length){
   bucket.rx=0n;bucket.tx=0n;
   for(const value of values){const rx=integer(value.rx_bytes),tx=integer(value.tx_bytes);if(rx===null||tx===null)throw Error('Invalid traffic counter');bucket.rx+=rx;bucket.tx+=tx;bucket.coveredMS+=value.covered_ms;bucket.intervals+=value.intervals}
   result.rx=(result.rx??0n)+bucket.rx;result.tx=(result.tx??0n)+bucket.tx;result.covered++;
  }
  result.buckets.push(bucket);
 }
 result.forward=result.tx;result.known=result.covered>0;return result;
}
function hourBar(bucket,metric,maximum,endpoint=''){
 const value=bucket[metric],height=value===null?0:Number((value*10n+maximum-1n)/maximum),hour=new Date(bucket.hour).toISOString();
 const title=(endpoint?endpoint+' · ':'')+(value===null?`${hour} · Unknown: no valid adjacent samples`:`${hour} · ${metric.toUpperCase()} ${value} WG bytes · ${bucket.coveredMS/1000} endpoint seconds · ${bucket.intervals} intervals`);
 return `<span class="wg-traffic-hour ${value===null?'missing':value===0n?'zero':'bar-'+height}" data-traffic-value="${value===null?'unknown':value}" data-traffic-metric="${metric}" ${endpoint?`data-traffic-endpoint="${esc(endpoint)}"`:''} tabindex="0" title="${esc(title)}" aria-label="${esc(title)}"></span>`;
}
function bars(summary,metric){
 const maximum=summary.buckets.reduce((a,b)=>b[metric]!==null&&b[metric]>a?b[metric]:a,1n);
 return `<div class="wg-traffic-hours" aria-label="24 hourly WG ${metric.toUpperCase()} observed deltas">${summary.buckets.map(bucket=>hourBar(bucket,metric,maximum)).join('')}</div>`;
}
function endpointBars(summary){
 const endpoints=list(summary.data.devices).map(device=>({id:device.device_id,buckets:list(device.buckets).map(bucket=>({hour:bucket.hour,tx:bucket.delta?integer(bucket.delta.tx_bytes):null,coveredMS:bucket.delta?.covered_ms||0,intervals:bucket.delta?.intervals||0}))}));
 const maximum=endpoints.flatMap(v=>v.buckets).reduce((a,b)=>b.tx!==null&&b.tx>a?b.tx:a,1n);
 return `<div class="wg-endpoint-legend">${endpoints.map(v=>`<small>${esc(v.id)} TX: ${trafficBytes(v.buckets.reduce((a,b)=>b.tx===null?a:(a??0n)+b.tx,null))}</small>`).join('')}</div><div class="wg-traffic-hours wg-endpoint-hours" aria-label="24 hourly WG TX deltas grouped by endpoint">${summary.buckets.map((bucket,i)=>`<span class="wg-traffic-group">${endpoints.map(v=>hourBar(v.buckets[i],'tx',maximum,v.id)).join('')}</span>`).join('')}</div>`;
}

export function trafficHistoryHTML(summary,both=false,compact=false,endpoints=false){
 if(!summary.scope)return '<small>WG traffic unavailable for this authorization.</small>';
 let contents='<small>Loading WG counters…</small>';
 if(summary.error)contents='<small>WG traffic could not be read.</small>';
 else if(summary.data){
  contents=`${both?`<small>RX ${trafficBytes(summary.rx)}</small>${bars(summary,'rx')}<small>TX ${trafficBytes(summary.tx)}</small>`:''}${endpoints?endpointBars(summary):bars(summary,'tx')}<small>${summary.covered}/24 hours with observed deltas${compact?'':' · partial coverage'}</small>`;
 }
 return `<div class="wg-traffic ${compact?'compact':''}" data-traffic-scope="${esc(summary.scope)}">${contents}<small><button type="button" class="tiny" data-traffic-retry="${esc(summary.scope)}">${summary.error?'Retry':summary.data?'Refresh':'Reload'}</button>${summary.data&&!compact?' · as of '+esc(new Date(summary.data.until).toISOString()):''}</small></div>`;
}
export function trafficRates(summary,now){
 return list(summary.data?.devices).map(device=>{
  const value=device.recent,valid=summary.current!==false&&value&&value.covered_ms>0&&value.last_at+180000>now;
  const thousandths=valid?integer(value.tx_bytes)*8n/BigInt(value.covered_ms):null;
  const rate=thousandths===null?'Unknown':thousandths===0n&&integer(value.tx_bytes)>0n?'<0.001 Mbps':`${thousandths/1000n}.${String(thousandths%1000n).padStart(3,'0')} Mbps`;
  return {id:device.device_id,text:device.device_id+' TX: '+rate,detail:'Shared peer TX; observed rate, not capacity'+(valid?' · '+value.covered_ms/1000+' seconds · through '+new Date(value.last_at).toISOString():'')};
 });
}
export function trafficRatesHTML(summary,now){
 const rates=trafficRates(summary,now);
 return rates.length?rates.map(v=>`<small data-traffic-rate="${esc(v.id)}" title="${esc(v.detail)}">${esc(v.text)}</small>`).join(''):'<small>WG rate: Unknown</small>';
}
export function trafficNextExpiry(histories,now){
 let until=0;for(const [id,item]of histories){if(!id.startsWith('traffic:'))continue;for(const device of list(item.data?.devices)){const expiry=device.recent?.last_at+180000;if(expiry>now&&(!until||expiry<until))until=expiry}}return until;
}
