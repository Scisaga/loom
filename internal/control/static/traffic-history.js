import{esc,list}from'./model.js';

const integer=value=>typeof value==='bigint'?value:typeof value==='number'&&Number.isSafeInteger(value)&&value>=0?BigInt(value):typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value)?BigInt(value):null;
const hourMS=3600000;
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
 return {key:JSON.stringify([projection.network_id,projection.control_config_id,scope,binding,devices.map(v=>[v.id,v.authorized,list(v.dependencies)])]),version:JSON.stringify(devices.map(v=>[v.id,v.last_report_at,v.evidence?.report_sequence])),url:'/api/control/ui/traffic-history?'+new URLSearchParams({[kind]:id})};
}
export function validateTrafficHistory(data,scope){
 const fail=()=>{throw Error('Invalid WG traffic history.');},cut=scope.indexOf(':'),kind=scope.slice(0,cut),id=scope.slice(cut+1);
 if(!data||data.schema!==3||data.scope!==scope||!Number.isSafeInteger(data.from)||data.from<0||data.from%hourMS!==0||!Number.isSafeInteger(data.until)||Math.floor(data.until/hourMS)*hourMS-23*hourMS!==data.from||!Array.isArray(data.devices))fail();
 if(kind==='device'&&(data.devices.length!==1||data.devices[0]?.device_id!==id))fail();
 const identities=new Set(),maximum=(1n<<64n)-1n,delta=value=>{const rx=integer(value?.rx_bytes),tx=integer(value?.tx_bytes);if(!value||rx===null||tx===null||rx>maximum||tx>maximum||!Number.isSafeInteger(value.covered_ms)||value.covered_ms<=0||!Number.isSafeInteger(value.intervals)||value.intervals<=0||!Number.isSafeInteger(value.first_at)||!Number.isSafeInteger(value.last_at)||value.first_at<0||value.first_at>=value.last_at||value.last_at>data.until||value.covered_ms>value.last_at-value.first_at)fail()};
 for(const device of data.devices){
  if(!device||typeof device.device_id!=='string'||!device.device_id||identities.has(device.device_id)||!Array.isArray(device.buckets)||device.buckets.length!==24)fail();
  identities.add(device.device_id);
  device.buckets.forEach((bucket,index)=>{if(!bucket||bucket.hour!==data.from+index*hourMS)fail();if(bucket.delta!==undefined){delta(bucket.delta);if(bucket.delta.first_at<bucket.hour||bucket.delta.last_at>bucket.hour+hourMS)fail()}});
  if(device.recent!==undefined)delta(device.recent);
 }
 return data;
}
export function trafficSummary(projection,scope,entry){
 const request=trafficHistoryRequest(projection,scope),record=request&&entry?.key===request.key?entry:null;
 let data=null,error=record?.error;
 if(record?.data)try{data=validateTrafficHistory(record.data,scope)}catch(value){error=value.message}
 const result={scope:request?scope:null,rx:null,tx:null,forward:null,buckets:[],known:false,covered:0,data,error,current:!!record&&record.version===request.version};
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
export function networkTrafficSummary(projection,histories){
 const scope='network:'+projection.network_id,devices=list(projection.devices).filter(device=>device.authorized),summaries=devices.map(device=>trafficSummary(projection,'device:'+device.id,histories.get('traffic:device:'+device.id))),ready=summaries.filter(value=>value.data);
 // Independently queried sources keep their own cutoff. A newer UTC window only
 // includes overlapping original buckets; missing endpoints and hours stay unknown.
 const from=ready.length?Math.max(...ready.map(value=>value.data.from)):null,cutoffs=ready.map(value=>value.data.until),sources=ready.flatMap(value=>value.data.devices);
 const result={scope,rx:null,tx:null,forward:null,buckets:[],known:false,covered:0,data:ready.length?{from,devices:sources}:null,current:summaries.every(value=>value.current),loaded:ready.length,total:devices.length,failed:summaries.filter(value=>value.error).length,cutoffs};
 if(from!==null)for(let index=0;index<24;index++){
  const hour=from+index*hourMS,values=sources.flatMap(device=>device.buckets.filter(bucket=>bucket.hour===hour&&bucket.delta).map(bucket=>bucket.delta)),bucket={hour,rx:null,tx:null,coveredMS:0,intervals:0};
  if(values.length){bucket.rx=0n;bucket.tx=0n;for(const value of values){bucket.rx+=integer(value.rx_bytes);bucket.tx+=integer(value.tx_bytes);bucket.coveredMS+=value.covered_ms;bucket.intervals+=value.intervals}result.rx=(result.rx??0n)+bucket.rx;result.tx=(result.tx??0n)+bucket.tx;result.covered++}
  result.buckets.push(bucket);
 }
 result.forward=result.tx;result.known=result.covered>0;
 if(!ready.length&&result.failed)result.error='WG traffic could not be read.';
 return result;
}
function hourBar(bucket,metric,maximum,endpoint=''){
 const value=bucket[metric],height=value===null?0:Number((value*10n+maximum-1n)/maximum),hour=new Date(bucket.hour).toISOString();
 const title=(endpoint?endpoint+' · ':'')+(value===null?`${hour} · Unknown: no valid adjacent samples`:`${hour} · ${metric.toUpperCase()} ${value} WG packet bytes · ${bucket.coveredMS/1000} endpoint seconds · ${bucket.intervals} intervals`);
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

function pairedBars(summary){
 const maximum=summary.buckets.reduce((value,bucket)=>['rx','tx'].reduce((v,key)=>bucket[key]!==null&&bucket[key]>v?bucket[key]:v,value),1n);
 return `<div class="wg-traffic-hours wg-paired-hours" aria-label="24 hourly WG RX and TX observed deltas">${summary.buckets.map(bucket=>`<span class="wg-traffic-group">${hourBar(bucket,'rx',maximum)}${hourBar(bucket,'tx',maximum)}</span>`).join('')}</div><div class="wg-paired-legend"><small>RX ${trafficBytes(summary.rx)}</small><small>TX ${trafficBytes(summary.tx)}</small></div>`;
}

export function trafficHistoryHTML(summary,both=false,compact=false,endpoints=false){
 if(!summary.scope)return '<small>WG traffic unavailable for this authorization.</small>';
 if(summary.total===0)return `<div class="wg-traffic ${compact?'compact':''}" data-traffic-scope="${esc(summary.scope)}" data-traffic-loaded="0" data-traffic-total="0" data-traffic-failed="0"><small>No authorized devices for WG history.</small></div>`;
 let contents='<small>Loading WG counters…</small>';
 if(summary.error)contents=`<small title="${esc(summary.error)}">WG traffic could not be read.</small>`;
 else if(summary.data){
  contents=both&&compact?pairedBars(summary):`${both?`<small>RX ${trafficBytes(summary.rx)}</small>${bars(summary,'rx')}<small>TX ${trafficBytes(summary.tx)}</small>`:''}${endpoints?endpointBars(summary):bars(summary,'tx')}<small>${summary.covered}/24 hours with observed deltas${compact?'':' · partial coverage'}</small>`;
 }
 const aggregate=summary.total!==undefined,cutoffs=list(summary.cutoffs),first=cutoffs.length?new Date(Math.min(...cutoffs)).toISOString():'',last=cutoffs.length?new Date(Math.max(...cutoffs)).toISOString():'',sameDay=first.slice(0,10)===last.slice(0,10),clock=value=>value.slice(sameDay?11:0,19).replace('T',' '),range=first?clock(first)+(clock(first)===clock(last)?'':' – '+clock(last))+' UTC':'',cutoff=aggregate&&first?`<span title="${esc('Query cutoffs '+first+(first===last?'':' – '+last))}">Cutoffs ${esc(range)}</span>`:summary.data&&!compact?'As of '+esc(new Date(summary.data.until).toISOString()):'',coverage=aggregate?`<small>${summary.loaded} / ${summary.total} devices loaded${summary.failed?' · '+summary.failed+' failed':summary.loaded<summary.total?' · partial':''}</small>`:'';
 const retry=summary.error||summary.failed?`<button type="button" class="tiny" data-traffic-retry="${esc(summary.scope)}">Retry</button>`:'';
 return `<div class="wg-traffic ${compact?'compact':''}" data-traffic-scope="${esc(summary.scope)}"${aggregate?` data-traffic-loaded="${summary.loaded}" data-traffic-total="${summary.total}" data-traffic-failed="${summary.failed}"`:''}>${contents}${coverage}${retry||cutoff?`<small>${retry}${retry&&cutoff?' · ':''}${cutoff}</small>`:''}</div>`;
}
export function trafficRates(summary,now){
 return list(summary.data?.devices).map(device=>{
  const value=device.recent,valid=summary.current!==false&&value&&value.covered_ms>0&&value.last_at+180000>now;
  const thousandths=valid?integer(value.tx_bytes)*8n/BigInt(value.covered_ms):null;
  const rate=thousandths===null?'Unknown':thousandths===0n&&integer(value.tx_bytes)>0n?'<0.001 Mbps':`${thousandths/1000n}.${String(thousandths%1000n).padStart(3,'0')} Mbps`;
  return {id:device.device_id,text:device.device_id+' TX: '+rate,detail:'Shared WG peer sent packets; includes handshakes, keepalives and encrypted overhead; forward and reverse rows share counters'+(valid?' · '+value.covered_ms/1000+' seconds · through '+new Date(value.last_at).toISOString():'')};
 });
}
export function trafficRatesHTML(summary,now){
 const rates=trafficRates(summary,now);
 return rates.length?rates.map(v=>`<small data-traffic-rate="${esc(v.id)}" title="${esc(v.detail)}">${esc(v.text)}</small>`).join(''):'<small>WG TX rate: Unknown</small>';
}
export function trafficNextExpiry(histories,now){
 let until=0;for(const [id,item]of histories){if(!id.startsWith('traffic:'))continue;for(const device of list(item.data?.devices)){const expiry=device.recent?.last_at+180000;if(expiry>now&&(!until||expiry<until))until=expiry}}return until;
}
