import{esc,list}from'./model.js';

export function runtimeHistoryKey(projection,device){
 return JSON.stringify([projection.network_id,projection.control_config_id,device.id,device.authorized,list(device.dependencies)]);
}
export const runtimeHistoryVersion=device=>JSON.stringify([device.last_report_at,device.evidence?.view_digest,device.evidence?.runtime]);

export function runtimeHistoryHTML(projection,device,history){
 const current=device.runtime_state||'unknown',stateClass=current==='running'?'ok':current==='error'?'bad':'dim';
 const prefix=`<span class="${stateClass}">Runtime: ${esc(current)}</span>`;
 if(!device.authorized)return `${prefix}<small>Runtime history unavailable for this authorization.</small>`;
 const item=history?.key===runtimeHistoryKey(projection,device)?history:null;
 let contents='<small>Loading runtime samples…</small>';
 if(item?.error)contents='<small>Runtime history could not be read.</small><button type="button" class="tiny" data-runtime-history-retry="'+esc(device.id)+'">Retry</button>';
 else if(item?.data){
  const data=item.data,slots=list(data.buckets).map(bucket=>{
   const sample=bucket.sample,state=sample?.state||'missing',hour=new Date(bucket.hour).toISOString().slice(0,16)+' UTC';
   const title=sample?`${hour} · sampled ${new Date(sample.reported_at).toISOString()} · ${state}\nView: ${sample.view_digest}\nApplied: ${sample.applied_view_digest||'none'}\nError: ${sample.error_code||'none'}\nReport: ${sample.report_id} · sequence ${sample.report_sequence}`:`${hour} · No valid runtime sample`;
   return `<span class="runtime-hour ${esc(state)}" data-runtime-hour="${bucket.hour}" data-runtime-state-sample="${esc(state)}" tabindex="0" title="${esc(title)}" aria-label="${esc(title)}"></span>`;
  }).join('');
  contents=`<div class="runtime-hours" aria-label="24 hourly runtime samples; not continuous uptime">${slots}</div><small title="As of ${esc(new Date(data.until).toISOString())}">24 hourly samples · not uptime <button type="button" class="tiny" data-runtime-history-retry="${esc(device.id)}">Refresh</button></small>`;
 }
 return `${prefix}<div data-runtime-history="${esc(device.id)}">${contents}</div>`;
}
