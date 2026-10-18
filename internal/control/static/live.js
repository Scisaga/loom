// The base belongs only to this ordered connection. Display expiry and HTTP
// readbacks never change it; reconnect always starts with a complete snapshot.
export function applyLive(previous,message){
 const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value),owns=(value,key)=>Object.hasOwn(value,key);
 if(!object(message)||message.schema!==3)throw Error('Invalid live envelope.');
 const keys=Object.keys(message).sort().join(',');
 if(keys==='schema,snapshot'){
  if(!object(message.snapshot)||message.snapshot.schema!==3)throw Error('Invalid live snapshot.');
  return message.snapshot;
 }
 if(keys!=='changes,schema'||!object(previous)||!Array.isArray(message.changes)||!message.changes.length)throw Error('Live changes need a snapshot.');
 let result=structuredClone(previous);
 for(const change of message.changes){
  if(!object(change)||!Array.isArray(change.path)||change.path.some(key=>typeof key!=='string'||['__proto__','prototype','constructor'].includes(key)))throw Error('Invalid live path.');
  const removing=change.remove===true,fields=Object.keys(change).sort().join(',');
  if(fields!==(removing?'path,remove':'path,value')||!removing&&!owns(change,'value'))throw Error('Invalid live change.');
  if(!change.path.length){if(removing||!object(change.value)||change.value.schema!==3)throw Error('Invalid live root.');result=structuredClone(change.value);continue}
  let parent=result;
  const validIndex=(value,key)=>/^(0|[1-9][0-9]*)$/.test(key)&&Number.isSafeInteger(Number(key))&&Number(key)<value.length;
  for(const key of change.path.slice(0,-1)){
   if(!object(parent)&&!Array.isArray(parent)||!owns(parent,key)||Array.isArray(parent)&&!validIndex(parent,key))throw Error('Missing live parent.');
   parent=parent[key];
  }
  const key=change.path.at(-1);
  if(!object(parent)&&!Array.isArray(parent)||Array.isArray(parent)&&(!validIndex(parent,key)||removing)||removing&&!owns(parent,key))throw Error('Invalid live target.');
  if(removing)delete parent[key];else parent[key]=structuredClone(change.value);
 }
 if(!object(result)||result.schema!==3)throw Error('Invalid live projection.');
 return result;
}
