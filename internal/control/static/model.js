export const list=value=>Array.isArray(value)?value:[];
export const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
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
