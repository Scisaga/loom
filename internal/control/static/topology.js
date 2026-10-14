import {esc, list, topologyPositions} from './model.js';

const pair = (a, b) => [a, b].sort().join('\0');
const n = value => Number(value.toFixed(1));
const hash = value => {
  let result = 2166136261;
  for (const character of value) result = Math.imul(result ^ character.codePointAt(0), 16777619) >>> 0;
  return result;
};

const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const linkKey = link => link.ID ? 'link:'+link.ID : 'first-hop:'+JSON.stringify([link.From,link.To,link.ResourceID||'',link.Transport]);

// A connection is a drawing of its original directional values, not a health
// value. Its identity survives selection changes and removal of either direction.
export function topologyConnections(links) {
  const groups = new Map();
  for (const link of list(links)) {
    const kind = link.Kind || 'tunnel', transport = link.Transport;
    const ends = [[link.From,link.FromResourceID||''],[link.To,link.ResourceID||'']].sort((a,b)=>compare(a[0],b[0])||compare(a[1],b[1]));
    const shared = kind !== 'first_hop' && transport === 'wireguard' && link.ID && link.FromResourceID && link.ResourceID;
    const key = shared ? 'connection:'+JSON.stringify([kind,transport,ends]) : linkKey(link);
    let group = groups.get(key);
    if (!group) {
      group = {key,links:[],from:ends[0][0],to:ends[1][0],kind,transport,fromResourceID:ends[0][1],resourceID:ends[1][1]};
      groups.set(key,group);
    }
    group.links.push(link);
  }
  return [...groups.values()].map(group=>({...group,links:group.links.sort((a,b)=>compare(linkKey(a),linkKey(b)))})).sort((a,b)=>compare(a.key,b.key));
}

// Line patterns summarize only the present, original WG DNS directions. A
// missing authorized reverse direction is never an unavailable observation.
export function topologyConnectionAppearance(group) {
  const values = new Map();
  for (const link of group.links) {
    const key=JSON.stringify([link.From,link.To]),direction=values.get(key)||{from:link.From,to:link.To,samples:[]};
    direction.samples.push(['available','unavailable'].includes(link.State)?link.State:'unknown');
    values.set(key,direction);
  }
  const directions=[...values.values()].map(value=>({from:value.from,to:value.to,state:value.samples.length===1?value.samples[0]:'unknown'})).sort((a,b)=>compare(a.from,b.from)||compare(a.to,b.to));
  const singleDirection=directions.length===1;
  let pattern='unknown',direction=null;
  if(directions.length&&directions.every(value=>value.state!=='unknown')){
    const available=directions.filter(value=>value.state==='available');
    if(available.length===directions.length){
      pattern=singleDirection?'dashed':'solid';
      if(singleDirection)direction={from:available[0].from,to:available[0].to};
    }
    else if(!available.length)pattern='dotted';
    else if(directions.length===2){pattern='dashed';direction={from:available[0].from,to:available[0].to}}
  }
  return {pattern,direction,singleDirection,directions};
}

function connectionLink(edge, view) {
  return edge.links.find(link=>link.ID===view.SelectedLink) || edge.links.find(link=>link.ID===view.PinnedLink) ||
    edge.links.find(link=>edge.routeLinks.has(link.ID)) || edge.links[0];
}

const connectionIDs = edge => edge.links.map(link=>link.ID).filter(Boolean);
const includesLink = (edge, id) => !!id && connectionIDs(edge).includes(id);

function curve(a, b, key, kind, lane = null) {
  if (lane === null && kind === 'first_hop' && a.ring === b.ring) {
    const delta = (b.angle - a.angle + 360) % 360;
    return {d: `M ${n(a.x)} ${n(a.y)} A ${n(a.rx)} ${n(a.ry)} 0 0 ${delta > 180 ? 0 : 1} ${n(b.x)} ${n(b.y)}`};
  }
  const dx = b.x - a.x, dy = b.y - a.y, distance = Math.hypot(dx, dy) || 1;
  const bend = lane ?? (kind==='first_hop' ? (hash(key)%2?24:-24) : 0);
  const cx = (a.x + b.x) / 2 - dy / distance * bend, cy = (a.y + b.y) / 2 + dx / distance * bend;
  return {d: `M ${n(a.x)} ${n(a.y)} Q ${n(cx)} ${n(cy)} ${n(b.x)} ${n(b.y)}`};
}

function subtitle(node) {
  return [node.Location, list(node.Roles).map(role=>role.replaceAll('_',' ')).join(' · ')].filter(Boolean).join(' · ');
}

function labelLines(value, limit) {
  const lines=[];let line='',used=0;
  for(const word of String(value).trim().split(/\s+/)){
    const length=[...word].reduce((sum,c)=>sum+(c.codePointAt(0)<128?1:2),0);
    if(line&&used+1+length>limit){lines.push(line);line='';used=0}
    if(line){line+=' ';used++}
    for(const character of word){
      const units=character.codePointAt(0)<128?1:2;
      if(used+units>limit){lines.push(line);line='';used=0}
      line+=character;used+=units;
    }
  }
  if (line) lines.push(line);
  return lines;
}

function layout(nodes, compact) {
  const positions=topologyPositions(nodes), labels=new Map(), base=compact?280:405;
  const units=line=>[...line].reduce((sum,c)=>sum+(c.codePointAt(0)<128?1:2),0);
  let height=base;
  for(let attempt=0;attempt<80;attempt++,height+=80){
    const cy=height*(compact?.44:.42),outerRY=height*(compact?.38:.44),outerRX=288;
    labels.clear();const boxes=[];
    for(const node of nodes){
      const point=positions.get(node.ID),ratio=point.ring==='outer'?1:.58,angle=point.angle*Math.PI/180;
      point.rx=outerRX*ratio;point.ry=outerRY*(point.ring==='outer'?1:.59);
      point.x=480+point.rx*Math.cos(angle);point.y=cy+point.ry*Math.sin(angle);
      const middle=Math.abs(point.x-480)<1,top=middle&&point.y<cy,anchor=middle?'middle':point.x<480?'end':'start',x=middle?point.x:point.x+(point.x<480?-18:18);
      const available=middle?440:point.x<480?x-8:952-x;
      const name=labelLines(node.Name||node.ID,Math.min(24,Math.floor(available/8))),detail=labelLines(subtitle(node),Math.min(32,Math.floor(available/6)));
      const y=middle?top?point.y-22-(name.length-1)*15:point.y+24:point.y-2-(name.length-1)*7.5;
      const sub=top?y-18-(detail.length-1)*12:y+name.length*15+5;
      labels.set(node.ID,{id:node.ID,point,name,detail,x,y,sub,anchor});
      const width=Math.max(0,...name.map(line=>units(line)*8),...detail.map(line=>units(line)*6));
      const left=anchor==='end'?x-width:anchor==='middle'?x-width/2:x,upper=Math.min(y-13,sub-10),bottom=Math.max(y+(name.length-1)*15+3,sub+(detail.length-1)*12+3);
      boxes.push({left,right:left+width,top:upper,bottom});
    }
    const fits=boxes.every(box=>box.left>=8&&box.right<=952&&box.top>=5&&box.bottom<=height-5);
    const overlap=boxes.some((a,i)=>boxes.slice(i+1).some(b=>a.left<b.right+8&&b.left<a.right+8&&a.top<b.bottom+8&&b.top<a.bottom+8));
    if(fits&&!overlap)return {positions,labels,height,cy,outerRY,outerRX};
  }
  return {positions,labels,height,cy:height*(compact?.44:.42),outerRY:height*(compact?.38:.44),outerRX:288};
}

export function topologyHTML(view, routes = [], id = 'network') {
  const nodes = list(view.Nodes).filter(node => node.ID);
  const compact = id === 'overview-topology', diagram = layout(nodes, compact), {positions,labels} = diagram;
  const selected = new Set(), direct = new Set(), routeEdges = new Map(), pairs = new Map();
  const edges = topologyConnections(list(view.Links).filter(link => positions.has(link.From) && positions.has(link.To)))
    .map(group => {
      const appearance=group.kind!=='first_hop'&&group.transport==='wireguard'?topologyConnectionAppearance(group):null;
      const edge={...group,appearance,hasRoute:false,routeLinks:new Set()}, peers=pairs.get(pair(group.from,group.to))||[];
      peers.push(edge);pairs.set(pair(group.from,group.to),peers);
      return edge;
    });
  for(const [key,peers] of pairs){
    peers.sort((a,b)=>compare(a.key,b.key));
    for(const [index,edge] of peers.entries()){
      edge.path={...curve(positions.get(edge.from),positions.get(edge.to),key,edge.kind,peers.length>1?(index-(peers.length-1)/2)*80:null),from:edge.from};
    }
  }
  for (const route of routes) {
    const chain = list(route.Chain);
    for (const node of chain) selected.add(node);
    if (chain.length === 1) {
      direct.add(chain[0]);
      continue;
    }
    for (let index = 0; index + 1 < chain.length; index++) {
      if (positions.has(chain[index]) && positions.has(chain[index + 1])) {
        if(index===0&&route.FirstTransport&&(route.FirstTransport==='wireguard'?view.ShowWG===false:view.ShowHy2===false))continue;
        if(index>0&&view.ShowWG===false)continue;
        const from=chain[index],to=chain[index+1],first=index===0&&!!route.FirstTransport;
        const linkID=list(route.LinkIDs)[index-(route.FirstTransport?1:0)];
        const edge=edges.find(group=>group.links.some(link=>link.From===from&&link.To===to&&(first?
          link.Kind==='first_hop'&&link.Transport===route.FirstTransport&&(!route.FirstResourceID||link.ResourceID===route.FirstResourceID):
          link.Kind!=='first_hop'&&(!linkID||link.ID===linkID))));
        if(!edge&&(first?route.FirstResourceID:linkID))continue;
        const key=edge?.key||JSON.stringify([from,to,first?route.FirstResourceID||route.FirstTransport:linkID||'']);
        const actualLink=edge?.links.find(link=>link.From===from&&link.To===to&&(first?link.Kind==='first_hop':!linkID||link.ID===linkID));
        if(edge){edge.hasRoute=true;if(actualLink?.ID)edge.routeLinks.add(actualLink.ID)}
        const path=edge?.path||{...curve(positions.get(from),positions.get(to),pair(from,to),first?'first_hop':'tunnel'),from};
        let actual=routeEdges.get(key);
        if(!actual){actual={from:edge?.from||from,to:edge?.to||to,first,path,appearance:edge?.appearance,linkIDs:new Set(),arrows:new Set(),resourceID:first?actualLink?.ResourceID||route.FirstResourceID:'',transport:first?route.FirstTransport:edge?.transport||'wireguard'};routeEdges.set(key,actual)}
        if(actualLink?.ID||linkID)actual.linkIDs.add(actualLink?.ID||linkID);
        actual.arrows.add(path.from===from?'end':'start');
      }
    }
  }
  const arrow = id + '-arrow', observationArrow=id+'-observation-arrow';
  const edgeMarkup = edges.map(edge => {
    const link=connectionLink(edge,view),ids=connectionIDs(edge),inspected=includesLink(edge,view.SelectedLink)||includesLink(edge,view.PinnedLink);
    const title=(edge.appearance?.singleDirection?'Only this relay candidate; no reverse candidate.\n':'')+edge.links.map(value=>`${value.From} → ${value.To} · ${value.Transport} · ${value.Kind==='first_hop'?'First-hop':'WG DNS'}: ${value.State||'unknown'} · ${value.Transport==='wireguard'?'shared WG peer':'resource observation'} · ${list(value.Metrics).join(' · ')||(value.Transport==='wireguard'?'WG TX rate: Unknown':'Hy2 authentication rate: Unknown')}`).join('\n');
    const stroke=edge.kind==='first_hop'?edge.transport==='hysteria2'?'hy2-first-hop':'first-hop':edge.kind;
    const state=edge.kind==='first_hop'?' '+(link.State||'unknown'):'';
    const observation=edge.appearance?` observation-${edge.appearance.pattern}${edge.appearance.singleDirection?' single-direction':''}`:'';
    const attributes=edge.appearance?`data-observation-pattern="${edge.appearance.pattern}" data-single-direction="${edge.appearance.singleDirection}"`:'';
    const measuredDirection=edge.appearance?.direction;
    const marker=measuredDirection?`marker-${edge.path.from===measuredDirection.from?'end':'start'}="url(#${observationArrow})" data-observation-from="${esc(measuredDirection.from)}" data-observation-to="${esc(measuredDirection.to)}"`:'';
    return `<g class="topology-edge ${edge.hasRoute?'has-route':''} ${inspected?'is-inspected':''}" data-key="${esc(edge.key)}" data-connection-key="${esc(edge.key)}" data-topology-links="${esc(JSON.stringify(ids))}" ${link.ID?`data-topology-link="${esc(link.ID)}" role="button" tabindex="0" aria-pressed="${inspected}" aria-label="${esc(ids.join(', '))}, inspect directional relay measurements and shared WG sent packets"`:''} data-resource="${esc(link.ResourceID||'')}" data-from-resource="${esc(edge.fromResourceID)}" data-to-resource="${esc(edge.resourceID)}" data-transport="${esc(edge.transport)}" data-from="${esc(edge.from)}" data-to="${esc(edge.to)}"><title>${esc(title)}</title><path class="edge-stroke ${esc(stroke+state+observation)}" ${attributes} ${marker} d="${edge.path.d}"/><path class="edge-hit" d="${edge.path.d}"/></g>`;
  }).join('');
  const selectedEdge = edges.find(edge=>includesLink(edge,view.SelectedLink)) || edges.find(edge=>includesLink(edge,view.PinnedLink));
  const height=diagram.height;
  const name=node=>nodes.find(value=>value.ID===node)?.Name||node;
  const measurements=selectedEdge?[...selectedEdge.links].sort((a,b)=>compare(a.From,b.From)||compare(a.To,b.To)||compare(linkKey(a),linkKey(b))).map(link=>`${name(link.From)} → ${name(link.To)} · ${link.State||'unknown'} · ${list(link.Metrics)[0]||'WG DNS RTT: Unknown'}`):[];
  const metricX=selectedEdge?n((positions.get(selectedEdge.from).x+positions.get(selectedEdge.to).x)/2):0,metricY=selectedEdge?n((positions.get(selectedEdge.from).y+positions.get(selectedEdge.to).y)/2-24):0;
  const metricMarkup=selectedEdge?`<text class="topology-metrics" x="${metricX}" y="${metricY}" text-anchor="middle"><title>${esc(connectionIDs(selectedEdge).join('\n'))}</title>${measurements.map((value,index)=>`<tspan x="${metricX}" dy="${index?14:0}">${esc(value)}</tspan>`).join('')}</text>`:'';

  const routeMarkup = [...routeEdges].sort(([a],[b])=>compare(a,b)).map(([key,{from,to,first,path,appearance,linkIDs,arrows,resourceID,transport}]) => {
    const ids=[...linkIDs].sort(),primary=ids.includes(view.SelectedLink)?view.SelectedLink:ids[0]||'';
    const markers=[...arrows].sort().map(end=>`marker-${end}="url(#${arrow})"`).join(' ');
    const observation=appearance?' observation-'+appearance.pattern:'';
    return `<path class="route topology-route ${first?'first-hop':''}${observation}" data-key="route:${esc(key)}" data-connection-key="${esc(key)}" ${appearance?`data-observation-pattern="${appearance.pattern}"`:''} data-route-links="${esc(JSON.stringify(ids))}" data-route-link="${esc(primary)}" data-route-resource="${esc(resourceID||'')}" data-transport="${esc(transport)}" data-from="${esc(from)}" data-to="${esc(to)}" ${markers} d="${path.d}"/>`;
  }).join('');
  const directMarkup = [...direct].filter(node => positions.has(node)).map(node => {
    const point = positions.get(node);
    return `<g class="route-local-exit" data-key="exit:${esc(node)}" transform="translate(${n(point.x + (point.x>480?-96:14))} ${n(point.y + 10)})"><rect width="82" height="19" rx="9.5" fill="#f5f7fc" stroke="#b9c9e9"/><circle cx="10" cy="9.5" r="3" fill="#466fc2"/><text x="18" y="13">LOCAL EXIT</text></g>`;
  }).join('');
  const nodeMarkup = nodes.filter(node => positions.has(node.ID)).map(node => {
    const point = positions.get(node.ID), location = labels.get(node.ID);
    const health = node.Runtime === 'running' ? '' : node.Runtime === 'error' ? 'problem' : 'unknown';
    const text = (lines,y,step,className)=>`<text class="${className}" text-anchor="${location.anchor}" x="${location.x}" y="${n(y)}">${lines.map((line,index)=>`<tspan x="${location.x}" dy="${index?step:0}">${esc(line)}</tspan>`).join('')}</text>`;
    return `<g class="topology-node" data-key="node:${esc(node.ID)}" data-node="${esc(node.ID)}" data-ring="${point.ring}" role="button" tabindex="0" aria-pressed="false" aria-label="${esc(node.Name || node.ID)}, focus adjacent links"><title>${esc(node.Name || node.ID)} · ${esc(node.ID)} · ${esc(subtitle(node))} · Runtime: ${esc(node.Runtime || 'unknown')}</title>${selected.has(node.ID) ? `<circle class="route-ring" cx="${n(point.x)}" cy="${n(point.y)}" r="11"/>` : ''}<circle class="node-hit" cx="${n(point.x)}" cy="${n(point.y)}" r="16"/><circle class="node-focus" cx="${n(point.x)}" cy="${n(point.y)}" r="11"/><circle class="node ${health} ${selected.has(node.ID) ? 'selected' : ''}" cx="${n(point.x)}" cy="${n(point.y)}" r="6"/><g class="topology-label">${text(location.name,location.y,15,'node-label')}${text(location.detail,location.sub,12,'sub node-label')}</g></g>`;
  }).join('');
  return `<svg class="topology" data-key="topology:${esc(id)}" data-selected-link="${esc(view.SelectedLink||'')}" data-pinned-link="${esc(view.PinnedLink||'')}" viewBox="0 0 960 ${height}" role="group" aria-label="Interactive concentric network topology"><defs><marker id="${arrow}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#466fc2"/></marker><marker id="${observationArrow}" class="observation-arrow" pointer-events="none" markerUnits="userSpaceOnUse" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#89968e"/></marker></defs><ellipse class="topology-ring outer" cx="480" cy="${diagram.cy}" rx="${diagram.outerRX}" ry="${diagram.outerRY}"/><ellipse class="topology-ring inner" cx="480" cy="${diagram.cy}" rx="${diagram.outerRX*.58}" ry="${diagram.outerRY*.59}"/><g data-key="edges">${edgeMarkup}</g><g data-key="metrics">${metricMarkup}</g><g data-key="routes">${routeMarkup}${directMarkup}</g><g data-key="nodes">${nodeMarkup}</g>${nodes.length ? '' : `<text class="sub" text-anchor="middle" x="480" y="${diagram.cy}">No certified topology</text>`}</svg>`;
}

const bindings=new WeakMap;
export function bindTopology(container) {
  const svg = container?.querySelector('svg');
  if (!svg) return;
  bindings.get(container)?.abort();
  const controller=new AbortController;bindings.set(container,controller);
  const listen=(event,handler)=>svg.addEventListener(event,handler,{signal:controller.signal});
  const nodes = [...svg.querySelectorAll('.topology-node')];
  const focused = container.contains(document.activeElement) ? document.activeElement.dataset.node : '';
  const known = new Set(nodes.map(node => node.dataset.node));
  let locked = known.has(container.dataset.locked) ? container.dataset.locked : '';
  const hasLink = (edge,id) => !!id && (edge.dataset.topologyLink===id || JSON.parse(edge.dataset.topologyLinks||'[]').includes(id));
  const selectedEdge = [...svg.querySelectorAll('[data-topology-link]')].find(edge => hasLink(edge,svg.dataset.selectedLink));
  const pinnedEdge = [...svg.querySelectorAll('[data-topology-link]')].find(edge => hasLink(edge,svg.dataset.pinnedLink));
  const apply = (nodeID, edge = null) => {
    if (!nodeID && (!edge || pinnedEdge)) edge = pinnedEdge || selectedEdge;
    const active = !!(nodeID || edge), visible = new Set(nodeID ? [nodeID] : []);
    svg.classList.toggle('has-focus', active);
    for (const item of svg.querySelectorAll('.topology-edge,.topology-route')) {
      const related = edge ? item.dataset.connectionKey===edge.dataset.connectionKey :
        !!nodeID && (item.dataset.from === nodeID || item.dataset.to === nodeID);
      item.classList.toggle('is-related', related);
      item.classList.toggle('is-inspected', !!edge && related);
      item.classList.toggle('is-muted', active && !related);
      if (related) {
        visible.add(item.dataset.from);
        visible.add(item.dataset.to);
      }
    }
    for (const item of nodes) {
      const same = item.dataset.node === nodeID;
      item.classList.toggle('is-selected', same && !!locked);
      item.classList.toggle('is-preview', same && !locked);
      item.classList.toggle('is-muted', active && !visible.has(item.dataset.node));
      item.setAttribute('aria-pressed', String(same && !!locked));
    }
    container.dataset.locked = locked;
  };
  const preview = event => {
    if (locked) return;
    const node = event.target.closest('.topology-node'), edge = event.target.closest('.topology-edge');
    apply(node?.dataset.node || '', edge);
  };
  listen('pointerover', preview);
  listen('focusin', preview);
  listen('pointerleave', () => apply(locked));
  listen('focusout', () => apply(locked));
  listen('click', event => {
    const node = event.target.closest('.topology-node');
    locked = node ? locked === node.dataset.node ? '' : node.dataset.node : '';
    apply(locked);
  });
  listen('keydown', event => {
    const node = event.target.closest('.topology-node'), edge = event.target.closest('[data-topology-link]');
    if (edge && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault();
      edge.dispatchEvent(new MouseEvent('click', {bubbles:true}));
    } else if (event.key === 'Escape') {
      locked = '';
      apply('');
    } else if (node && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault();
      locked = locked === node.dataset.node ? '' : node.dataset.node;
      apply(locked);
    }
  });
  if (focused) svg.querySelector(`[data-node="${CSS.escape(focused)}"]`)?.focus();
  const hovered=svg.querySelector('.topology-node:hover,.topology-edge:hover'),active=document.activeElement?.closest('.topology-node,.topology-edge');
  const previewed=hovered||(svg.contains(active)?active:null);
  let previewEdge=previewed?.matches('.topology-edge')?previewed:null;
  if(previewEdge?.dataset.topologyLink)previewEdge=selectedEdge||previewEdge;
  apply(locked||previewed?.dataset.node||'',locked?null:previewEdge);
}
