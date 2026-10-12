import {esc, list, topologyPositions} from './model.js';

const pair = (a, b) => [a, b].sort().join('\0');
const n = value => Number(value.toFixed(1));
const hash = value => {
  let result = 2166136261;
  for (const character of value) result = Math.imul(result ^ character.codePointAt(0), 16777619) >>> 0;
  return result;
};

function curve(a, b, key, kind) {
  if (kind === 'first_hop' && a.ring === b.ring) {
    const delta = (b.angle - a.angle + 360) % 360;
    return {d: `M ${n(a.x)} ${n(a.y)} A ${n(a.rx)} ${n(a.ry)} 0 0 ${delta > 180 ? 0 : 1} ${n(b.x)} ${n(b.y)}`};
  }
  const dx = b.x - a.x, dy = b.y - a.y, distance = Math.hypot(dx, dy) || 1;
  const bend = kind==='first_hop' ? (hash(key)%2?24:-24) : 0;
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
  const selected = new Set(), direct = new Set(), routeEdges = new Map(), firstEdges=new Set(), curves = new Map();
  const edges = list(view.Links)
    .filter(link => positions.has(link.From) && positions.has(link.To))
    .map(link => {
      const key = pair(link.From, link.To), path = curve(positions.get(link.From), positions.get(link.To), key, link.Kind);
      if (!curves.has(key) || link.Kind !== 'first_hop') curves.set(key, {...path, from: link.From});
      return {link, key, path};
    });
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
        const id=`${chain[index]}\0${chain[index + 1]}`;
        routeEdges.set(id, [chain[index], chain[index + 1]]);
        if(index===0&&route.FirstTransport)firstEdges.add(id);
      }
    }
  }
  const arrow = id + '-arrow';
  const edgeMarkup = edges.map(edge => `<g class="topology-edge" ${edge.link.ID?`data-topology-link="${esc(edge.link.ID)}" role="button" tabindex="0" aria-pressed="${edge.link.ID===view.SelectedLink}" aria-label="${esc(edge.link.ID)}, inspect shared link traffic"`:''} data-from="${esc(edge.link.From)}" data-to="${esc(edge.link.To)}"><title>${esc(edge.link.From)} → ${esc(edge.link.To)} · ${esc(edge.link.Transport)} · ${esc(edge.link.State || 'unknown')} · shared peer · ${esc(list(edge.link.Metrics).join(' · ') || 'WG rate: Unknown')}</title><path class="${edge.link.Kind==='first_hop'?edge.link.Transport==='hysteria2'?'hy2-first-hop':'first-hop':esc(edge.link.Kind || 'tunnel')} ${esc(edge.link.State || 'unknown')}" d="${edge.path.d}"/><path class="edge-hit" d="${edge.path.d}"/></g>`).join('');
  const selectedEdge = edges.find(edge => edge.link.ID === view.SelectedLink);
  const height=diagram.height;
  const measurements=list(selectedEdge?.link.Metrics),rates=measurements.find(value=>value.startsWith(selectedEdge?.link.From+' TX: ')),plain=[measurements[0]?.split(': ').slice(1).join(': '),rates?.split(' TX: ')[1],measurements[1]?.split(': ').slice(1).join(': ')].filter(Boolean).join(' · ');
  const metricX=selectedEdge?n((positions.get(selectedEdge.link.From).x+positions.get(selectedEdge.link.To).x)/2):0,metricY=selectedEdge?n((positions.get(selectedEdge.link.From).y+positions.get(selectedEdge.link.To).y)/2-24):0;
  const metricMarkup=selectedEdge?`<text class="topology-metrics" x="${metricX}" y="${metricY}" text-anchor="middle"><title>${esc(selectedEdge.link.ID)} · ${esc(measurements.join(' · '))}</title><tspan x="${metricX}">${esc(view.SelectedServiceName?view.SelectedServiceName+' · selected':selectedEdge.link.ID+' · inspected')}</tspan><tspan x="${metricX}" dy="14">${esc(plain)}</tspan></text>`:'';

  const routeMarkup = [...routeEdges.values()].map(([from, to]) => {
    const path=firstEdges.has(`${from}\0${to}`)?{...curve(positions.get(from),positions.get(to),pair(from,to),'first_hop'),from}:curves.get(pair(from,to))||{...curve(positions.get(from),positions.get(to),pair(from,to),'tunnel'),from};
    return `<path class="route topology-route ${firstEdges.has(`${from}\0${to}`)?'first-hop':''}" data-from="${esc(from)}" data-to="${esc(to)}" marker-${path.from === from ? 'end' : 'start'}="url(#${arrow})" d="${path.d}"/>`;
  }).join('');
  const directMarkup = [...direct].filter(node => positions.has(node)).map(node => {
    const point = positions.get(node);
    return `<g class="route-local-exit" transform="translate(${n(point.x + (point.x>480?-96:14))} ${n(point.y + 10)})"><rect width="82" height="19" rx="9.5" fill="#f5f7fc" stroke="#b9c9e9"/><circle cx="10" cy="9.5" r="3" fill="#466fc2"/><text x="18" y="13">LOCAL EXIT</text></g>`;
  }).join('');
  const nodeMarkup = nodes.filter(node => positions.has(node.ID)).map(node => {
    const point = positions.get(node.ID), location = labels.get(node.ID);
    const health = node.Runtime === 'running' ? '' : node.Runtime === 'error' ? 'problem' : 'unknown';
    const text = (lines,y,step,className)=>`<text class="${className}" text-anchor="${location.anchor}" x="${location.x}" y="${n(y)}">${lines.map((line,index)=>`<tspan x="${location.x}" dy="${index?step:0}">${esc(line)}</tspan>`).join('')}</text>`;
    return `<g class="topology-node" data-node="${esc(node.ID)}" data-ring="${point.ring}" role="button" tabindex="0" aria-pressed="false" aria-label="${esc(node.Name || node.ID)}, focus adjacent links"><title>${esc(node.Name || node.ID)} · ${esc(node.ID)} · ${esc(subtitle(node))} · Runtime: ${esc(node.Runtime || 'unknown')}</title>${selected.has(node.ID) ? `<circle class="route-ring" cx="${n(point.x)}" cy="${n(point.y)}" r="11"/>` : ''}<circle class="node-hit" cx="${n(point.x)}" cy="${n(point.y)}" r="16"/><circle class="node-focus" cx="${n(point.x)}" cy="${n(point.y)}" r="11"/><circle class="node ${health} ${selected.has(node.ID) ? 'selected' : ''}" cx="${n(point.x)}" cy="${n(point.y)}" r="6"/><g class="topology-label">${text(location.name,location.y,15,'node-label')}${text(location.detail,location.sub,12,'sub node-label')}</g></g>`;
  }).join('');
  return `<svg class="topology" data-selected-link="${esc(view.SelectedLink||'')}" viewBox="0 0 960 ${height}" role="group" aria-label="Interactive concentric network topology"><defs><marker id="${arrow}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#466fc2"/></marker></defs><ellipse class="topology-ring outer" cx="480" cy="${diagram.cy}" rx="${diagram.outerRX}" ry="${diagram.outerRY}"/><ellipse class="topology-ring inner" cx="480" cy="${diagram.cy}" rx="${diagram.outerRX*.58}" ry="${diagram.outerRY*.59}"/>${edgeMarkup}${metricMarkup}${routeMarkup}${directMarkup}${nodeMarkup}${nodes.length ? '' : `<text class="sub" text-anchor="middle" x="480" y="${diagram.cy}">No certified topology</text>`}</svg>`;
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
  const selectedEdge = [...svg.querySelectorAll('[data-topology-link]')].find(edge => edge.dataset.topologyLink === svg.dataset.selectedLink);
  const apply = (nodeID, edge = null) => {
    if (!nodeID && !edge) edge = selectedEdge;
    const active = !!(nodeID || edge), visible = new Set(nodeID ? [nodeID] : []);
    svg.classList.toggle('has-focus', active);
    for (const item of svg.querySelectorAll('.topology-edge,.topology-route')) {
      const related = edge ? item.dataset.topologyLink && edge.dataset.topologyLink ? item.dataset.topologyLink === edge.dataset.topologyLink : item.dataset.from === edge.dataset.from && item.dataset.to === edge.dataset.to :
        !!nodeID && (item.dataset.from === nodeID || item.dataset.to === nodeID);
      item.classList.toggle('is-related', related);
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
  apply(locked);
}
