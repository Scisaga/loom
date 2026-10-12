import {esc, list, topologyPositions} from './model.js';

const pair = (a, b) => [a, b].sort().join('\0');
const n = value => Number(value.toFixed(1));
const hash = value => {
  let result = 2166136261;
  for (const character of value) result = Math.imul(result ^ character.codePointAt(0), 16777619) >>> 0;
  return result;
};

function curve(a, b, key, kind) {
  if (kind === 'candidate' && a.ring === b.ring) {
    const delta = (b.angle - a.angle + 360) % 360;
    return {d: `M ${n(a.x)} ${n(a.y)} A ${n(a.rx)} ${n(a.ry)} 0 0 ${delta > 180 ? 0 : 1} ${n(b.x)} ${n(b.y)}`};
  }
  const dx = b.x - a.x, dy = b.y - a.y, distance = Math.hypot(dx, dy) || 1;
  const bend = (hash(key) % 7 - 3) * 7 || 4;
  const cx = (a.x + b.x) / 2 - dy / distance * bend, cy = (a.y + b.y) / 2 + dx / distance * bend;
  return {d: `M ${n(a.x)} ${n(a.y)} Q ${n(cx)} ${n(cy)} ${n(b.x)} ${n(b.y)}`};
}

function subtitle(node) {
  return [node.Location, list(node.Roles).join(' + ')].filter(Boolean).join(' · ');
}

function labelLines(value, limit) {
  const lines = [];let line = '', used = 0;
  for (const character of String(value).replace(/\s+/g, ' ')) {
    const units = character.codePointAt(0) < 128 ? 1 : 2;
    if (used + units > limit) {lines.push(line);line = '';used = 0}
    line += character;used += units;
  }
  if (line) lines.push(line);
  return lines;
}

function layout(nodes, compact) {
  const positions = topologyPositions(nodes), groups = [[], []], labels = new Map();
  for (const node of [...nodes].sort((a,b)=>a.ID<b.ID?-1:a.ID>b.ID?1:0)) {
    const point = positions.get(node.ID), left = point.x < 480 - .1, right = point.x > 480 + .1;
    const side = left ? 0 : right ? 1 : Number(groups[1].length < groups[0].length);
    const name = labelLines(node.Name || node.ID, 30), detail = labelLines(subtitle(node), 38);
    groups[side].push({id:node.ID,point,name,detail,height:name.length*15+detail.length*12});
  }
  const used = groups.map(group=>group.reduce((sum,value)=>sum+value.height,0)+Math.max(0,group.length-1)*14);
  const height = Math.max(compact ? 280 : 360, ...used.map(value=>value+84)), cy = height/2, outerRY = cy-58;
  for (const point of positions.values()) {
    const ratio = point.ring==='outer'?1:75/130;
    point.x = 480 + (point.x-480)*205/310;
    point.y = cy + (point.y-180)*outerRY/130;
    point.rx = point.ring==='outer'?205:205*170/310;
    point.ry = outerRY*ratio;
  }
  groups.forEach((group,side)=>{
    group.sort((a,b)=>a.point.y-b.point.y||(a.id<b.id?-1:a.id>b.id?1:0));
    let y = (height-used[side])/2;
    for (const value of group) {
      labels.set(value.id,{...value,x:side?715:245,y:y+12,sub:y+value.name.length*15+10,anchor:side?'start':'end',lineX:side?702:258,lineY:y+value.height/2});
      y += value.height+14;
    }
  });
  return {positions,labels,height,cy,outerRY};
}

export function topologyHTML(view, routes = [], id = 'network') {
  const nodes = list(view.Nodes).filter(node => node.ID);
  const compact = id === 'overview-topology', diagram = layout(nodes, compact), {positions,labels} = diagram;
  const selected = new Set(), direct = new Set(), routeEdges = new Map(), curves = new Map();
  const edges = list(view.Links)
    .filter(link => positions.has(link.From) && positions.has(link.To))
    .map(link => {
      const key = pair(link.From, link.To), path = curve(positions.get(link.From), positions.get(link.To), key, link.Kind);
      if (!curves.has(key) || link.Kind !== 'candidate') curves.set(key, {...path, from: link.From});
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
        routeEdges.set(`${chain[index]}\0${chain[index + 1]}`, [chain[index], chain[index + 1]]);
      }
    }
  }
  const arrow = id + '-arrow';
  const edgeMarkup = edges.map(edge => `<g class="topology-edge" ${edge.link.ID?`data-topology-link="${esc(edge.link.ID)}" role="button" tabindex="0" aria-pressed="${edge.link.ID===view.SelectedLink}" aria-label="${esc(edge.link.ID)}, inspect shared link traffic"`:''} data-from="${esc(edge.link.From)}" data-to="${esc(edge.link.To)}"><title>${esc(edge.link.From)} → ${esc(edge.link.To)} · ${esc(edge.link.Transport)} · ${esc(edge.link.State || 'unknown')} · shared peer · ${esc(list(edge.link.Metrics).join(' · ') || 'WG rate: Unknown')}</title><path class="${esc(edge.link.Kind || 'tunnel')} ${esc(edge.link.State || 'unknown')}" d="${edge.path.d}"/><path class="edge-hit" d="${edge.path.d}"/></g>`).join('');
  const selectedEdge = edges.find(edge => edge.link.ID === view.SelectedLink);
  const metricY = diagram.height + 12;
  const metricRows = selectedEdge ? Math.ceil(Math.max(1,list(selectedEdge.link.Metrics).length)/2) : 0;
  const height = selectedEdge ? metricY + metricRows * 16 + 16 : diagram.height;
  const metricMarkup = selectedEdge ? `<text class="topology-metrics" x="480" y="${metricY}" text-anchor="middle"><tspan x="480">${esc(selectedEdge.link.ID)} · shared WG peer</tspan>${(list(selectedEdge.link.Metrics).length?list(selectedEdge.link.Metrics):['WG rate: Unknown']).reduce((rows,value,index)=>{if(index%2===0)rows.push([]);rows[rows.length-1].push(value);return rows},[]).map(row=>`<tspan x="480" dy="16">${esc(row.join(' · '))}</tspan>`).join('')}</text>` : '';
  const routeMarkup = [...routeEdges.values()].map(([from, to]) => {
    const path = curves.get(pair(from, to)) || {...curve(positions.get(from), positions.get(to), pair(from, to), 'tunnel'), from};
    return `<path class="route topology-route" data-from="${esc(from)}" data-to="${esc(to)}" marker-${path.from === from ? 'end' : 'start'}="url(#${arrow})" d="${path.d}"/>`;
  }).join('');
  const directMarkup = [...direct].filter(node => positions.has(node)).map(node => {
    const point = positions.get(node);
    return `<g class="route-local-exit" transform="translate(${n(point.x + (point.x>480?-96:14))} ${n(point.y + 10)})"><rect width="82" height="19" rx="9.5" fill="#f5f7fc" stroke="#b9c9e9"/><circle cx="10" cy="9.5" r="3" fill="#466fc2"/><text x="18" y="13">LOCAL EXIT</text></g>`;
  }).join('');
  const nodeMarkup = nodes.filter(node => positions.has(node.ID)).map(node => {
    const point = positions.get(node.ID), location = labels.get(node.ID);
    const health = node.Health === 'available' ? '' : node.Health === 'unavailable' ? 'problem' : 'unknown';
    const text = (lines,y,step,className)=>`<text class="${className}" text-anchor="${location.anchor}" x="${location.x}" y="${n(y)}">${lines.map((line,index)=>`<tspan x="${location.x}" dy="${index?step:0}">${esc(line)}</tspan>`).join('')}</text>`;
    return `<g class="topology-node" data-node="${esc(node.ID)}" data-ring="${point.ring}" role="button" tabindex="0" aria-pressed="false" aria-label="${esc(node.Name || node.ID)}, focus adjacent links"><title>${esc(node.Name || node.ID)} · ${esc(node.ID)} · ${esc(subtitle(node))} · ${esc(node.Health || 'unknown')}</title><path class="node-label-leader" d="M ${n(point.x)} ${n(point.y)} L ${location.lineX} ${n(location.lineY)}"/>${selected.has(node.ID) ? `<circle class="route-ring" cx="${n(point.x)}" cy="${n(point.y)}" r="11"/>` : ''}<circle class="node-hit" cx="${n(point.x)}" cy="${n(point.y)}" r="16"/><circle class="node-focus" cx="${n(point.x)}" cy="${n(point.y)}" r="11"/><circle class="node ${health} ${selected.has(node.ID) ? 'selected' : ''}" cx="${n(point.x)}" cy="${n(point.y)}" r="6"/><g class="topology-label">${text(location.name,location.y,15,'node-label')}${text(location.detail,location.sub,12,'sub node-label')}</g></g>`;
  }).join('');
  return `<svg class="topology" data-selected-link="${esc(view.SelectedLink||'')}" viewBox="0 0 960 ${height}" role="group" aria-label="Interactive concentric network topology"><defs><marker id="${arrow}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#466fc2"/></marker></defs><ellipse class="topology-ring outer" cx="480" cy="${diagram.cy}" rx="205" ry="${diagram.outerRY}"/><ellipse class="topology-ring inner" cx="480" cy="${diagram.cy}" rx="${205*170/310}" ry="${diagram.outerRY*75/130}"/><text class="ring-key" text-anchor="end" x="942" y="21">hover preview · click lock · Esc clear</text>${edgeMarkup}${metricMarkup}${routeMarkup}${directMarkup}${nodeMarkup}${nodes.length ? '' : `<text class="sub" text-anchor="middle" x="480" y="${diagram.cy}">No certified topology</text>`}</svg>`;
}

export function bindTopology(container) {
  const svg = container?.querySelector('svg');
  if (!svg) return;
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
  svg.addEventListener('pointerover', preview);
  svg.addEventListener('focusin', preview);
  svg.addEventListener('pointerleave', () => apply(locked));
  svg.addEventListener('focusout', () => apply(locked));
  svg.addEventListener('click', event => {
    const node = event.target.closest('.topology-node');
    locked = node ? locked === node.dataset.node ? '' : node.dataset.node : '';
    apply(locked);
  });
  svg.addEventListener('keydown', event => {
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
