import {
  esc,
  list,
  topologyPositions
} from './model.js';
const key = (a, b) => [a, b].sort().join('\u0000');
const hash = value => {
  let h = 2166136261;
  for (const c of value) h = Math.imul(h ^ c.codePointAt(0), 16777619) >>> 0;
  return h;
};
const number = v => Number(v.toFixed(1));
export const age = value => {
  if (!value || !Number.isFinite(Date.parse(value))) return 'Not reported';
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(value)) / 1000));
  return seconds < 60 ? `${seconds}s ago` : seconds < 3600 ? `${Math.floor(seconds/60)}m ago` : `${Math.floor(seconds/3600)}h ago`;
};
export function bitRate(value) {
  if (!Number.isFinite(value)) return '—';
  for (const [unit, scale] of [
      ['Gb/s', 1e9],
      ['Mb/s', 1e6],
      ['kb/s', 1e3]
    ])
    if (value >= scale) return `${(value/scale).toFixed(1)}${unit}`;
  return `${Math.round(value)}bit/s`;
}
export function linkMetric(l) {
  const latency = l.Samples > l.Failures && l.ObservedAt ? `${l.MS}ms` : '—',
    variation = l.QualityObservations - l.QualityFailed >= 2 && l.QualityP95MS >= l.QualityP50MS ? `Δ${l.QualityP95MS-l.QualityP50MS}ms` : 'Δ—',
    probe = l.Kind === 'direct-hy2',
    rate = probe ? (l.ProbeSamples > 0 && l.ProbeBytes > 0 && l.ProbeDurationMS > 0 ? bitRate(l.ProbeBytes * 8000 / l.ProbeDurationMS) : '—') : (l.RateSamples > 0 && l.RateWindowSeconds > 0 ? bitRate(l.RecentTXBytes * 8 / l.RateWindowSeconds) : '—');
  const detail = `${l.ObservedFrom||l.From} → ${l.ObservedTo||l.To} · ${probe?'Hy2 single-hop response; fixed-response probe rate, not business traffic or capacity':'WireGuard RTT; 5m sender TX rate'} · ${latency} · 15m P95−P50 ${variation} · ${rate} · ${l.Source||''} · ${l.MetricsSource||''}`;
  return {
    latency,
    variation,
    rate,
    text: `${latency} · ${variation} · ${rate}`,
    detail
  };
}

function curve(a, b, k, kind) {
  if (kind === 'candidate' && a.ring === b.ring) {
    const outer = a.ring === 'outer',
      delta = (b.angle - a.angle + 360) % 360;
    return {
      d: `M ${number(a.x)} ${number(a.y)} A ${outer?310:170} ${(outer?130:75)*(a.scaleY||1)} 0 0 ${delta>180?0:1} ${number(b.x)} ${number(b.y)}`
    };
  }
  const dx = b.x - a.x,
    dy = b.y - a.y,
    d = Math.hypot(dx, dy) || 1,
    bend = (hash(k) % 7 - 3) * 7 || 4,
    cx = (a.x + b.x) / 2 - dy / d * bend,
    cy = (a.y + b.y) / 2 + dx / d * bend;
  return {
    d: `M ${number(a.x)} ${number(a.y)} Q ${number(cx)} ${number(cy)} ${number(b.x)} ${number(b.y)}`,
    point(t, offset) {
      const tx = 2 * (1 - t) * (cx - a.x) + 2 * t * (b.x - cx),
        ty = 2 * (1 - t) * (cy - a.y) + 2 * t * (b.y - cy),
        distance = Math.hypot(tx, ty) || 1;
      return {
        x: (1 - t) ** 2 * a.x + 2 * (1 - t) * t * cx + t * t * b.x - ty / distance * offset,
        y: (1 - t) ** 2 * a.y + 2 * (1 - t) * t * cy + t * t * b.y + tx / distance * offset
      };
    }
  };
}

function label(p) {
  const radians = p.angle * Math.PI / 180,
    c = Math.cos(radians);
  if (Math.abs(c) < .35) return {
    x: p.x,
    y: p.y + (Math.sin(radians) < 0 ? -20 : 25),
    sub: p.y + (Math.sin(radians) < 0 ? -7 : 40),
    anchor: 'middle'
  };
  return {
    x: p.x + (c < 0 ? -17 : 17),
    y: p.y - 2,
    sub: p.y + 15,
    anchor: c < 0 ? 'end' : 'start'
  };
}

function subtitle(n) {
  const location = [n.Country, n.City].filter(Boolean).join(' ') || n.Name || '',
    traits = [...(n.Self ? ['control'] : []), ...list(n.Roles).filter(r => r !== 'control')];
  if (n.EgressCapable && !traits.includes('egress')) traits.push('egress');
  return [location, traits.join(' + ')].filter(Boolean).join(' · ');
}
const bounds = (x, y, width, height = 19, anchor = 'middle') => ({
  x: x - (anchor === 'middle' ? width / 2 : anchor === 'end' ? width : 0) - 3,
  y: y - height + 4,
  w: width + 6,
  h: height
});
const overlap = (a, b) => a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;

function textWidth(s, size) {
  return [...s].reduce((sum, c) => sum + (c.codePointAt(0) > 127 ? size : size * .61), 0);
}

function metricPositions(edges, positions, nodes) {
  const occupied = [];
  for (const n of nodes) {
    const p = positions.get(n.ID),
      l = label(p);
    occupied.push(bounds(p.x, p.y + 17, 34, 34), bounds(l.x, l.y, textWidth(n.ID, 12), 20, l.anchor), bounds(l.x, l.sub, textWidth(subtitle(n), 10), 17, l.anchor));
  }
  const result = new Map();
  // 标签位置仅沿原边找空隙，不移动节点，也不把标签当作路由顶点。
  for (const edge of edges.filter(e => e.link.Kind !== 'candidate').sort((a, b) => a.key.localeCompare(b.key))) {
    const width = textWidth(edge.metric.text, 8.8) + 8;
    let best, score = Infinity;
    for (const t of [.5, .32, .68, .23, .77])
      for (const offset of [14, -14, 26, -26, 38, -38]) {
        const p = edge.curve.point(t, offset),
          b = bounds(p.x, p.y + 3, width),
          penalty = occupied.reduce((sum, o) => sum + (overlap(b, o) ? 1000 : 0), 0) + Math.abs(t - .5) * 10 + Math.abs(offset);
        if (penalty < score) {
          score = penalty;
          best = {
            p,
            b
          };
        }
      }
    result.set(edge.key, best.p);
    occupied.push(best.b);
  }
  return result;
}
export function topologySVG(view, routes = list(view.Routes), id = 'network') {
  const nodes = list(view.Nodes).filter(n => n.ID),
    positions = topologyPositions(nodes),
    selected = new Set(),
    direct = new Set(),
    routeEdges = new Map(),
    curves = new Map();
  const compact = id === 'overview-topology';
  if (compact)
    for (const p of positions.values()) {
      p.y = 140 + (p.y - 180) * .8;
      p.scaleY = .8;
    }
  const edges = list(view.Links).filter(l => positions.has(l.From) && positions.has(l.To)).map(link => {
    const k = key(link.From, link.To),
      c = curve(positions.get(link.From), positions.get(link.To), k, link.Kind);
    if (!curves.has(k) || link.Kind !== 'candidate') curves.set(k, {
      ...c,
      from: link.From
    });
    return {
      link,
      key: k,
      curve: c,
      metric: linkMetric(link)
    };
  });
  for (const r of routes.filter(r => !r.Stale)) {
    const chain = list(r.Chain);
    for (const n of chain) selected.add(n);
    if (chain.length <= 1) {
      selected.add(r.Node);
      direct.add(r.Node);
      continue;
    }
    for (let i = 0; i + 1 < chain.length; i++)
      if (positions.has(chain[i]) && positions.has(chain[i + 1])) routeEdges.set(chain[i] + '|' + chain[i + 1], [chain[i], chain[i + 1]]);
  }
  const metrics = metricPositions(edges, positions, nodes),
    attr = l => `data-from="${esc(l.From)}" data-to="${esc(l.To)}"`,
    arrow = id + '-arrow';
  return `<svg class="topology" viewBox="0 0 960 ${compact?280:360}" role="group" aria-label="Interactive concentric network topology"><defs><marker id="${arrow}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#466fc2"/></marker></defs><ellipse class="topology-ring outer" cx="480" cy="${compact?140:180}" rx="310" ry="${compact?104:130}"/><ellipse class="topology-ring inner" cx="480" cy="${compact?140:180}" rx="170" ry="${compact?60:75}"/><text class="ring-key" x="18" y="21">内圈：接受建连 · 外圈：reverse_only</text><text class="ring-key" text-anchor="end" x="942" y="21">悬停预览 · 点击锁定 · Esc 取消</text>${edges.map(e=>`<g class="topology-edge" ${attr(e.link)}><title>${esc(e.link.Kind==='candidate'?'On-demand candidate; no continuous observation':e.metric.detail)}</title><path class="${esc(e.link.Kind||'tunnel')} ${esc(e.link.State||'unknown')}" d="${e.curve.d}"/><path class="edge-hit" d="${e.curve.d}"/></g>`).join('')}${[...routeEdges.values()].map(([from,to])=>{
    const c=curves.get(key(from,to))||{...curve(positions.get(from),positions.get(to),key(from,to),'tunnel'),from};
    return '<path class="route topology-route" data-from="'+esc(from)+'" data-to="'+esc(to)+'" marker-'+(c.from===from?'end':'start')+'="url(#'+arrow+')" d="'+c.d+'"/>';
  }).join('')}${[...direct].filter(n=>positions.has(n)).map(n=>{const p=positions.get(n);return `<g class="route-local-exit" transform="translate(${number(p.x+14)} ${number(p.y+10)})"><rect width="82" height="19" rx="9.5" fill="#f5f7fc" stroke="#b9c9e9"/><circle cx="10" cy="9.5" r="3" fill="#466fc2"/><text x="18" y="13">LOCAL EXIT</text></g>`;}).join('')}${edges.filter(e=>e.link.Kind!=='candidate').map(e=>{const p=metrics.get(e.key);return `<g class="edge-metric" ${attr(e.link)} transform="translate(${number(p.x)} ${number(p.y)})"><title>${esc(e.metric.detail)}</title><text text-anchor="middle" y="3">${esc(e.metric.text)}</text></g>`;}).join('')}${nodes.map(n=>{
    const p=positions.get(n.ID),l=label(p),health=n.Health==='problem'?'problem':n.Health==='healthy'?'':'unknown';
    return `<g class="topology-node" data-node="${esc(n.ID)}" data-ring="${p.ring}" role="button" tabindex="0" aria-pressed="false" aria-label="${esc(n.ID)}，聚焦相邻链路"><title>${esc(n.ID+' · '+subtitle(n)+' · '+(n.Health||'unknown'))}</title>${selected.has(n.ID)?`<circle class="route-ring" cx="${number(p.x)}" cy="${number(p.y)}" r="11"/>`:''}<circle class="node-hit" cx="${number(p.x)}" cy="${number(p.y)}" r="16"/><circle class="node-focus" cx="${number(p.x)}" cy="${number(p.y)}" r="11"/><circle class="node ${health} ${selected.has(n.ID)?'selected':''}" cx="${number(p.x)}" cy="${number(p.y)}" r="6"/><text class="node-label" text-anchor="${l.anchor}" x="${number(l.x)}" y="${number(l.y)}">${esc(n.ID)}</text><text class="sub node-label" text-anchor="${l.anchor}" x="${number(l.x)}" y="${number(l.sub)}">${esc(subtitle(n))}</text></g>`;
  }).join('')}${nodes.length?'':'<text class="sub" text-anchor="middle" x="480" y="180">No topology observations</text>'}</svg>`;
}
export function renderTopology(container, view, routes) {
  if (!container) return;
  const html = topologySVG(view, routes, container.id),
    focused = container.contains(document.activeElement) ? document.activeElement.dataset.node : '';
  if (container.dataset.svg === html) return;
  container.innerHTML = html;
  container.dataset.svg = html;
  const svg = container.querySelector('svg');
  let locked = container.dataset.locked || '';
  if (!list(view.Nodes).some(n => n.ID === locked)) locked = '';
  const apply = (nodeID, edge = null) => {
    const active = !!(nodeID || edge),
      visible = new Set(nodeID ? [nodeID] : []);
    svg.classList.toggle('has-focus', active);
    for (const e of svg.querySelectorAll('.topology-edge,.topology-route')) {
      const related = edge ? e.dataset.from === edge.dataset.from && e.dataset.to === edge.dataset.to : !!nodeID && (e.dataset.from === nodeID || e.dataset.to === nodeID);
      e.classList.toggle('is-related', related);
      e.classList.toggle('is-muted', active && !related);
      if (related) {
        visible.add(e.dataset.from);
        visible.add(e.dataset.to);
      }
    }
    for (const e of svg.querySelectorAll('.edge-metric')) e.classList.toggle('is-related', edge ? e.dataset.from === edge.dataset.from && e.dataset.to === edge.dataset.to : !!nodeID && (e.dataset.from === nodeID || e.dataset.to === nodeID));
    for (const n of svg.querySelectorAll('.topology-node')) {
      const same = n.dataset.node === nodeID;
      n.classList.toggle('is-selected', same && !!locked);
      n.classList.toggle('is-preview', same && !locked);
      n.classList.toggle('is-muted', active && !visible.has(n.dataset.node));
      n.setAttribute('aria-pressed', String(same && !!locked));
    }
    container.dataset.locked = locked;
  };
  const preview = e => {
    if (locked) return;
    const n = e.target.closest('.topology-node'),
      edge = e.target.closest('.topology-edge');
    apply(n?.dataset.node || '', edge);
  };
  svg.addEventListener('pointerover', preview);
  svg.addEventListener('focusin', preview);
  svg.addEventListener('pointerleave', () => apply(locked));
  svg.addEventListener('focusout', () => apply(locked));
  svg.addEventListener('click', e => {
    const n = e.target.closest('.topology-node');
    locked = n ? (locked === n.dataset.node ? '' : n.dataset.node) : '';
    apply(locked);
  });
  svg.addEventListener('keydown', e => {
    const n = e.target.closest('.topology-node');
    if (e.key === 'Escape') {
      locked = '';
      apply('');
    } else if (n && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      locked = locked === n.dataset.node ? '' : n.dataset.node;
      apply(locked);
    }
  });
  if (focused) svg.querySelector(`[data-node="${CSS.escape(focused)}"]`)?.focus();
  apply(locked);
}
export const legend = `<div class="legend"><span><i class="key"></i>WireGuard</span><span><i class="key direct-hy2"></i>Hy2 direct</span><span><i class="key candidate"></i>Candidate</span><span><i class="key route"></i>Agent route</span></div>`;
