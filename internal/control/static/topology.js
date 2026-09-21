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
    const outer = a.ring === 'outer', delta = (b.angle - a.angle + 360) % 360;
    return {d: `M ${n(a.x)} ${n(a.y)} A ${outer ? 310 : 170} ${(outer ? 130 : 75) * (a.scaleY || 1)} 0 0 ${delta > 180 ? 0 : 1} ${n(b.x)} ${n(b.y)}`};
  }
  const dx = b.x - a.x, dy = b.y - a.y, distance = Math.hypot(dx, dy) || 1;
  const bend = (hash(key) % 7 - 3) * 7 || 4;
  const cx = (a.x + b.x) / 2 - dy / distance * bend, cy = (a.y + b.y) / 2 + dx / distance * bend;
  return {d: `M ${n(a.x)} ${n(a.y)} Q ${n(cx)} ${n(cy)} ${n(b.x)} ${n(b.y)}`};
}

function label(point) {
  const radians = point.angle * Math.PI / 180, c = Math.cos(radians), s = Math.sin(radians);
  if (Math.abs(c) < .35) return {x: point.x, y: point.y + (s < 0 ? -20 : 25), sub: point.y + (s < 0 ? -7 : 40), anchor: 'middle'};
  return {x: point.x + (c < 0 ? -17 : 17), y: point.y - 2, sub: point.y + 15, anchor: c < 0 ? 'end' : 'start'};
}

function subtitle(node) {
  return [node.Location, list(node.Roles).join(' + ')].filter(Boolean).join(' · ');
}

export function topologyHTML(view, routes = [], id = 'network') {
  const nodes = list(view.Nodes).filter(node => node.ID);
  const positions = topologyPositions(nodes), compact = id === 'overview-topology';
  const selected = new Set(), direct = new Set(), routeEdges = new Map(), curves = new Map();
  if (compact) for (const point of positions.values()) {
    point.y = 140 + (point.y - 180) * .8;
    point.scaleY = .8;
  }
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
  const edgeMarkup = edges.map(edge => `<g class="topology-edge" data-from="${esc(edge.link.From)}" data-to="${esc(edge.link.To)}"><title>${esc(edge.link.From)} → ${esc(edge.link.To)} · ${esc(edge.link.Transport)} · ${esc(edge.link.State || 'unknown')}</title><path class="${esc(edge.link.Kind || 'tunnel')} ${esc(edge.link.State || 'unknown')}" d="${edge.path.d}"/><path class="edge-hit" d="${edge.path.d}"/></g>`).join('');
  const routeMarkup = [...routeEdges.values()].map(([from, to]) => {
    const path = curves.get(pair(from, to)) || {...curve(positions.get(from), positions.get(to), pair(from, to), 'tunnel'), from};
    return `<path class="route topology-route" data-from="${esc(from)}" data-to="${esc(to)}" marker-${path.from === from ? 'end' : 'start'}="url(#${arrow})" d="${path.d}"/>`;
  }).join('');
  const directMarkup = [...direct].filter(node => positions.has(node)).map(node => {
    const point = positions.get(node);
    return `<g class="route-local-exit" transform="translate(${n(point.x + 14)} ${n(point.y + 10)})"><rect width="82" height="19" rx="9.5" fill="#f5f7fc" stroke="#b9c9e9"/><circle cx="10" cy="9.5" r="3" fill="#466fc2"/><text x="18" y="13">LOCAL EXIT</text></g>`;
  }).join('');
  const nodeMarkup = nodes.filter(node => positions.has(node.ID)).map(node => {
    const point = positions.get(node.ID), location = label(point);
    const health = node.Health === 'available' ? '' : node.Health === 'unavailable' ? 'problem' : 'unknown';
    return `<g class="topology-node" data-node="${esc(node.ID)}" data-ring="${point.ring}" role="button" tabindex="0" aria-pressed="false" aria-label="${esc(node.Name || node.ID)}, focus adjacent links"><title>${esc(node.ID)} · ${esc(subtitle(node))} · ${esc(node.Health || 'unknown')}</title>${selected.has(node.ID) ? `<circle class="route-ring" cx="${n(point.x)}" cy="${n(point.y)}" r="11"/>` : ''}<circle class="node-hit" cx="${n(point.x)}" cy="${n(point.y)}" r="16"/><circle class="node-focus" cx="${n(point.x)}" cy="${n(point.y)}" r="11"/><circle class="node ${health} ${selected.has(node.ID) ? 'selected' : ''}" cx="${n(point.x)}" cy="${n(point.y)}" r="6"/><text class="node-label" text-anchor="${location.anchor}" x="${n(location.x)}" y="${n(location.y)}">${esc(node.Name || node.ID)}</text><text class="sub node-label" text-anchor="${location.anchor}" x="${n(location.x)}" y="${n(location.sub)}">${esc(subtitle(node))}</text></g>`;
  }).join('');
  return `<svg class="topology" viewBox="0 0 960 ${compact ? 280 : 360}" role="group" aria-label="Interactive concentric network topology"><defs><marker id="${arrow}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="#466fc2"/></marker></defs><ellipse class="topology-ring outer" cx="480" cy="${compact ? 140 : 180}" rx="310" ry="${compact ? 104 : 130}"/><ellipse class="topology-ring inner" cx="480" cy="${compact ? 140 : 180}" rx="170" ry="${compact ? 60 : 75}"/><text class="ring-key" x="18" y="21">inner: accepts connections · outer: reverse_only</text><text class="ring-key" text-anchor="end" x="942" y="21">hover preview · click lock · Esc clear</text>${edgeMarkup}${routeMarkup}${directMarkup}${nodeMarkup}${nodes.length ? '' : '<text class="sub" text-anchor="middle" x="480" y="180">No certified topology</text>'}</svg>`;
}

export function bindTopology(container) {
  const svg = container?.querySelector('svg');
  if (!svg) return;
  const nodes = [...svg.querySelectorAll('.topology-node')];
  const focused = container.contains(document.activeElement) ? document.activeElement.dataset.node : '';
  const known = new Set(nodes.map(node => node.dataset.node));
  let locked = known.has(container.dataset.locked) ? container.dataset.locked : '';
  const apply = (nodeID, edge = null) => {
    const active = !!(nodeID || edge), visible = new Set(nodeID ? [nodeID] : []);
    svg.classList.toggle('has-focus', active);
    for (const item of svg.querySelectorAll('.topology-edge,.topology-route')) {
      const related = edge ? item.dataset.from === edge.dataset.from && item.dataset.to === edge.dataset.to :
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
    const node = event.target.closest('.topology-node');
    if (event.key === 'Escape') {
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
