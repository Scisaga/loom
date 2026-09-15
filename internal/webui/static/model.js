export const roles = ['use_loom', 'forward', 'internet_egress', 'control'];
export const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
} [c]));
export const list = value => Array.isArray(value) ? value : [];
export const short = value => String(value || '').slice(0, 12) || '—';
export function matchesDevice(device, query) {
  const selected = query.getAll('role'),
    assigned = list(device.responsibilities);
  if (selected.length && !(query.get('match') === 'all' ? selected.every(r => assigned.includes(r)) : selected.some(r => assigned.includes(r)))) return false;
  if (query.get('platform') && device.platform !== query.get('platform')) return false;
  if (query.get('state') && device.data_plane_status !== query.get('state')) return false;
  if ((device.status === 'revoked') !== (query.get('archived') === '1')) return false;
  const search = (query.get('q') || '').trim().toLowerCase();
  return `${device.name} ${device.id}`.toLowerCase().includes(search);
}
// 加入码只用于未绑定身份；观测状态不能扩大生命周期操作范围。
export function deviceActions(device, capabilities, node) {
  if (!device) return [];
  const unjoined = ['pending', 'invite_expired'].includes(device.status) && !device.claimed_at && !device.key_fingerprint;
  const joinedAccess = device.identity_source === 'enrollment' && !!device.claimed_at && !!device.key_fingerprint &&
    ['active', 'paused'].includes(device.membership) && !['revoked', 'provisioning', 'pending'].includes(device.status) && !device.replaced_by &&
    list(device.responsibilities).length === 1 && device.responsibilities[0] === 'use_loom';
  const conditions = {renew: unjoined, discard: unjoined, replace: joinedAccess, delete: joinedAccess,
    purge: device.status === 'revoked' && !node?.Declared};
  return Object.keys(conditions).filter(action => capabilities[action] && conditions[action]);
}
export function enrollmentInput(form) {
  const data = new FormData(form),
    platform = data.get('platform');
  const responsibilities = platform === 'linux-server' ? data.getAll('responsibility') : ['use_loom'];
  const input = {
    name: String(data.get('name') || '').trim(),
    platform,
    responsibilities
  };
  if (responsibilities.includes('use_loom')) input.destination_grants = data.getAll('destination_grant');
  if (responsibilities.includes('forward')) input.direction = data.get('direction');
  return input;
}
export function bytes(value) {
  if (value === null || value === undefined || value === '') return '—';
  const n = typeof value === 'bigint' ? value : BigInt(value),
    units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let divisor = 1n,
    index = 0;
  while (n / divisor >= 1024n && index < units.length - 1) {
    divisor *= 1024n;
    index++;
  }
  return `${Number(n*10n/divisor)/10} ${units[index]}`;
}
export function trafficSample(counters, now = Date.now()) {
  const valid = list(counters).filter(c => c.trusted && c.counter_epoch && Number.isFinite(Date.parse(c.observed_at)));
  if (!valid.length) return null;
  // 不混合计数器重置边界；缺失的 peer 也会使速率区间重新开始。
  const sorted = [...valid].sort((a, b) => (a.interface + '|' + a.peer_node).localeCompare(b.interface + '|' + b.peer_node));
  let rx = 0n,
    tx = 0n;
  const identity = [];
  const times = [];
  for (const c of sorted) {
    try {
      rx += BigInt(c.rx_bytes);
      tx += BigInt(c.tx_bytes);
    } catch {
      return null;
    }
    identity.push(`${c.interface}|${c.peer_node}|${c.counter_epoch}`);
    times.push(Date.parse(c.observed_at));
  }
  const at = Math.min(...times);
  return {
    rx,
    tx,
    at,
    identity: identity.join('\n'),
    stale: now - at > 90000 || at > now + 60000
  };
}
export function trafficRate(previous, current) {
  if (!previous || !current || current.stale || previous.stale || previous.identity !== current.identity) return null;
  const seconds = (current.at - previous.at) / 1000;
  if (seconds <= 0 || seconds > 90 || current.rx < previous.rx || current.tx < previous.tx) return null;
  return {
    rx: BigInt(Math.round(Number(current.rx - previous.rx) / seconds)),
    tx: BigInt(Math.round(Number(current.tx - previous.tx) / seconds))
  };
}
export function currentNetwork(view) {
  const nodes = list(view.Nodes).filter(n => n.Declared && !n.Paused),
    ids = new Set(nodes.map(n => n.ID));
  const paths = a => list(a).filter(p => ids.has(p.Node) && list(p.Chain).every(id => ids.has(id)));
  return {
    ...view,
    Nodes: nodes,
    Links: list(view.Links).filter(e => ids.has(e.From) && ids.has(e.To)),
    Routes: paths(view.Routes),
    Candidates: paths(view.Candidates)
  };
}
// 沿用现行拓扑的 direction 分环与半步错位；运行路径从不参与位置计算。
export function topologyPositions(nodes) {
  const sorted = [...nodes].sort((a, b) => Number(!!b.Self) - Number(!!a.Self) || a.ID.localeCompare(b.ID));
  let inner = sorted.filter(n => n.Direction !== 'reverse_only'),
    outer = sorted.filter(n => n.Direction === 'reverse_only').sort((a, b) => a.ID.localeCompare(b.ID));
  if (!outer.length && inner.length > 1) outer = inner.splice(Math.ceil(inner.length / 2));
  const positions = new Map();
  [inner, outer].forEach((group, ring) => group.forEach((n, i) => {
    const angle = -90 + (ring ? 180 / group.length : 0) + i * 360 / group.length,
      radians = angle * Math.PI / 180;
    positions.set(n.ID, {
      x: 480 + (ring ? 310 : 170) * Math.cos(radians),
      y: 180 + (ring ? 130 : 75) * Math.sin(radians),
      angle,
      ring: ring ? 'outer' : 'inner'
    });
  }));
  return positions;
}
export function historyPoints(history, nodeID = '') {
  return list(history?.buckets).map(bucket => {
    const entries = list(bucket.nodes).filter(n => !nodeID || n.node === nodeID),
      accepted = entries.filter(n => n.samples > 0);
    return {
      start: bucket.start,
      end: bucket.end,
      present: accepted.length > 0 || (!nodeID && bucket.samples > 0),
      rx: accepted.reduce((sum, n) => sum + BigInt(n.rx_bytes), 0n),
      tx: accepted.reduce((sum, n) => sum + BigInt(n.tx_bytes), 0n),
      resets: entries.reduce((sum, n) => sum + n.resets, 0),
      gaps: entries.reduce((sum, n) => sum + n.gaps, 0),
      bucketResets: bucket.resets,
      bucketGaps: bucket.gaps
    };
  });
}

export function linkHistory(history) {
  const totals = new Map();
  for (const bucket of list(history?.buckets)) {
    for (const link of list(bucket.links)) {
      const key = [link.from, link.to].sort().join('|');
      let item = totals.get(key);
      if (!item) {
        item = {
          key,
          from: link.from,
          to: link.to,
          tx: 0n,
          buckets: 0,
          resets: 0,
          gaps: 0
        };
        totals.set(key, item);
      }
      item.resets += link.resets;
      item.gaps += link.gaps;
      if (link.samples > 0) {
        item.tx += BigInt(link.tx_bytes);
        item.buckets++;
      }
    }
  }
  return [...totals.values()];
}
