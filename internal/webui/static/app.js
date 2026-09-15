import {
  icon,
  platforms
} from './icons.js';
import {
  renderTopology,
  legend,
  linkMetric,
  age
} from './topology.js';
import {
  roles,
  esc,
  list,
  short,
  matchesDevice,
  enrollmentInput,
  bytes,
  trafficSample,
  trafficRate,
  currentNetwork,
  topologyPositions,
  historyPoints,
  linkHistory
} from './model.js';
const app = document.querySelector('#app'),
  connection = document.querySelector('#connection');
let inspectedLink = '';
let caps = {},
  snapshot = {
    view: {},
    inventory: {
      devices: []
    },
    node_traffic: {}
  },
  routeEpoch = 0,
  events = [],
  packages = null;
const samples = new Map(),
  rates = new Map(),
  orders = new Map();
const query = () => new URLSearchParams(location.search),
  node = id => list(snapshot.view.Nodes).find(n => n.ID === id);
const tag = v => `<span class="tag">${esc(v)}</span>`,
  tags = a => `<div class="tags">${list(a).map(tag).join('')}</div>`;
const link = (path, label) => `<a href="${esc(path)}" data-nav>${esc(label)}</a>`;
const badge = value => `<span class="badge ${['online','live','healthy','active','applied'].includes(value)?'good':['problem','failed'].includes(value)?'bad':['stale','unknown'].includes(value)?'warn':'muted'}">${esc(value||'Unknown')}</span>`;
const time = value => value ? `<time datetime="${esc(value)}" title="${esc(value)}">${esc(new Date(value).toLocaleString())}</time>` : 'Not reported';
const heading = (title, description, action = '') => `<div class="heading"><div><h1>${esc(title)}</h1><p>${esc(description)}</p></div>${action}</div>`;
const table = (headers, id) => `<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody id="${id}"></tbody></table></div>`;

function notify(message, bad = false) {
  const n = document.querySelector('#notice');
  n.textContent = message;
  n.hidden = false;
  n.classList.toggle('error', bad);
  clearTimeout(n.timer);
  n.timer = setTimeout(() => n.hidden = true, 7000);
}
async function api(path, body, method = 'POST') {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : method,
    headers: body === undefined ? {} : {
      'Content-Type': 'application/json'
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store',
    credentials: 'same-origin'
  });
  const raw = await response.text();
  let result;
  try {
    result = JSON.parse(raw);
  } catch {
    throw Error(raw || `HTTP ${response.status}`);
  }
  if (!response.ok) throw Error(result.error || `HTTP ${response.status}`);
  return result;
}
async function task(button, fn) {
  if (button?.disabled) return;
  const before = button?.textContent;
  if (button) {
    button.disabled = true;
    button.textContent = 'Working…';
  }
  try {
    await fn();
  } catch (error) {
    notify(error.message, true);
  } finally {
    if (button?.isConnected) {
      button.disabled = false;
      button.textContent = before;
    }
  }
}

function setHTML(element, html) {
  if (element && element.dataset.html !== html) {
    const open = [...element.querySelectorAll('details[open]')].map(d => d.querySelector('summary')?.textContent);
    element.innerHTML = html;
    for (const d of element.querySelectorAll('details'))
      if (open.includes(d.querySelector('summary')?.textContent)) d.open = true;
    element.dataset.html = html;
  }
}

function rows(id, items, key, render) {
  const parent = document.getElementById(id);
  if (!parent) return;
  const existing = new Map([...parent.children].map(e => [e.dataset.key, e]));
  for (const item of items) {
    const k = String(key(item));
    let tr = existing.get(k);
    if (!tr) {
      tr = document.createElement('tr');
      tr.dataset.key = k;
      parent.append(tr);
    }
    existing.delete(k);
    const cells = render(item);
    cells.forEach((html, i) => {
      let td = tr.children[i];
      if (!td) {
        td = document.createElement('td');
        tr.append(td);
      }
      setHTML(td, html);
    });
  }
  for (const tr of existing.values()) tr.remove();
}

function accept(data) {
  const warning = document.querySelector('#evidence-warning'),
    errors = [data.error, ...list(data.view.Warnings)].filter(Boolean);
  warning.textContent = errors.join(' · ');
  warning.hidden = errors.length === 0;
  for (const [id, traffic] of Object.entries(data.node_traffic || {})) {
    const next = trafficSample(traffic.current),
      previous = samples.get(id);
    if (next && (!previous || next.at !== previous.at || next.identity !== previous.identity)) {
      rates.set(id, trafficRate(previous, next));
      samples.set(id, next);
    } else if (!next || next.stale) {
      rates.delete(id);
      if (next) samples.set(id, next);
      else samples.delete(id);
    }
  }
  for (const id of [...samples.keys()])
    if (!(id in (data.node_traffic || {}))) {
      samples.delete(id);
      rates.delete(id);
    }
  snapshot = data;
  updatePage();
}
async function refresh() {
  accept(await api('/api/control/ui/snapshot'));
}

function navigate(url, replace = false) {
  const u = new URL(url, location.href);
  history[replace ? 'replaceState' : 'pushState']({}, '', u.pathname + u.search);
  render();
}
window.addEventListener('popstate', render);
document.addEventListener('click', event => {
  const a = event.target.closest('a[data-nav]');
  if (a && !event.ctrlKey && !event.metaKey && !event.shiftKey && event.button === 0) {
    event.preventDefault();
    navigate(a.href);
  }
});

function live() {
  let retry = 1000;
  const connect = () => {
    const ws = new WebSocket(`${location.protocol==='https:'?'wss:':'ws:'}//${location.host}/api/control/device-inventory/live`);
    ws.onopen = () => {
      retry = 1000;
      connection.textContent = caps.admin ? 'Live · Admin certificate' : 'Live · Read only';
    };
    ws.onmessage = event => {
      try {
        const m = JSON.parse(event.data);
        if (m.type === 'snapshot' && m.snapshot) accept(m.snapshot);
      } catch {
        connection.textContent = 'Invalid live update';
      }
    };
    ws.onclose = () => {
      connection.textContent = 'Reconnecting · last evidence retained';
      setTimeout(connect, retry);
      retry = Math.min(30000, retry * 2);
    };
    ws.onerror = () => ws.close();
  };
  connect();
}

function deviceRows() {
  const q = query(),
    devices = list(snapshot.inventory.devices).filter(d => matchesDevice(d, q));
  // 首次显示冻结顺序；实时状态改变不触发行移动。
  devices.forEach(d => {
    if (!orders.has(d.id)) orders.set(d.id, orders.size);
  });
  devices.sort((a, b) => orders.get(a.id) - orders.get(b.id));
  rows('devices-body', devices, d => d.id, d => {
    const n = node(d.id),
      sample = samples.get(d.id),
      rate = rates.get(d.id),
      fresh = sample && !sample.stale && Date.now() - sample.at <= 90000;
    const version = d.last_seen_at && n?.Version ? short(n.Version.Commit) + (n.Version.Dirty ? ' · modified' : '') : 'Not reported';
    return [
      `${link('/devices/'+encodeURIComponent(d.id),d.name||d.id)}<small>${esc(d.platform||'Unknown platform')} · <span class="mono">${esc(d.id)}</span></small>`,
      `${badge(d.presence_status==='live'?'online':d.presence_status||'unknown')}<small>${esc(d.membership||d.status)}</small>`,
      tags(d.responsibilities),
      `${badge(d.data_plane_status)}<small>${esc(d.config_state)}</small>`,
      sample ? `<span>${fresh&&rate?`↓ ${bytes(rate.rx)}/s · ↑ ${bytes(rate.tx)}/s`:'Rate unknown'}</span><small>WG total ↓ ${bytes(sample.rx)} · ↑ ${bytes(sample.tx)}${fresh?'':' · stale'}</small>` : '<span class="muted">Not reported</span><small>No device traffic counters</small>',
      `${esc(version)}<small>${time(d.last_seen_at)}</small>`,
      `<details class="details"><summary>${list(d.destination_grants).length} grants</summary>${tags(d.destination_grants)}</details>`,
      `${caps.pause&&list(d.responsibilities).length===1&&d.responsibilities[0]==='use_loom'&&['active','paused'].includes(d.membership)?`<button class="row-button" data-device-action="${d.membership==='paused'?'resume':'pause'}" data-id="${esc(d.id)}">${d.membership==='paused'?'Resume':'Pause'}</button>`:''}`
    ];
  });
  const count = document.querySelector('#device-count');
  if (count) count.textContent = `${devices.length} devices · ${snapshot.inventory.active_invites||0} active invitations`;
  const empty = document.querySelector('#device-empty');
  if (empty) empty.hidden = devices.length > 0;
}

function filters() {
  const q = query();
  return `<div class="filters" id="device-filters"><input aria-label="Search devices" type="search" name="q" placeholder="Search devices…" value="${esc(q.get('q'))}">${roles.map(r=>`<label class="filter-role"><input type="checkbox" name="role" value="${r}" ${q.getAll('role').includes(r)?'checked':''}>${r}</label>`).join('')}<select name="match" aria-label="Responsibility match"><option value="any">Any selected</option><option value="all" ${q.get('match')==='all'?'selected':''}>All selected</option></select><select name="platform" aria-label="Platform">${[['','All platforms'],['linux-server','Linux'],['windows-desktop','Windows'],['android','Android']].map(([v,t])=>`<option value="${v}" ${q.get('platform')===v?'selected':''}>${t}</option>`).join('')}</select><select name="state" aria-label="Runtime state">${['','online','problem','stale','unknown','not observed'].map(s=>`<option value="${s}" ${q.get('state')===s?'selected':''}>${s||'All runtime states'}</option>`).join('')}</select><label class="filter-role"><input type="checkbox" name="archived" value="1" ${q.get('archived')==='1'?'checked':''}>Archived</label></div>`;
}

function devicesPage() {
  app.innerHTML = heading('Devices', 'Presence, runtime and traffic from existing signed reports.', caps.create ? '<a class="button primary" href="/devices?new=1" data-nav>＋ Add Device</a>' : '') + filters() + table(['Device', 'Presence', 'Responsibilities', 'Loom runtime', 'Traffic · node WireGuard', 'Version / last report', 'Grants', ''], 'devices-body') + '<div class="empty" id="device-empty" hidden>No matching devices.</div><p class="list-count" id="device-count"></p>';
  const filtersElement = document.querySelector('#device-filters');
  filtersElement.addEventListener('input', () => {
    const q = new URLSearchParams();
    for (const input of filtersElement.querySelectorAll('input,select')) {
      if (input.type === 'checkbox' && !input.checked) continue;
      if (input.value && !(input.name === 'match' && input.value === 'any')) q.append(input.name, input.value);
    }
    history.replaceState({}, '', location.pathname + (q.size ? '?' + q : ''));
    deviceRows();
  });
  deviceRows();
}

function bindDeviceActions() {
  app.addEventListener('click', event => {
    const b = event.target.closest('[data-device-action]');
    if (!b) return;
    const action = b.dataset.deviceAction,
      confirmations = {
        replace: 'Confirm that the old identity and configuration have been deleted from this device before replacing it?',
        delete: 'Remove this device from Loom? Local files on the device will remain.',
        purge: 'Permanently delete this archived record?',
        discard: 'Discard this pending identity?'
      };
    if (confirmations[action] && !window.confirm(confirmations[action])) return;
    task(b, async () => {
      const result = await api('/api/control/ui/device-action', {
        id: b.dataset.id,
        action,
        confirm: !!confirmations[action]
      });
      if (result.invite?.invite_id) navigate('/devices/invites/' + encodeURIComponent(result.invite.invite_id));
      else {
        await refresh();
        notify('Device updated');
      }
    });
  });
}
async function enrollmentPage(epoch) {
  app.innerHTML = heading('Add Device', 'Create a one-time invitation with its platform and responsibilities.') + '<p>Loading available grants…</p>';
  const options = await api('/api/control/ui/enrollment-options');
  if (epoch !== routeEpoch) return;
  app.innerHTML = heading('Add Device', 'The invitation fixes platform, responsibilities and destination grants.') + `<section class="card form-card"><form id="enrollment-form"><div class="field"><label for="device-name">Display name</label><input id="device-name" name="name" required placeholder="e.g. build server" maxlength="128"></div><div class="field"><label for="device-platform">Platform</label><select id="device-platform" name="platform"><option value="windows-desktop">Windows</option><option value="android">Android</option><option value="linux-server">Linux</option></select></div><p id="fixed-role">Responsibility: <b>use_loom</b></p><fieldset id="role-choices" class="field" hidden><legend>Responsibilities</legend><div class="choices">${[['use_loom','Use Loom from this device'],['forward','Forward traffic for other devices'],['internet_egress','Offer Internet egress']].map(([v,t])=>`<label class="choice" ${v==='internet_egress'?'id="egress-choice" hidden':''}><input type="checkbox" name="responsibility" value="${v}" ${v==='use_loom'?'checked':''}><span>${v}<small>${t}</small></span></label>`).join('')}</div></fieldset><fieldset id="grant-choices" class="field"><legend>Destination grants</legend><div class="choices">${list(options.destination_grants).map(g=>`<label class="choice"><input type="checkbox" name="destination_grant" value="${esc(g.id)}" checked><span>${esc(g.name||g.id)}<small>${esc(g.id)}</small></span></label>`).join('')||'<p class="warn">No destination grants are available.</p>'}</div></fieldset><div id="direction-choice" class="field" hidden><label for="device-direction">Connection direction</label><select id="device-direction" name="direction" disabled><option value="bidirectional">Can initiate and accept connections</option><option value="reverse_only">Initiates reverse connections only</option><option value="direct_only">Accepts connections only</option></select><small>Direction controls data-plane links. It does not describe SSH access.</small></div><p class="inline-error" id="form-error" role="alert"></p><div class="actions"><button class="primary" type="submit">Create Device</button><a class="button" data-nav href="/devices">Cancel</a></div></form></section>`;
  const form = document.querySelector('#enrollment-form');
  const visibility = () => {
    const linux = form.platform.value === 'linux-server',
      use = form.querySelector('[value=use_loom]'),
      forward = form.querySelector('[value=forward]'),
      egress = form.querySelector('[value=internet_egress]');
    if (!linux) {
      use.checked = true;
      forward.checked = false;
      egress.checked = false;
    }
    if (!forward.checked) egress.checked = false;
    const toggle = (id, enabled) => {
      const e = form.querySelector('#' + id);
      e.hidden = !enabled;
      for (const control of e.querySelectorAll('input,select')) control.disabled = !enabled;
    };
    toggle('role-choices', linux);
    form.querySelector('#fixed-role').hidden = linux;
    toggle('egress-choice', linux && forward.checked);
    toggle('grant-choices', use.checked);
    toggle('direction-choice', linux && forward.checked);
  };
  form.addEventListener('change', visibility);
  visibility();
  form.addEventListener('submit', event => {
    event.preventDefault();
    task(form.querySelector('button[type=submit]'), async () => {
      const error = form.querySelector('#form-error');
      error.textContent = '';
      try {
        const invite = await api('/api/control/device-invites', enrollmentInput(form));
        navigate('/devices/invites/' + encodeURIComponent(invite.invite_id));
      } catch (e) {
        error.textContent = e.message;
        throw e;
      }
    });
  });
}
async function invitePage(id, epoch) {
  const invite = await api('/api/control/ui/invites/' + encodeURIComponent(id));
  if (epoch !== routeEpoch) return;
  const forward = list(invite.responsibilities).includes('forward');
  app.innerHTML = heading('Device invitation', invite.client_name || invite.client_id) + `<div class="grid"><section class="card"><h2>Install and join · ${esc(invite.platform)}</h2><div id="invite-packages">Loading packages…</div><p>${invite.platform==='android'?'Install the signed Release APK, then open Loom and scan the QR code.':invite.platform==='windows-desktop'?'Extract the package and open Loom, then import the QR or join file.':'Run the installation commands on the target through your existing SSH session or local console.'}</p><div id="install-commands"></div></section><section class="card">${!forward?`<img class="qr" src="/api/control/device-invites/${encodeURIComponent(id)}/qr.png" alt="One-time device invitation">`:''}<p class="note">Single use. Expires ${time(invite.expires_at)}.</p>${tags(invite.responsibilities)}<div class="field"><label for="invite-uri">One-time join link</label><input class="invite-input" id="invite-uri" readonly value="${esc(invite.invite_uri)}"></div><div class="actions"><button id="copy-invite">Copy join link</button>${!forward?`<a class="button" href="/api/control/device-invites/${encodeURIComponent(id)}/download" download>Download join file</a>`:''}</div><p class="muted">Share only with the intended device. Reconnects reuse its existing identity.</p></section></div><a class="button" href="/devices" data-nav>Back to Devices</a>`;
  document.querySelector('#copy-invite').onclick = () => task(document.querySelector('#copy-invite'), async () => {
    await navigator.clipboard.writeText(invite.invite_uri);
    notify('Join link copied');
  });
  const catalog = await getPackages();
  if (epoch !== routeEpoch) return;
  const available = list(catalog.artifacts).filter(p => p.platform === invite.platform && p.variant !== 'debug');
  setHTML(document.querySelector('#invite-packages'), available.map(packageCard).join('') || '<p class="note">No verified package is published for this platform.</p>');
  if (invite.platform === 'linux-server') {
    const pkg = available.find(p => p.arch === 'amd64');
    let text = '';
    if (pkg) {
      text = `sha256sum -c ${pkg.filename}.sha256\ntar -xzf ${pkg.filename}\ncd loom-client-linux-amd64\nsudo ./install.sh --no-enroll\nsudo /usr/local/bin/loom client enroll -stdin`;
    }
    setHTML(document.querySelector('#install-commands'), (forward ? `<p class="note">Declare the server endpoint and direction in /etc/loom/device.yaml before joining. Public listener readiness is separate from successful installation. Check the host firewall and existing mappings if readiness remains preparing.</p><p>Invitation direction: <b>${esc(invite.direction)}</b></p>` : '') + (text ? `<pre>${esc(text)}</pre><small>After enroll starts, paste the join link through stdin and press Ctrl-D. The secret stays out of shell history.</small>` : ''));
  }
}

function detailPage(id) {
  const d = list(snapshot.inventory.devices).find(d => d.id === id),
    n = node(id);
  if (!d && !n) {
    app.innerHTML = heading('Device', 'No current device evidence is available.');
    return;
  }
  app.innerHTML = heading(d?.name || n?.Name || id, id, link('/devices', '← Devices')) + `<div id="device-detail" class="card"></div><section class="card"><h2>WireGuard links</h2>${table(['Peer / interface','Carrier','Handshake','Cumulative RX / TX','Evidence'],'tunnels-body')}</section><section class="card" id="device-history"></section><div id="device-actions" class="actions"></div>`;
  updateDetail(id);
}

function updateDetail(id) {
  updateHistory('device-history', id);
  const d = list(snapshot.inventory.devices).find(d => d.id === id),
    n = node(id);
  if (!d && !n) return;
  setHTML(document.querySelector('#device-detail'), `<div class="metrics"><div class="metric">Presence<strong>${badge(d?.presence_status)}</strong><small>${time(d?.heartbeat_at)}</small></div><div class="metric">Loom runtime<strong>${badge(d?.data_plane_status||n?.Health)}</strong><small>${time(d?.last_seen_at||n?.ObservedAt)}</small></div><div class="metric">Configuration<strong>${esc(d?.config_state||short(n?.Applied))}</strong></div><div class="metric">Version<strong>${esc(d?.last_seen_at?short(n?.Version?.Commit):'Not reported')}</strong></div></div><hr>${tags(d?.responsibilities||n?.Roles)}<p>Destination grants</p>${tags(d?.destination_grants)}${list(d?.runtime_problems).map(p=>`<p class="note error">${esc(p)}</p>`).join('')}<details class="details"><summary>Evidence and configuration details</summary><pre>${esc(JSON.stringify({source:n?.Source,observed_at:n?.ObservedAt,direction:d?.direction,endpoint:d?.public_endpoint,components:n?.Components,rollout:n?.Rollout},null,2))}</pre></details>`);
  const counters = list(snapshot.node_traffic?.[id]?.current);
  rows('tunnels-body', list(n?.Tunnels), t => t.Interface + '|' + t.PeerNode, t => {
    const c = counters.find(c => c.interface === t.Interface && c.peer_node === t.PeerNode);
    return [`${esc(t.PeerNode||'Unknown peer')}<small>${esc(t.Interface)}</small>`, t.CarrierPresent ? badge(t.State) : 'Not observed', t.CarrierPresent ? (t.AgeSec >= 0 ? `${t.AgeSec}s ago` : 'Never') : 'Unknown', c?.trusted ? `${bytes(c.rx_bytes)} / ${bytes(c.tx_bytes)}` : 'Not reported', `${esc(c?.source||'No counters')}<small>${time(c?.observed_at)}</small>`];
  });
  if (d) {
    const actions = [];
    const add = (key, label, condition = true) => {
      if (caps[key] && condition) actions.push(`<button data-device-action="${key}" data-id="${esc(id)}" class="${['delete','purge','discard'].includes(key)?'danger':''}">${label}</button>`);
    };
    add('renew', 'New join code', d.status !== 'revoked');
    add('replace', 'Replace identity', d.status !== 'revoked');
    add('delete', 'Remove device', d.status !== 'revoked');
    add('purge', 'Delete archived record', d.status === 'revoked');
    add('discard', 'Discard pending identity', d.membership === 'identity only');
    setHTML(document.querySelector('#device-actions'), actions.join(''));
  }
}

function overviewPage() {
  app.innerHTML = '<div class="network-heading"><span class="eyebrow">LIVE NETWORK</span><h1>Network overview</h1><p class="dim" id="overview-subtitle"></p></div><div id="overview-health" class="overview-health"></div><div id="overview-stats" class="steps"></div><div id="snapshot-verdict"></div><div class="overview-primary"><section class="card overview-topology-card"><div class="overview-card-head"><h2>Network topology</h2>' + legend + '</div><div id="overview-topology"></div></section><aside class="overview-side"><section class="card overview-compact-card" id="overview-traffic"></section><section class="card overview-compact-card" id="overview-rollout"></section></aside></div><div class="overview-secondary"><section class="card overview-list-card"><div class="sectionhead"><h2>Network devices</h2><a class="tiny" href="/devices" data-nav>All devices →</a></div>' + table(['Name', 'Location', 'Status', 'WG RX / TX · 24h', 'Last seen'], 'overview-nodes') + '</section><section class="card overview-list-card"><div class="sectionhead"><h2>Automatic routing</h2><a class="tiny" href="/routing" data-nav>Decision evidence →</a></div>' + table(['Managed rule', 'Scope', 'Agent-selected path', 'Status'], 'overview-routes') + '</section></div><section class="card overview-events"><div class="sectionhead"><h2>Recent events</h2><a class="tiny" href="/events" data-nav>View all events →</a></div><div id="overview-events"></div></section><div id="overview-warnings"></div><details class="network-history"><summary>Retained WireGuard traffic · detailed time buckets</summary><section class="card" id="fleet-history"></section></details>';
  updateOverview();
  if (caps.admin) api('/api/control/ui/events').then(value => {
    if (location.pathname !== '/') return;
    events = list(value.events);
    updateOverviewEvents();
  }).catch(error => setHTML(document.querySelector('#overview-events'), `<p class="muted">${esc(error.message)}</p>`));
}

function ruleName(v, r) {
  return list(r.ScopeKind === 'service' ? v.Services : v.Policies).find(s => s.ID === r.ScopeID)?.Name || r.ScopeID || r.Declaration || r.Selector;
}

function routePath(r) {
  return list(r.Chain).length ? r.Chain.join(' → ') : `${r.Node} · local exit`;
}

function networkView() {
  const v = currentNetwork(snapshot.view),
    devices = new Map(list(snapshot.inventory.devices).map(d => [d.id, d]));
  return {
    ...v,
    Nodes: v.Nodes.map(n => {
      const d = devices.get(n.ID);
      return d ? {
        ...n,
        Health: d.data_plane_status === 'online' ? 'healthy' : d.data_plane_status === 'problem' ? 'problem' : 'unknown'
      } : n;
    })
  };
}

function updateOverview() {
  const v = networkView(),
    active = v.Nodes.filter(n => !n.Decommission),
    healthy = active.filter(n => n.Health === 'healthy').length,
    problems = active.filter(n => n.Health === 'problem').length,
    unknown = active.length - healthy - problems,
    carriers = v.Links.filter(l => l.Kind === 'tunnel'),
    fresh = v.Routes.filter(r => !r.Stale),
    history = snapshot.traffic?.history,
    points = historyPoints(history),
    known = points.filter(p => p.present),
    total = known.reduce((sum, p) => sum + p.rx + p.tx, 0n),
    max = known.reduce((sum, p) => p.rx + p.tx > sum ? p.rx + p.tx : sum, 1n),
    publisher = v.Publisher;
  const healthClass = problems ? 'bad' : unknown ? 'warn' : 'ok';
  setHTML(document.querySelector('#overview-subtitle'), `${esc(v.Self||'Current network')} control plane · observed ${esc(age(v.ObservedAt))}`);
  setHTML(document.querySelector('#overview-health'), `<span class="status-check ${healthClass}">${problems?'!':unknown?'?':'✓'}</span><span>${healthy} 个节点正常${problems?` · ${problems} 个异常`:''}${unknown?` · ${unknown} 个等待可信状态上报`:''}</span>`);
  setHTML(document.querySelector('#overview-stats'), [
    ['节点状态', `${healthy} <small>/ ${active.length} 正常</small>`, `${problems} 个异常 · ${unknown} 个等待上报`],
    ['WireGuard 常驻隧道', `${carriers.filter(l=>l.State==='active').length} / ${carriers.length} <small>已连通</small>`, '仅统计配置中声明的隧道'],
    ['自动选路决策', `${fresh.length} / ${v.Routes.length} <small>已上报</small>`, '规则生成 · Agent 自动选择'],
    ['配置快照', esc(short(v.Applied)), `控制面当前版本 · ${esc(age(v.ObservedAt))}`]
  ].map(([title, value, detail]) => `<div class="step"><span class="label">${title}</span><b>${value}</b><span class="tiny dim">${detail}</span></div>`).join(''));
  const versions = new Set(active.map(n => n.Applied).filter(Boolean)),
    missing = active.filter(n => !n.Applied).length;
  setHTML(document.querySelector('#snapshot-verdict'), versions.size > 1 || missing ? `<aside class="note snapshot-alert"><strong>${versions.size>1?'配置仍在同步':'配置版本证据不完整'}</strong><span>${versions.size} 个已上报版本 · ${missing} 个设备尚未验证</span></aside>` : '');
  renderTopology(document.querySelector('#overview-topology'), v);
  const bars = points.slice(-16),
    barWidth = 220 / Math.max(bars.length, 1);
  const spark = `<svg class="traffic-spark" viewBox="0 0 220 62" role="img" aria-label="Retained WireGuard traffic buckets"><path d="M0 1H220M0 30H220M0 61H220" stroke="#e2e6e3" fill="none"/>${bars.map((p,i)=>{
    const height=Number((p.rx+p.tx)*50n/max);return p.present?`<rect x="${i*barWidth+2}" y="${60-height}" width="${Math.max(1,barWidth-4)}" height="${Math.max(1,height)}" fill="#73c39d"><title>${esc(bytes(p.rx+p.tx))} · ${p.resets} resets · ${p.gaps} gaps</title></rect>`:`<path d="M${i*barWidth+barWidth/2} 5v52" stroke="#ccd2ce" stroke-dasharray="2 4"><title>No accepted delta</title></path>`;
  }).join('')}</svg>`;
  setHTML(document.querySelector('#overview-traffic'), `<div class="sectionhead"><h2>WireGuard traffic</h2><span class="tiny dim">Retained centrally · last 24h</span></div><div class="traffic-compact-body"><div><div class="label">Last 24h</div><div class="metric">${known.length?bytes(total):'Unavailable'}</div><div class="tiny dim">${known.length} / ${points.length} sampled buckets</div></div><div>${spark}<div class="traffic-compact-scale"><span>Node-interface RX + TX</span><span>now</span></div></div></div>`);
  const verified = active.filter(n => n.Rollout?.Stage === 'verified').length,
    applied = active.filter(n => publisher?.LastSnapshot && n.Applied === publisher.LastSnapshot).length,
    stages = [
      ['Signed', !!publisher?.LastSnapshot],
      ['Distributed', !!publisher?.Healthy && !!publisher?.LastSuccess],
      ['Applied', active.length > 0 && applied === active.length],
      ['Verified', active.length > 0 && verified === active.length]
    ];
  setHTML(document.querySelector('#overview-rollout'), `<div class="sectionhead"><h2>Latest fleet rollout</h2><a class="tiny" href="/releases?tab=deployments" data-nav>Deployments →</a></div>${publisher?`<div class="rollout-summary">Snapshot <b class="mono">${esc(short(publisher.LastSnapshot))}</b><br><span class="dim">${verified} / ${active.length} verified</span></div><div class="rollout-stages">${stages.map(([label,done])=>`<span class="rollout-stage ${done?'done':'pending'}">${label}</span>`).join('')}</div><div class="tiny dim">publisher code ${esc(short(publisher.Commit))} · last success ${esc(age(publisher.LastSuccess))}</div>`:'<p class="muted">Publisher state is unavailable.</p>'}`);
  const ordered = [...v.Nodes].sort((a, b) => Number(!!b.Self) - Number(!!a.Self) || a.ID.localeCompare(b.ID)).slice(0, 6);
  rows('overview-nodes', ordered, n => n.ID, n => {
    const samples = historyPoints(history, n.ID).filter(p => p.present),
      rx = samples.reduce((sum, p) => sum + p.rx, 0n),
      tx = samples.reduce((sum, p) => sum + p.tx, 0n);
    return [link('/devices/' + encodeURIComponent(n.ID), n.ID), esc([n.Country, n.City].filter(Boolean).join(' ') || n.Name || '—'), badge(n.Health), samples.length ? bytes(rx) + ' / ' + bytes(tx) : '—', esc(age(n.ObservedAt))];
  });
  rows('overview-routes', v.Routes.slice(0, 5), r => r.Node + '|' + r.Selector, r => [esc(ruleName(v, r)), esc(r.ScopeKind || 'Policy'), esc(routePath(r)), badge(r.Stale ? 'stale' : 'observed')]);
  setHTML(document.querySelector('#overview-warnings'), problems || unknown ? `<section class="card overview-attention"><div class="sectionhead"><h2>需要关注</h2><a class="tiny" href="/devices" data-nav>查看设备 →</a></div><p>${problems} 个节点异常 · ${unknown} 个节点等待可信观测</p></section>` : '');
  updateHistory('fleet-history');
  updateOverviewEvents();
}

function updateOverviewEvents() {
  setHTML(document.querySelector('#overview-events'), events.slice(0, 3).map(e => `<div class="overview-event-row"><time>${esc(e.TS?new Date(e.TS).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',hour12:false}):'—')}</time><span class="dot"></span><span class="clip">${esc(e.Detail||`${e.Node} · ${e.Kind} · ${e.From} → ${e.To}`)}</span></div>`).join('') || '<p class="tiny dim">No recent transitions.</p>');
}

function topologyPage() {
  app.innerHTML = '<div class="network-heading"><span class="eyebrow">NETWORK / TOPOLOGY</span><h1>Network topology</h1><p class="dim" id="topology-subtitle"></p></div><div id="topology-summary" class="overview-health"></div><div class="topology-layout"><section class="card topology-stage"><div class="topology-card-head"><div><h2>Topology layers</h2><p class="dim">Declared structure remains visible when trusted observation is missing.</p></div>' + legend + '</div><div id="topology"></div><p class="topology-caption">Candidate edges describe allowable paths. Missing a direct WireGuard edge does not mean there is no path.</p></section><aside class="topology-side"><section class="card topology-status-card" id="topology-status"></section><section class="card topology-traffic-card" id="topology-traffic"></section></aside></div><section class="card topology-edge-card"><div class="edge-panel-head"><h2>Persistent WireGuard edges</h2><span class="dim">24h link bytes = TX deltas from each endpoint; receiver RX is not added again</span></div>' + table(['Edge', '24h TX total / bar', 'Buckets with samples', 'RTT', 'State', 'Latest trusted sample'], 'links-body') + '</section><details id="topology-candidates" class="network-history"><summary>On-demand route hops · configured intent</summary><div id="candidate-links" class="route-hop-list"></div></details>';
  document.querySelector('#links-body').addEventListener('click', e => {
    const row = e.target.closest('tr');
    if (row) {
      inspectedLink = row.dataset.key;
      updateTopology();
    }
  });
  document.querySelector('#links-body').addEventListener('keydown', e => {
    if (['Enter', ' '].includes(e.key)) {
      e.preventDefault();
      e.target.closest('tr')?.click();
    }
  });
  updateTopology();
}

function updateTopology() {
  if (!document.querySelector('#topology')) return;
  const v = networkView(),
    entry = query().get('entry'),
    carriers = v.Links.filter(l => l.Kind === 'tunnel'),
    direct = v.Links.filter(l => l.Kind === 'direct-hy2'),
    candidates = v.Links.filter(l => l.Kind === 'candidate'),
    active = carriers.filter(l => l.State === 'active').length,
    fresh = v.Routes.filter(r => !r.Stale),
    history = snapshot.traffic?.history,
    totals = linkHistory(history),
    key = l => [l.From, l.To].sort().join('|');
  setHTML(document.querySelector('#topology-subtitle'), `Intent, trusted observations and read-only automatic Agent decisions · observed ${esc(age(v.ObservedAt))}`);
  setHTML(document.querySelector('#topology-summary'), `<span class="status-check ${active===carriers.length&&active?'ok':'warn'}">${active===carriers.length&&active?'✓':'?'}</span><span>${v.Nodes.length} nodes · ${carriers.length} persistent WireGuard links · ${fresh.length} fresh automatic decisions</span>`);
  renderTopology(document.querySelector('#topology'), v, v.Routes.filter(r => !entry || r.Node === entry));
  setHTML(document.querySelector('#topology-status'), `<div class="sectionhead"><h2>Layer status</h2><span class="tiny ${active===carriers.length&&active?'ok':'dim'}">${active===carriers.length&&active?'● ALL OBSERVED':'PARTIAL EVIDENCE'}</span></div><div class="layer-carriers"><div class="label">WIREGUARD CARRIERS</div><div class="metric ${active===carriers.length&&active?'ok':''}">${active} / ${carriers.length} active</div><span class="tiny dim">${carriers.length} declared · current inventory · signed evidence</span></div><div class="topology-status-grid"><div><div class="label">HY2 DIRECT</div><div class="metric">${direct.filter(l=>l.Samples>l.Failures).length} / ${direct.length} sampled</div><div class="tiny dim">Signed single-hop probe</div></div><div><div class="label">ON-DEMAND</div><div class="metric">${candidates.length} possible hops</div><div class="tiny dim">Intent only · no tunnel health</div></div></div><div class="layer-routing"><div class="label">AUTOMATIC ROUTING</div><a href="/routing" data-nav>${fresh.length} / ${v.Routes.length} fresh · Agent-selected · read-only →</a></div>`);
  if (!carriers.some(l => key(l) === inspectedLink)) inspectedLink = carriers.length ? key(carriers[0]) : '';
  const max = totals.reduce((sum, l) => l.tx > sum ? l.tx : sum, 1n);
  rows('links-body', carriers, key, l => {
    const m = linkMetric(l),
      total = totals.find(t => t.key === key(l)),
      ratio = total ? Number(total.tx * 220n / max) : 0;
    return [`<span class="mono">${esc(l.From)} ↔ ${esc(l.To)}</span>`, `<div class="link-total"><span class="mono">${total?.buckets?bytes(total.tx):'—'}</span><svg viewBox="0 0 230 12" aria-hidden="true"><rect x="0" y="2" width="230" height="8" rx="2" fill="#edf1ee"/>${total?.buckets?`<rect x="0" y="2" width="${ratio}" height="8" rx="2" fill="#73c39d"/>`:''}</svg></div>`, `<span class="mono">${total?.buckets||0} / ${list(history?.buckets).length} · ${total?.resets||0} reset · ${total?.gaps||0} gap</span>`, m.latency, badge(l.State), esc(age(l.ObservedAt))];
  });
  for (const row of document.querySelectorAll('#links-body tr')) {
    row.tabIndex = 0;
    row.classList.toggle('inspected', row.dataset.key === inspectedLink);
    row.setAttribute('aria-selected', String(row.dataset.key === inspectedLink));
  }
  const selected = carriers.find(l => key(l) === inspectedLink),
    total = totals.find(l => l.key === inspectedLink),
    buckets = list(history?.buckets).slice(-16).map(b => list(b.links).find(l => [l.from, l.to].sort().join('|') === inspectedLink)),
    peak = buckets.reduce((max, l) => l?.samples > 0 && BigInt(l.tx_bytes) > max ? BigInt(l.tx_bytes) : max, 1n),
    width = 230 / Math.max(buckets.length, 1),
    endpoints = buckets.reduce((max, l) => Math.max(max, l?.reporting_endpoints || 0), 0);
  const spark = `<svg class="link-spark" viewBox="0 0 230 80" role="img" aria-label="Selected link TX deltas"><path d="M0 5H230M0 40H230M0 76H230" fill="none" stroke="#e2e6e3"/>${buckets.map((l,i)=>{if(!l?.samples)return `<path d="M${i*width+width/2} 10v62" stroke="#ccd2ce" stroke-dasharray="3 4"><title>No accepted delta</title></path>`;const h=Number(BigInt(l.tx_bytes)*65n/peak);return `<rect x="${i*width+2}" y="${75-h}" width="${Math.max(1,width-4)}" height="${Math.max(1,h)}" fill="#2aa875"><title>${esc(bytes(l.tx_bytes))} · ${l.resets} resets · ${l.gaps} gaps</title></rect>`;}).join('')}</svg>`;
  setHTML(document.querySelector('#topology-traffic'), `<div class="sectionhead"><h2>Link traffic</h2><span class="tiny ok">Retained · endpoint TX only</span></div><p class="mono tiny">${selected?`Inspecting · ${esc(selected.From)} ↔ ${esc(selected.To)}`:'No persistent link'}</p><div class="link-traffic-body"><div><span class="tiny ok">Endpoint TX total</span><div class="metric">${total?.buckets?bytes(total.tx):'Unavailable'}</div><span class="tiny dim">Reporting endpoints</span><div class="metric">${endpoints}</div></div><div>${spark}<div class="traffic-compact-scale"><span>24h ago</span><span>now</span></div></div></div><span class="tiny dim">Undirected link · no RX double count</span>`);
  document.querySelector('#topology-candidates').hidden = !candidates.length;
  setHTML(document.querySelector('#candidate-links'), candidates.map(l => `<div class="route-hop"><span class="mono">${esc(l.From)} ↔ ${esc(l.To)}</span><span class="tiny dim">Available by intent · no continuous RTT or heartbeat</span></div>`).join(''));
}

function routingPage() {
  app.innerHTML = heading('Live paths', 'Agent selections and candidates are read-only observations.') + table(['Entry', 'Service / policy', 'Selected chain', 'Reason', 'Evidence'], 'routes-body') + '<section class="card"><h2>Candidate paths</h2>' + table(['Entry', 'Service / policy', 'Chain', 'State'], 'candidates-body') + '</section>';
  updateRouting();
}

function updateRouting() {
  const v = currentNetwork(snapshot.view);
  rows('routes-body', v.Routes, r => r.Node + '|' + r.Selector, r => [link('/devices/' + encodeURIComponent(r.Node), r.Node), `${esc(r.ScopeID||r.Declaration)}<small>${esc(r.PolicyID)}</small>`, esc(list(r.Chain).join(' → ') || r.Candidate), `${esc(r.Reason)}${r.Health?`<small>Selected: ${esc(r.Health.SelectedState)} · ${esc(r.Health.SelectedMetrics||'metrics unknown')}</small>`:''}`, `${badge(r.Stale?'stale':'observed')}<small>${time(r.ObservedAt)} · ${esc(r.Source)}</small>`]);
  rows('candidates-body', v.Candidates, c => c.Node + '|' + c.Declaration + '|' + list(c.Chain).join('/'), c => [esc(c.Node), esc(c.ScopeID || c.Declaration), esc(list(c.Chain).join(' → ')), badge(c.State)]);
}
async function servicesPage(epoch) {
  app.innerHTML = heading('Services', 'Host matches → Service → Policy', caps.services ? '<a class="button primary" href="/services?new=1" data-nav>＋ Add Service</a>' : '') + table(['Service', 'Host matches / addresses', 'Policy', ''], 'services-body') + '<div id="service-editor"></div>';
  updateServices();
  if (!(query().get('new') || query().get('service')) || !caps.services) return;
  const ssot = await api('/api/control/ui/ssot');
  if (epoch !== routeEpoch) return;
  const service = list(snapshot.view.Services).find(s => s.ID === query().get('service')) || {};
  document.querySelector('#service-editor').innerHTML = `<section class="card form-card"><h2>${service.ID?'Edit Service':'Add Service'}</h2><form id="service-form"><div class="field"><label>ID</label><input name="id" required value="${esc(service.ID)}" ${service.ID?'readonly':''}></div><div class="field"><label>Name</label><input name="name" value="${esc(service.Name)}"></div><div class="field"><label>Host matches / addresses · one per line</label><textarea name="addresses" required>${esc(list(service.Addresses).join('\n'))}</textarea></div><div class="field"><label>Policy</label><select name="policy" required>${list(snapshot.view.Policies).map(p=>`<option value="${esc(p.ID)}" ${p.ID===service.PolicyID?'selected':''}>${esc(p.Name||p.ID)}</option>`).join('')}</select></div><p id="service-error" class="inline-error"></p><div class="actions"><button class="primary" type="submit">Save Service</button>${service.ID?'<button type="button" id="delete-service" class="danger">Delete Service</button>':''}<a class="button" href="/services" data-nav>Cancel</a></div></form></section>`;
  const form = document.querySelector('#service-form'),
    save = async (deleting, button) => task(button, async () => {
      try {
        await api('/api/control/ui/services', {
          service: {
            ID: form.elements.id.value,
            Name: form.elements.name.value,
            Declaration: form.elements.policy.value,
            Addresses: form.elements.addresses.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
          },
          revision: ssot.revision,
          delete: deleting
        });
        await refresh();
        navigate('/services');
        notify('SSOT saved; publication and application are separate states.');
      } catch (e) {
        document.querySelector('#service-error').textContent = e.message;
        throw e;
      }
    });
  form.onsubmit = e => {
    e.preventDefault();
    save(false, e.submitter);
  };
  if (service.ID) document.querySelector('#delete-service').onclick = e => {
    if (confirm('Delete this Service?')) save(true, e.target);
  };
}

function updateServices() {
  rows('services-body', list(snapshot.view.Services), s => s.ID, s => [`${esc(s.Name||s.ID)}<small>${esc(s.ID)}</small>`, tags(list(s.Hosts).map(h => h.Match + ': ' + h.Host).concat(list(s.Addresses))), esc(s.PolicyID), caps.services ? link('/services?service=' + encodeURIComponent(s.ID), 'Edit') : '']);
}
async function ssotPage(epoch) {
  if (!caps.ssot) {
    app.innerHTML = heading('SSOT', 'An authorized administrator certificate is required.');
    return;
  }
  const value = await api('/api/control/ui/ssot');
  if (epoch !== routeEpoch) return;
  app.innerHTML = heading('SSOT', 'Validate and save the complete configuration with revision conflict protection.') + `<section class="card"><form id="ssot-form"><textarea class="ssot-editor" name="content" spellcheck="false" aria-label="SSOT source">${esc(value.content)}</textarea><p class="mono muted" id="ssot-revision">Revision ${esc(value.revision)}</p><pre id="ssot-findings" hidden></pre><div class="actions"><button type="submit" name="action" value="validate">Validate</button><button class="primary" type="submit" name="action" value="save">Save SSOT</button></div></form></section>`;
  let revision = value.revision;
  document.querySelector('#ssot-form').onsubmit = e => {
    e.preventDefault();
    const form = e.target,
      action = e.submitter.value;
    task(e.submitter, async () => {
      const findings = document.querySelector('#ssot-findings');
      findings.hidden = false;
      try {
        const result = await api('/api/control/ui/ssot', {
          content: form.elements.content.value,
          revision,
          action
        });
        findings.textContent = result.findings || (result.saved ? 'Saved. Publication and device application are tracked in Releases.' : 'Validation passed.');
        if (result.saved) {
          revision = result.revision;
          document.querySelector('#ssot-revision').textContent = 'Revision ' + revision;
        }
      } catch (error) {
        findings.textContent = error.message;
        throw error;
      }
    });
  };
}
async function eventsPage(epoch) {
  if (!caps.admin) {
    app.innerHTML = heading('Events', 'An administrator certificate is required.');
    return;
  }
  app.innerHTML = heading('Events', 'State changes and unresolved conditions.', '<a class="button" href="/events.csv" download>Export CSV</a>') + `<div class="filters"><input type="search" id="event-search" aria-label="Filter events" placeholder="Search events…"><select id="event-level" aria-label="Event level"><option value="">All levels</option><option>problem</option><option>ok</option><option>info</option><option>pending</option></select><button id="refresh-events">Refresh</button></div>` + table(['Time', 'Device', 'Kind / subject', 'Change', 'Level / detail'], 'events-body') + '<div id="unresolved"></div>';
  const load = async () => {
    const result = await api('/api/control/ui/events');
    if (epoch !== routeEpoch) return;
    events = list(result.events);
    updateEvents();
    setHTML(document.querySelector('#unresolved'), list(result.unresolved).map(e => `<p class="note">${esc(e.Node)} · ${esc(e.Kind)} · ${esc(e.Detail)} · ${e.AtLeast?'at least ':''}${esc(e.Lasted)}</p>`).join(''));
  };
  document.querySelector('#event-search').oninput = updateEvents;
  document.querySelector('#event-level').onchange = updateEvents;
  document.querySelector('#refresh-events').onclick = e => task(e.target, load);
  await load();
}

function updateEvents() {
  const q = document.querySelector('#event-search')?.value.toLowerCase() || '',
    level = document.querySelector('#event-level')?.value;
  rows('events-body', events.filter(e => (!level || e.Level === level) && JSON.stringify(e).toLowerCase().includes(q)), e => e.TS + '|' + e.Node + '|' + e.Kind + '|' + e.Subject, e => [time(e.TS), esc(e.Node), `${esc(e.Kind)}<small>${esc(e.Subject)}</small>`, `${esc(e.From)} → ${esc(e.To)}`, `${badge(e.Level)}<small>${esc(e.Detail)}</small>`]);
}
async function getPackages() {
  try {
    packages = await api('/api/control/ui/releases');
  } catch (e) {
    packages = {
      artifacts: [],
      error: e.message
    };
  }
  return packages;
}

function packageCard(p) {
  const platform = platforms.find(value => value.id === p.platform),
    title = p.platform === 'windows-desktop' ? p.variant : p.platform === 'android' ? (p.variant === 'debug' ? 'Debug APK' : 'Release APK') : p.title || 'Linux server';
  return `<article class="card package"><div class="package-heading"><span class="platform-mark ${platform?.icon||''}">${icon(platform?.icon)}</span><div><h3>${esc(title)}</h3><span class="muted">${esc(p.version)}</span></div>${tag(p.arch)}</div><div class="artifact-source">Source <span class="mono">${esc(short(p.source_commit))}</span> · ${bytes(p.size)}</div><small>${esc(p.signing||'Platform signature verified')}</small><details class="details"><summary>Checksum and release evidence</summary><p class="digest mono">SHA-256 ${esc(p.sha256)}</p></details><div class="actions"><a class="button primary" href="${esc(p.url)}" download>${icon('download')}Download</a>${p.checksum_url?`<a class="button" href="${esc(p.checksum_url)}" download>SHA-256</a>`:''}${p.signature_url?`<a class="button" href="${esc(p.signature_url)}" download>Signature</a>`:''}${p.sbom_url?`<a class="button" href="${esc(p.sbom_url)}" download>SBOM</a>`:''}</div></article>`;
}
async function releasesPage(epoch) {
  const deployment = query().get('tab') === 'deployments' || location.pathname === '/deployments',
    selected = platforms.find(p => p.id === query().get('platform')) || platforms[0];
  app.innerHTML = heading('Releases', 'Client packages and deployment history.') + `<div class="release-tabs" role="tablist" aria-label="Release platform">${platforms.map(p=>`<a role="tab" aria-selected="${!deployment&&p.id===selected.id}" tabindex="${!deployment&&p.id===selected.id?0:-1}" aria-controls="release-content" href="/releases?platform=${p.id}" data-nav>${icon(p.icon)}${p.label}</a>`).join('')}<a role="tab" aria-selected="${deployment}" tabindex="${deployment?0:-1}" aria-controls="release-content" href="/releases?tab=deployments" data-nav>${icon('releases')}Deployments</a></div><div id="release-content" role="tabpanel"></div>`;
  const tabs = document.querySelector('.release-tabs');
  tabs.onkeydown = e => {
    const items = [...tabs.querySelectorAll('[role=tab]')],
      index = items.indexOf(e.target);
    if (index < 0 || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
    e.preventDefault();
    const next = e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : (index + (e.key === 'ArrowRight' ? 1 : -1) + items.length) % items.length;
    navigate(items[next].getAttribute('href'));
  };
  if (deployment) {
    document.querySelector('#release-content').innerHTML = '<section class="card" id="publisher"></section>' + table(['Device', 'Applied configuration', 'Running version', 'Rollout', 'Last report'], 'deployments-body');
    updateDeployments();
    return;
  }
  const catalog = await getPackages();
  if (epoch !== routeEpoch) return;
  const order = ['server', 'release', 'installed', 'portable-tun', 'portable-mixed', 'debug'],
    artifacts = list(catalog.artifacts).filter(p => p.platform === selected.id).sort((a, b) => order.indexOf(a.variant) - order.indexOf(b.variant) || a.arch.localeCompare(b.arch)),
    stable = artifacts.filter(p => p.variant !== 'debug'),
    debug = artifacts.filter(p => p.variant === 'debug');
  setHTML(document.querySelector('#release-content'), (catalog.error ? `<p class="note">${esc(catalog.error)}</p>` : '') + (catalog.publication?.mirrors ? `<p class="release-publication muted">${catalog.publication.mirrors} distribution locations verified at publication · ${time(catalog.publication.verified_at)}</p>` : '') + `<div class="grid package-grid">${stable.map(packageCard).join('')||'<p class="muted">No verified package published.</p>'}</div>` + (debug.length ? `<details class="details developer-packages"><summary>Developer packages</summary><div class="grid package-grid">${debug.map(packageCard).join('')}</div></details>` : ''));
}

function updateDeployments() {
  const p = snapshot.view.Publisher;
  setHTML(document.querySelector('#publisher'), '<h2>Publisher</h2>' + (p ? `${badge(p.Healthy?'healthy':'problem')}<p>Last publication ${time(p.LastSuccess)} · snapshot <span class="mono">${esc(short(p.LastSnapshot))}</span></p>${p.LastError?`<p class="note error">${esc(p.LastError)}</p>`:''}` : '<p>No publisher evidence reported.</p>'));
  rows('deployments-body', list(snapshot.view.Nodes), n => n.ID, n => [link('/devices/' + encodeURIComponent(n.ID), n.Name || n.ID), esc(short(n.Applied)), `${esc(short(n.Version?.Commit))}${n.Version?.Dirty?' · modified':''}`, `${badge(n.Rollout?.Stage||'not reported')}<small>${esc(n.Rollout?.Error)}</small>`, time(n.ObservedAt)]);
}

function updatePage() {
  const path = location.pathname;
  if (path === '/devices' && !query().has('new')) deviceRows();
  else if (path.startsWith('/devices/') && !path.startsWith('/devices/invites/')) updateDetail(decodeURIComponent(path.slice(9)));
  else if (path === '/') updateOverview();
  else if (path === '/topology') updateTopology();
  else if (path === '/routing') updateRouting();
  else if (path === '/services') updateServices();
  else if (path === '/deployments' || path === '/releases' && query().get('tab') === 'deployments') updateDeployments();
}
async function render() {
  const epoch = ++routeEpoch,
    path = location.pathname;
  app.className = path === '/' ? 'network-page page-overview' : path === '/topology' ? 'network-page page-topology' : '';
  for (const a of document.querySelectorAll('nav a')) {
    const active = a.pathname === path || a.pathname === '/releases' && path === '/deployments' || a.pathname === '/devices' && path.startsWith('/devices/');
    if (active) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  try {
    if (!caps.admin && path !== '/') {
      app.innerHTML = heading('Administrator certificate required', 'Import admin.p12 and reconnect to manage devices, services and releases.');
      return;
    }
    if (path === '/') overviewPage();
    else if (path === '/devices' || path === '/clients' || path === '/nodes') {
      if (query().get('new') === '1' && caps.create) await enrollmentPage(epoch);
      else devicesPage();
    } else if (path.startsWith('/devices/invites/')) await invitePage(decodeURIComponent(path.slice('/devices/invites/'.length)), epoch);
    else if (path.startsWith('/devices/') || path.startsWith('/nodes/')) detailPage(decodeURIComponent(path.split('/')[2]));
    else if (path === '/topology') topologyPage();
    else if (path === '/routing') routingPage();
    else if (path === '/services') await servicesPage(epoch);
    else if (path === '/ssot' || path === '/settings') await ssotPage(epoch);
    else if (path === '/events') await eventsPage(epoch);
    else if (path === '/releases' || path === '/deployments') await releasesPage(epoch);
    else app.innerHTML = heading('Page not found', '');
  } catch (e) {
    if (epoch === routeEpoch) app.innerHTML = heading('Unable to load this page', e.message) + '<button id="retry-page">Retry</button>';
    const retry = document.querySelector('#retry-page');
    if (retry) retry.onclick = render;
  }
}
bindDeviceActions();
for (const item of document.querySelectorAll('header nav a')) {
  const name = item.pathname === '/' ? 'overview' : item.pathname.slice(1);
  item.insertAdjacentHTML('afterbegin', icon(name));
}
try {
  const boot = await api('/api/control/ui');
  caps = boot.capabilities;
  for (const link of document.querySelectorAll('nav a')) link.hidden = !caps.admin && link.pathname !== '/';
  snapshot = boot.snapshot;
  accept(snapshot);
  await render();
  live();
  document.documentElement.dataset.ready = 'true';
} catch (e) {
  app.innerHTML = heading('Connection unavailable', e.message);
  connection.textContent = 'Disconnected';
}

function updateHistory(elementID, nodeID = '') {
  const history = snapshot.traffic?.history,
    element = document.getElementById(elementID);
  if (!element) return;
  if (!history) {
    setHTML(element, `<h2>Retained WireGuard traffic</h2><p class="muted">${esc(snapshot.traffic?.history_status||'not supported')}</p>`);
    return;
  }
  const points = historyPoints(history, nodeID),
    known = points.filter(p => p.present),
    total = known.reduce((sum, p) => sum + p.rx + p.tx, 0n),
    max = known.reduce((m, p) => p.rx + p.tx > m ? p.rx + p.tx : m, 1n);
  const width = 900,
    height = 120,
    step = width / Math.max(points.length, 1);
  const bars = points.map((p, i) => !p.present ? '' : nodeID ? [
    ['rx', '#88b99e'],
    ['tx', '#7498b5']
  ].map(([direction, color], side) => `<rect x="${i*step+1+side*step/2}" y="${height-Number(p[direction]*100n/max)}" width="${Math.max(step/2-2,1)}" height="${Math.max(Number(p[direction]*100n/max),1)}" fill="${color}"><title>${esc(p.start)} · ${direction.toUpperCase()} ${bytes(p[direction])}</title></rect>`).join('') : `<rect x="${i*step+1}" y="${height-Number((p.rx+p.tx)*100n/max)}" width="${Math.max(step-2,1)}" height="${Math.max(Number((p.rx+p.tx)*100n/max),1)}" fill="#88b99e"><title>${esc(p.start)} · RX ${bytes(p.rx)} · TX ${bytes(p.tx)}</title></rect>`).join('');
  setHTML(element, `<h2>${nodeID?'Device':'Fleet'} forwarding · retained time buckets</h2><p><b>${bytes(total)}</b> · ${known.length} / ${points.length} sampled buckets</p>${known.length?`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="WireGuard traffic by sampled time bucket">${bars}</svg>`:'<p class="muted">No accepted traffic deltas in this window.</p>'}<small>${time(history.window_start)} — ${time(history.window_end)} · bucket ${esc(history.bucket_width)}</small><p class="muted">${nodeID?'RX and TX on this device’s WireGuard interfaces.':'Fleet totals sum node-interface RX + TX across hops; they are not unique application payload volume.'} Missing buckets remain unknown; rejected resets and gaps contribute no bytes.</p><details class="details"><summary>Bucket evidence</summary><div class="table-wrap"><table><thead><tr><th>Time</th><th>RX</th><th>TX</th><th>Resets / gaps</th></tr></thead><tbody>${points.map(p=>`<tr><td>${time(p.start)}</td><td>${p.present?bytes(p.rx):'Unknown'}</td><td>${p.present?bytes(p.tx):'Unknown'}</td><td>${p.resets} / ${p.gaps}<small>Window flags ${p.bucketResets} / ${p.bucketGaps}</small></td></tr>`).join('')}</tbody></table></div></details>`);
}
