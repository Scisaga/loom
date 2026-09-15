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
  app.innerHTML = heading('Overview', 'Current network and trusted evidence, updated in place.') + '<div id="overview-stats" class="stats"></div><div class="grid"><section class="card"><h2>Current network</h2>' + table(['Device', 'Health', 'Last observation'], 'overview-nodes') + '</section><section class="card"><h2>Current paths</h2>' + table(['Entry / service', 'Selected path', 'Observation'], 'overview-routes') + '</section></div><div id="overview-warnings"></div><section class="card" id="fleet-history"></section>';
  updateOverview();
}

function updateOverview() {
  updateHistory('fleet-history');
  const v = currentNetwork(snapshot.view),
    devices = list(snapshot.inventory.devices).filter(d => d.status !== 'revoked');
  setHTML(document.querySelector('#overview-stats'), [
    ['Devices', devices.length || v.Nodes.length],
    ['Online', caps.admin ? devices.filter(d => d.presence_status === 'live').length : '—'],
    ['Runtime problems', devices.filter(d => d.data_plane_status === 'problem').length],
    ['Observed paths', v.Routes.length]
  ].map(([label, value]) => `<div class="stat"><span class="muted">${label}</span><strong>${value}</strong></div>`).join(''));
  rows('overview-nodes', v.Nodes, n => n.ID, n => [link('/devices/' + encodeURIComponent(n.ID), n.Name || n.ID), badge(n.Health), time(n.ObservedAt)]);
  rows('overview-routes', v.Routes, r => r.Node + '|' + r.Selector, r => [`${esc(r.Node)}<small>${esc(r.ScopeID||r.Declaration)}</small>`, esc(list(r.Chain).join(' → ') || r.Candidate), r.Stale ? badge('stale') : time(r.ObservedAt)]);
  setHTML(document.querySelector('#overview-warnings'), list(snapshot.view.Warnings).map(w => `<p class="note">${esc(w)}</p>`).join(''));
}

function topologyPage() {
  app.innerHTML = heading('Topology', 'Declared links form the layout; current paths are read-only overlays.') + '<div class="filters"><label>Highlight entry <select id="topology-entry"><option value="">All entries</option></select></label></div><div id="topology"></div>' + table(['From → to', 'Transport / state', 'Observed latency', 'Traffic / evidence'], 'links-body') + '<section class="card"><h2>Retained WireGuard link traffic · sender TX only</h2><p class="muted">Sum of endpoint TX deltas; receiver RX is not added again.</p>' + table(['Link', 'Accepted TX', 'Sampled buckets', 'Resets / gaps'], 'link-history-body') + '</section>';
  const select = document.querySelector('#topology-entry');
  for (const n of currentNetwork(snapshot.view).Nodes) {
    const o = new Option(n.Name || n.ID, n.ID);
    select.add(o);
  }
  select.value = query().get('entry') || '';
  select.onchange = () => {
    const q = query();
    if (select.value) q.set('entry', select.value);
    else q.delete('entry');
    history.replaceState({}, '', '/topology?' + q);
    updateTopology();
  };
  updateTopology();
}

function updateTopology() {
  rows('link-history-body', linkHistory(snapshot.traffic?.history), l => l.key, l => [`${esc(l.from)} ↔ ${esc(l.to)}`, l.buckets ? bytes(l.tx) : 'No accepted delta', String(l.buckets), `${l.resets} / ${l.gaps}`]);
  const v = currentNetwork(snapshot.view),
    positions = topologyPositions(v.Nodes.map(n => ({
      ...n,
      Responsibilities: list(snapshot.inventory.devices).find(d => d.id === n.ID)?.responsibilities
    }))),
    entry = document.querySelector('#topology-entry')?.value;
  const edge = (from, to, cls) => {
    const a = positions.get(from),
      b = positions.get(to);
    return a && b ? `<path class="${cls}" d="M ${a.x} ${a.y} Q 550 300 ${b.x} ${b.y}"/>` : '';
  };
  const svg = `<svg class="topology" viewBox="0 0 1100 600" role="img" aria-label="Current network topology"><ellipse class="ring" cx="550" cy="300" rx="410" ry="220"/><ellipse class="ring" cx="550" cy="300" rx="225" ry="130"/>${v.Links.map(l=>edge(l.From,l.To,'edge '+(l.Kind==='candidate'?'candidate ':'' )+(l.State==='active'?'active':''))).join('')}${v.Routes.filter(r=>!entry||r.Node===entry).flatMap(r=>{const chain=[r.Node,...list(r.Chain).filter((x,i)=>i||x!==r.Node)];return chain.slice(1).map((to,i)=>edge(chain[i],to,'route'));}).join('')}${v.Nodes.map(n=>{const p=positions.get(n.ID);return `<a href="/devices/${encodeURIComponent(n.ID)}" data-nav><circle class="node" cx="${p.x}" cy="${p.y}" r="12"/><text x="${p.x}" y="${p.y+29}">${esc(n.Name||n.ID)}</text><text class="metric" x="${p.x}" y="${p.y+44}">${esc(n.Health||'unknown')}</text></a>`;}).join('')}</svg>`;
  setHTML(document.querySelector('#topology'), svg);
  rows('links-body', v.Links, l => l.From + '|' + l.To + '|' + l.Kind, l => [`${esc(l.From)} → ${esc(l.To)}`, `${esc(l.Kind)} · ${badge(l.State)}`, l.Samples > 0 ? `${l.MS} ms · ${l.Samples} samples` : 'Not measured', `${l.RateSamples>0&&l.RateWindowSeconds>0?bytes(BigInt(Math.round(l.RecentTXBytes/l.RateWindowSeconds)))+'/s · WG':'No rate'}<small>${time(l.ObservedAt)} · ${esc(l.Source)}</small>`]);
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
  return `<article class="card package"><div class="bar"><h3>${esc(p.title||p.filename)}</h3>${tag(p.arch)}</div><p class="muted">${esc(p.variant)} · ${esc(p.version)}</p><div class="artifact-source">Source <span class="mono">${esc(short(p.source_commit))}</span> · ${bytes(p.size)}</div><small>${esc(p.signing||'Platform signature verified')}</small><details class="details"><summary>Checksum and release evidence</summary><p class="digest mono">SHA-256 ${esc(p.sha256)}</p>${list(p.mirrors).map(m=>`<small>${esc(m)}</small>`).join('')}</details><div class="actions"><a class="button primary" href="${esc(p.url)}" download>Download</a>${p.checksum_url?`<a class="button" href="${esc(p.checksum_url)}" download>SHA-256</a>`:''}${p.signature_url?`<a class="button" href="${esc(p.signature_url)}" download>Signature</a>`:''}${p.sbom_url?`<a class="button" href="${esc(p.sbom_url)}" download>SBOM</a>`:''}</div></article>`;
}
async function releasesPage(epoch) {
  const deployment = query().get('tab') === 'deployments' || location.pathname === '/deployments';
  app.innerHTML = heading('Releases', 'Verified client packages and deployment evidence.') + `<div class="tabs"><a href="/releases" data-nav class="${!deployment?'active':''}">Client packages</a><a href="/releases?tab=deployments" data-nav class="${deployment?'active':''}">Deployments</a></div><div id="release-content"></div>`;
  if (deployment) {
    document.querySelector('#release-content').innerHTML = '<section class="card" id="publisher"></section>' + table(['Device', 'Applied configuration', 'Running version', 'Rollout', 'Last report'], 'deployments-body');
    updateDeployments();
    return;
  }
  const catalog = await getPackages();
  if (epoch !== routeEpoch) return;
  const stable = list(catalog.artifacts).filter(p => p.variant !== 'debug'),
    debug = list(catalog.artifacts).filter(p => p.variant === 'debug');
  setHTML(document.querySelector('#release-content'), (catalog.error ? `<p class="note">${esc(catalog.error)}</p>` : '') + (catalog.publication?.mirrors ? `<p class="muted">${catalog.publication.mirrors} distribution locations verified at publication · ${time(catalog.publication.verified_at)}</p>` : '') + ['linux-server', 'android', 'windows-desktop'].map(platform => `<section><h2>${platform==='linux-server'?'Linux':platform==='android'?'Android':'Windows'}</h2><div class="grid">${stable.filter(p=>p.platform===platform).map(packageCard).join('')||'<p class="muted">No verified package published.</p>'}</div></section>`).join('') + (debug.length ? `<details class="details"><summary>Developer packages</summary><div class="grid">${debug.map(packageCard).join('')}</div></details>` : ''));
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
