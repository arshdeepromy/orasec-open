/*
 * Ora — the OraSec assistant (web). Vanilla JS, no build step.
 * Character and chat behaviour of the Ora assistant:
 *   the orb (exact port of OraOrb.tsx), a floating draggable chat window, history, short notes,
 *   👍/👎, first-run notice, Ctrl/⌘ + /, minimise pill, "Take me there" + spotlight,
 *   guided walkthroughs, and proposal cards that change nothing until Confirm.
 * The panel's state (open / minimised / chat) survives page loads, so "Take me there" keeps the chat.
 */
(function () {
  'use strict';
  if (window.__oraLoaded) return;
  window.__oraLoaded = true;
  var BOOT = window.ORA_BOOT || {};
  var API = BOOT.api || '/orasec/ora/api/';
  var SS = window.sessionStorage;

  /* ───────────────────────── Orb (port of OraOrb.tsx) ───────────────────────── */
  var ORB_SHAPES = {
    circle: [60, 22, 81, 22, 98, 39, 98, 60, 98, 81, 81, 98, 60, 98, 39, 98, 22, 81, 22, 60, 22, 39, 39, 22, 60, 22],
    squircle: [60, 24, 90, 24, 96, 30, 96, 60, 96, 90, 90, 96, 60, 96, 30, 96, 24, 90, 24, 60, 24, 30, 30, 24, 60, 24],
    star: [60, 16, 68, 42, 78, 52, 104, 60, 78, 68, 68, 78, 60, 104, 52, 78, 42, 68, 16, 60, 42, 52, 52, 42, 60, 16],
    blob: [62, 20, 88, 24, 100, 42, 96, 62, 92, 86, 74, 100, 56, 96, 34, 92, 20, 78, 24, 56, 28, 36, 40, 18, 62, 20],
    tri: [60, 20, 74, 20, 90, 52, 99, 76, 104, 90, 96, 96, 60, 96, 24, 96, 16, 90, 21, 76, 30, 52, 46, 20, 60, 20],
    pill: [60, 30, 90, 30, 104, 42, 104, 60, 104, 78, 90, 90, 60, 90, 30, 90, 16, 78, 16, 60, 16, 42, 30, 30, 60, 30]
  };
  var WORK_CYCLE = ['squircle', 'star', 'blob', 'tri', 'pill', 'circle'];
  var MORPH_MS = 620, BLINK_EVERY_MS = 5200, BLINK_MS = 150;
  var RING_SPEED = { idle: 0.05, listening: 0.08, working: 0.42, happy: 0.12, sorry: 0.02, sleeping: 0.01 };
  var SPARK_SPEED = { idle: 0.09, listening: 0.12, working: 0.3, happy: 0.2, sorry: 0.04, sleeping: 0 };
  var GOLD = '#D4AF37', SPARK = '#F5D76E', EYE = '#F5C542', EYE_STROKE = '#B8901F';
  var NS = 'http://www.w3.org/2000/svg';
  var orbSeq = 0;

  function easeInOutCubic(t) { var x = Math.min(1, Math.max(0, t)); return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2; }
  function lerpShape(a, b, t) { var o = new Array(26); for (var i = 0; i < 26; i++) o[i] = a[i] + (b[i] - a[i]) * t; return o; }
  function shapeToPath(n) {
    function f(v) { return (Math.round(v * 100) / 100).toString(); }
    var d = 'M' + f(n[0]) + ' ' + f(n[1]);
    for (var s = 0; s < 4; s++) { var o = 2 + s * 6; d += ' C' + f(n[o]) + ' ' + f(n[o + 1]) + ' ' + f(n[o + 2]) + ' ' + f(n[o + 3]) + ' ' + f(n[o + 4]) + ' ' + f(n[o + 5]); }
    return d + ' Z';
  }
  function workingShapeAt(elapsed) {
    var step = Math.floor(Math.max(0, elapsed) / MORPH_MS);
    var from = WORK_CYCLE[(step + WORK_CYCLE.length - 1) % WORK_CYCLE.length];
    var to = WORK_CYCLE[step % WORK_CYCLE.length];
    return lerpShape(ORB_SHAPES[from], ORB_SHAPES[to], easeInOutCubic((Math.max(0, elapsed) % MORPH_MS) / MORPH_MS));
  }
  function eyeBase(m) {
    if (m === 'listening') return { dx: -1, dy: 2.5, ry: 6.6 };
    if (m === 'working') return { dx: 0, dy: 0, ry: 4.2 };
    if (m === 'sorry') return { dx: 0, dy: 3, ry: 5 };
    return { dx: 0, dy: 0, ry: 6.6 };
  }
  function reducedMotion() { try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } }
  function el(tag, attrs) { var e = document.createElementNS(NS, tag); for (var k in attrs) e.setAttribute(k, attrs[k]); return e; }

  function Orb(size, mood, label) {
    var self = this, uid = 'ora-orb' + (++orbSeq), clipId = uid + '-clip';
    self.mood = mood || 'idle';
    self.reduced = reducedMotion();
    var circle = shapeToPath(ORB_SHAPES.circle);
    var svg = el('svg', { viewBox: '0 0 120 120', width: size, height: size, focusable: 'false' });
    if (label) { svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', label); } else svg.setAttribute('aria-hidden', 'true');
    var defs = el('defs', {}), cp = el('clipPath', { id: clipId, clipPathUnits: 'userSpaceOnUse' });
    self.clip = el('path', { d: circle }); cp.appendChild(self.clip); defs.appendChild(cp); svg.appendChild(defs);
    self.baseRing = el('circle', { cx: 60, cy: 60, r: 49, fill: 'none', stroke: GOLD, 'stroke-width': 3, opacity: 0.35 });
    svg.appendChild(self.baseRing);
    self.ringG = el('g', {});
    self.ring = el('circle', { cx: 60, cy: 60, r: 49, fill: 'none', stroke: GOLD, 'stroke-width': 3, 'stroke-linecap': 'round', 'stroke-dasharray': '230 78' });
    self.ringG.appendChild(self.ring); svg.appendChild(self.ringG);
    self.sparkG = el('g', {}); self.sparkG.appendChild(el('circle', { cx: 60, cy: 11, r: 2.6, fill: SPARK })); svg.appendChild(self.sparkG);
    self.body = el('g', {});
    self.bodyPath = el('path', { d: circle, fill: '#00705F' });
    var hl = el('g', { 'clip-path': 'url(#' + clipId + ')' });
    hl.appendChild(el('circle', { cx: 54, cy: 50, r: 31, fill: '#00B39F' }));
    hl.appendChild(el('circle', { cx: 47, cy: 42, r: 8, fill: '#3ED6BC', opacity: 0.6 }));
    self.eyes = el('g', {});
    self.body.appendChild(self.bodyPath); self.body.appendChild(hl); self.body.appendChild(self.eyes);
    svg.appendChild(self.body);
    self.svg = svg;
    self.setMood(self.mood, true);
    if (!self.reduced && window.requestAnimationFrame) self.start();
  }
  Orb.prototype.drawEyes = function () {
    var m = this.mood, g = this.eyes, b = eyeBase(m);
    while (g.firstChild) g.removeChild(g.firstChild);
    this.eyeL = this.eyeR = null;
    if (m === 'happy') {
      g.appendChild(el('path', { d: 'M45 64 Q50 55 55 64', fill: 'none', stroke: EYE, 'stroke-width': 3.6, 'stroke-linecap': 'round' }));
      g.appendChild(el('path', { d: 'M65 64 Q70 55 75 64', fill: 'none', stroke: EYE, 'stroke-width': 3.6, 'stroke-linecap': 'round' }));
    } else if (m === 'sleeping') {
      g.appendChild(el('path', { d: 'M45.5 63 Q50 66 54.5 63', fill: 'none', stroke: EYE, 'stroke-width': 2, 'stroke-linecap': 'round' }));
      g.appendChild(el('path', { d: 'M65.5 63 Q70 66 74.5 63', fill: 'none', stroke: EYE, 'stroke-width': 2, 'stroke-linecap': 'round' }));
    } else {
      this.eyeL = el('ellipse', { cx: 50, cy: 62, rx: 4.6, ry: b.ry, fill: EYE, stroke: EYE_STROKE, 'stroke-width': 0.8 });
      this.eyeR = el('ellipse', { cx: 70, cy: 62, rx: 4.6, ry: b.ry, fill: EYE, stroke: EYE_STROKE, 'stroke-width': 0.8 });
      g.appendChild(this.eyeL); g.appendChild(this.eyeR);
    }
    g.setAttribute('transform', 'translate(' + b.dx + ' ' + b.dy + ')');
  };
  Orb.prototype.setMood = function (m, force) {
    if (!force && m === this.mood) return;
    this.mood = m;
    var sleeping = m === 'sleeping';
    this.svg.setAttribute('data-mood', m);
    this.baseRing.setAttribute('opacity', sleeping ? 0.15 : 0.35);
    this.ringG.setAttribute('opacity', sleeping ? 0.35 : 1);
    this.ring.setAttribute('stroke-dasharray', m === 'working' ? '16 10' : '230 78');
    this.sparkG.style.display = sleeping ? 'none' : '';
    this.drawEyes();
    if (this.reduced) {
      var d = shapeToPath(m === 'working' ? ORB_SHAPES.squircle : ORB_SHAPES.circle);
      this.bodyPath.setAttribute('d', d); this.clip.setAttribute('d', d);
      this.body.setAttribute('transform', m === 'sorry' ? 'rotate(-12 60 60)' : '');
    }
  };
  Orb.prototype.start = function () {
    var self = this, last = 0, start = performance.now(), ring = 0, spark = 0, tilt = 0, workingSince = -1;
    var shape = ORB_SHAPES.circle.slice();
    function frame(now) {
      if (!self.svg.isConnected) { self.raf = 0; return; }
      var m = self.mood, dt = last ? Math.min(64, now - last) : 16; last = now;
      var t = now - start;
      ring = (ring + RING_SPEED[m] * dt) % 360; spark = (spark + SPARK_SPEED[m] * dt) % 360;
      if (m === 'working') { if (workingSince < 0) workingSince = now; shape = workingShapeAt(now - workingSince); }
      else { workingSince = -1; shape = lerpShape(shape, ORB_SHAPES.circle, 1 - Math.pow(0.82, dt / 16)); }
      var d = shapeToPath(shape);
      self.bodyPath.setAttribute('d', d); self.clip.setAttribute('d', d);
      tilt += ((m === 'sorry' ? -12 : 0) - tilt) * Math.min(1, dt / 140);
      var scale = 1, dy = 0;
      if (m === 'happy') { var bb = Math.abs(Math.sin(t / 170)); dy = -5 * bb; scale = 1 + 0.03 * bb; }
      else if (m === 'sleeping') { scale = 1 + 0.018 * Math.sin(t / 900); dy = -1.2 * Math.sin(t / 900); }
      else if (m !== 'working') { scale = 1 + 0.025 * Math.sin(t / 520); dy = -2 * Math.sin(t / 520); }
      self.body.setAttribute('transform', 'translate(0 ' + dy.toFixed(2) + ') rotate(' + tilt.toFixed(2) + ' 60 60) translate(60 60) scale(' + scale.toFixed(4) + ') translate(-60 -60)');
      self.ringG.setAttribute('transform', 'rotate(' + ring.toFixed(2) + ' 60 60)');
      self.sparkG.setAttribute('transform', 'rotate(' + spark.toFixed(2) + ' 60 60)');
      var b = eyeBase(m), ry = b.ry, dx = b.dx;
      if ((m === 'idle' || m === 'listening' || m === 'sorry') && t % BLINK_EVERY_MS < BLINK_MS) ry = 0.6;
      if (m === 'working') dx = 3 * Math.sin(t / 190);
      self.eyes.setAttribute('transform', 'translate(' + dx.toFixed(2) + ' ' + b.dy + ')');
      if (self.eyeL) { self.eyeL.setAttribute('ry', ry.toFixed(2)); self.eyeR.setAttribute('ry', ry.toFixed(2)); }
      self.raf = window.requestAnimationFrame(frame);
    }
    self.raf = window.requestAnimationFrame(frame);
  };
  window.OraOrb = Orb;

  /* ───────────────────────── helpers ───────────────────────── */
  function h(tag, props, kids) {
    var e = document.createElement(tag);
    if (props) for (var k in props) {
      var v = props[k];
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k === 'html') e.innerHTML = v;
      else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? '' : v);
    }
    (kids || []).forEach(function (c) { if (c != null && c !== false) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return e;
  }
  var ICON = {
    close: '<path d="M18 6 6 18M6 6l12 12"/>', min: '<path d="M5 12h14"/>', plus: '<path d="M12 5v14M5 12h14"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', note: '<path d="M4 5h16v11H8l-4 4z"/><path d="M8 9h8M8 12h5"/>',
    back: '<path d="M15 18l-6-6 6-6"/>', send: '<path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4z"/>',
    go: '<path d="M5 12h14M13 6l6 6-6 6"/>', map: '<path d="M9 4 3 6v14l6-2 6 2 6-2V4l-6 2z"/><path d="M9 4v14M15 6v14"/>',
    shield: '<path d="M12 3 4 6v6c0 5 3.5 8.5 8 9 4.5-.5 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>', trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    warn: '<path d="M12 3 2 21h20z"/><path d="M12 10v5M12 18h.01"/>'
  };
  function icon(name) {
    var s = document.createElementNS(NS, 'svg');
    s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('fill', 'none'); s.setAttribute('stroke', 'currentColor');
    s.setAttribute('stroke-width', '2'); s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round'); s.setAttribute('aria-hidden', 'true');
    s.innerHTML = ICON[name]; return s;
  }
  function ib(name, label, fn) { var b = h('button', { type: 'button', class: 'ora-ib', 'aria-label': label, title: label, onclick: fn }); b.appendChild(icon(name)); return b; }
  function sget(k, d) { try { var v = SS.getItem(k); return v ? JSON.parse(v) : d; } catch (e) { return d; } }
  function sset(k, v) { try { if (v == null) SS.removeItem(k); else SS.setItem(k, JSON.stringify(v)); } catch (e) { /* private mode */ } }
  function ago(iso) {
    var d = new Date(iso), s = (Date.now() - d) / 1000;
    if (s < 60) return 'just now'; if (s < 3600) return Math.floor(s / 60) + ' min ago'; if (s < 86400) return Math.floor(s / 3600) + ' h ago';
    return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
  }
  function samePath(p) { return (p || '').split('?')[0].split('#')[0] === location.pathname; }
  function pageCtx() {
    var h1 = document.querySelector('main h1, #base-content h1, .osp h1, h1');
    return { path: location.pathname, title: (h1 && h1.textContent.trim()) || document.title.replace(/\s*\|\s*OraSec.*$/, '') };
  }

  function api(path, opts) {
    opts = opts || {};
    var init = { method: opts.method || 'GET', credentials: 'same-origin', headers: { 'Accept': 'application/json' } };
    if (opts.body !== undefined) { init.method = opts.method || 'POST'; init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(opts.body); }
    if (init.method !== 'GET') init.headers['X-CSRFToken'] = BOOT.csrf || '';
    return fetch(API + path, init).then(function (r) {
      var ct = r.headers.get('content-type') || '';
      if (ct.indexOf('application/json') < 0) return { ok: false, status: r.status === 200 ? 401 : r.status, data: { detail: 'Your session has ended. Sign in again.', mood: 'sleeping' } };
      return r.json().then(function (d) { return { ok: r.ok, status: r.status, data: d }; });
    }).catch(function () { return { ok: false, status: 0, data: { detail: 'Can’t reach OraSec right now. Check your connection.', mood: 'sorry' } }; });
  }

  /* ───────────────────────── state ───────────────────────── */
  var S = {
    status: null, open: false, min: false, view: 'chat', cid: null, title: '', msgs: [], busy: false, err: null,
    mood: 'idle', moodTimer: 0, pos: sget('ora.pos', null)
  };
  function save() { sset('ora.state', { open: S.open, min: S.min, cid: S.cid, view: S.view }); }
  var root, launch, launchOrb, panel, headOrb, body, input, sendBtn, subtitle, mini, miniOrb;

  function setMood(m, holdMs) {
    clearTimeout(S.moodTimer);
    S.mood = m;
    [launchOrb, headOrb, miniOrb].forEach(function (o) { if (o) o.setMood(m); });
    if (holdMs) S.moodTimer = setTimeout(function () { setMood(S.status && !S.status.available ? 'sleeping' : 'idle'); }, holdMs);
  }

  /* ───────────────────────── launcher ───────────────────────── */
  function buildLauncher() {
    launch = h('button', { type: 'button', class: 'ora-launch', 'aria-label': 'Ask Ora, your OraSec assistant', onclick: function () { openPanel(); } });
    launchOrb = new Orb(56, S.mood);
    launch.appendChild(launchOrb.svg);
    var tip = h('span', { class: 'ora-tip' }, ['Ask Ora ']);
    tip.appendChild(h('kbd', { text: (navigator.platform || '').indexOf('Mac') >= 0 ? '⌘ /' : 'Ctrl /' }));
    launch.appendChild(tip);
    root.appendChild(launch);
  }

  /* ───────────────────────── panel ───────────────────────── */
  function openPanel(focus) {
    S.open = true; S.min = false; save(); render();
    if (focus !== false) setTimeout(function () { input && input.focus(); }, 30);
  }
  function closePanel() { S.open = false; S.min = false; save(); render(); launch && launch.focus(); }
  function minimise() { S.open = true; S.min = true; save(); render(); }
  function newChat() { S.cid = null; S.msgs = []; S.title = ''; S.view = 'chat'; S.err = null; save(); render(); input && input.focus(); }

  function render() {
    if (panel) { panel.remove(); panel = null; headOrb = null; }
    if (mini) { mini.remove(); mini = null; miniOrb = null; }
    if (!(S.open && S.min)) S.miniShown = false;
    launch.style.display = (S.open || (S.status && S.status.hidden)) ? 'none' : '';
    if (!S.open) { S.shown = false; return; }
    if (S.min) { S.shown = false; return renderMini(); }
    var anim = !S.shown; S.shown = true;
    panel = h('div', { class: 'ora-panel' + (anim ? ' in' : ''), role: 'dialog', 'aria-label': 'Ora assistant', tabindex: '-1', 'data-ora-panel': '' });
    if (S.pos && window.innerWidth >= 640) { panel.style.left = S.pos.x + 'px'; panel.style.top = S.pos.y + 'px'; panel.style.right = 'auto'; panel.style.bottom = 'auto'; }
    var head = h('div', { class: 'ora-head' });
    if (S.view !== 'chat') head.appendChild(ib('back', 'Back to the chat', function () { S.view = 'chat'; save(); render(); }));
    headOrb = new Orb(36, S.mood, 'Ora');
    head.appendChild(headOrb.svg);
    subtitle = h('p', { 'aria-live': 'polite', text: S.busy ? 'Thinking…' : (S.view === 'history' ? 'Your recent chats' : S.view === 'notes' ? 'What I remember' : 'Your OraSec assistant') });
    head.appendChild(h('div', { class: 't' }, [h('h2', { text: S.view === 'history' ? 'Chats' : S.view === 'notes' ? 'Notes' : 'Ora' }), subtitle]));
    head.appendChild(ib('plus', 'New chat', newChat));
    if (S.view === 'chat') head.appendChild(ib('clock', 'Chat history', function () { S.view = 'history'; save(); render(); }));
    head.appendChild(ib('min', 'Minimise', minimise));
    head.appendChild(ib('close', 'Close Ora', closePanel));
    makeDraggable(head);
    panel.appendChild(head);
    body = h('div', { class: 'ora-body' });
    panel.appendChild(body);
    if (S.view === 'history') renderHistory();
    else if (S.view === 'notes') renderNotes();
    else { renderChat(); panel.appendChild(renderComposer()); }
    panel.addEventListener('keydown', function (e) { if (e.key === 'Escape') { e.stopPropagation(); minimise(); } });
    root.appendChild(panel);
    if (S.view === 'chat') body.scrollTop = body.scrollHeight;
  }

  function makeDraggable(handle) {
    var sx, sy, ox, oy, on = false;
    handle.addEventListener('pointerdown', function (e) {
      if (window.innerWidth < 640 || e.target.closest('button')) return;
      var r = panel.getBoundingClientRect(); on = true; sx = e.clientX; sy = e.clientY; ox = r.left; oy = r.top;
      handle.classList.add('drag'); handle.setPointerCapture(e.pointerId);
    });
    handle.addEventListener('pointermove', function (e) {
      if (!on) return;
      var x = Math.max(8, Math.min(window.innerWidth - panel.offsetWidth - 8, ox + e.clientX - sx));
      var y = Math.max(8, Math.min(window.innerHeight - 80, oy + e.clientY - sy));
      panel.style.left = x + 'px'; panel.style.top = y + 'px'; panel.style.right = 'auto'; panel.style.bottom = 'auto';
      S.pos = { x: x, y: y };
    });
    handle.addEventListener('pointerup', function () { if (on) { on = false; handle.classList.remove('drag'); sset('ora.pos', S.pos); } });
    handle.addEventListener('dblclick', function () { S.pos = null; sset('ora.pos', null); render(); });
  }

  function renderMini() {
    var last = S.msgs.length ? S.msgs[S.msgs.length - 1] : null;
    var manim = !S.miniShown; S.miniShown = true;
    mini = h('button', { type: 'button', class: 'ora-mini' + (manim ? ' in' : ''), 'aria-label': 'Open Ora', onclick: function () { openPanel(); } });
    miniOrb = new Orb(36, S.mood);
    mini.appendChild(miniOrb.svg);
    mini.appendChild(h('span', { class: 't' }, [h('b', { text: S.busy ? 'Ora is thinking…' : 'Ora' }), h('span', { text: last ? last.text : 'Ask me anything about OraSec' })]));
    root.appendChild(mini);
  }

  /* ── chat view ── */
  var STARTERS = ['What should we fix first?', 'How is our security posture?', 'Which known-exploited vulnerabilities affect us?', 'Where do I add a risk?'];

  function renderChat() {
    var st = S.status || {};
    if (st.available === false) {
      body.appendChild(h('div', { class: 'ora-err' }, [st.configured ? 'Ora is resting right now. Please try again a bit later.' : 'Ora isn’t set up yet. A superuser can connect it in Ora settings.']));
      if (st.superuser) body.appendChild(h('div', { class: 'ora-acts' }, [goBtn({ type: 'navigate', path: '/orasec/ora/settings/', label: 'Ora settings' })]));
      return;
    }
    if (!st.notice_ack) {
      body.appendChild(h('div', { class: 'ora-note', 'data-testid': 'ora-first-run' }, [
        h('div', { text: st.notice || '' }),
        st.memory_notice ? h('div', { text: st.memory_notice, style: 'margin-top:6px;color:var(--ora-muted);font-size:12.5px' }) : null,
        h('div', { class: 'ft' }, [h('button', { type: 'button', class: 'ora-btn p', text: 'Got it', onclick: function () {
          st.notice_ack = true; render(); api('preference/', { body: { notice_ack: true } });
        } })])
      ]));
    }
    if (!S.msgs.length) {
      var hello = h('div', { class: 'ora-hello' });
      var big = new Orb(84, S.mood === 'idle' ? 'happy' : S.mood); hello.appendChild(big.svg);
      if (S.mood === 'idle') setTimeout(function () { big.setMood('idle'); }, 1800);
      hello.appendChild(h('h3', { text: 'Kia ora' + (st.first_name ? ' ' + st.first_name : '') + '! I’m Ora.' }));
      hello.appendChild(h('p', { text: 'I can prioritise findings, evaluate risk, explain vulnerabilities, find your way around OraSec and prepare changes for you to confirm.' }));
      hello.appendChild(h('div', { class: 'ora-chips' }, STARTERS.map(function (q) { return h('button', { type: 'button', class: 'ora-chip', text: q, onclick: function () { send(q); } }); })));
      body.appendChild(hello);
    }
    S.msgs.forEach(function (m, i) { body.appendChild(renderMsg(m, i === S.msgs.length - 1)); });
    if (S.busy) {
      var ty = h('div', { class: 'ora-typing', role: 'status', 'aria-label': 'Ora is typing' });
      var to = new Orb(28, 'working'); ty.appendChild(to.svg);
      ty.appendChild(h('span', { class: 'dots' }, [h('i'), h('i'), h('i')]));
      body.appendChild(ty);
    }
    if (S.err) body.appendChild(h('div', { class: 'ora-err', role: 'alert', text: S.err }));
  }

  function renderMsg(m, isLast) {
    if (m.role === 'user') return h('div', { class: 'ora-u' }, [h('p', { text: m.text })]);
    var w = h('div', { class: 'ora-a' + (m.mood === 'sorry' ? ' sorry' : ''), 'data-testid': 'ora-answer' });
    w.appendChild(h('p', { class: 'txt', text: m.text }));
    if (m.steps && m.steps.length) w.appendChild(h('ol', { class: 'ora-steps' }, m.steps.map(function (s) { return h('li', { text: s }); })));
    if (m.items && m.items.length) w.appendChild(h('div', { class: 'ora-items' }, m.items.map(renderItem)));
    if (m.proposal) w.appendChild(renderCard(m.proposal, m));
    var acts = (m.actions || []).filter(function (a) { return a.type === 'navigate' || a.type === 'guide'; });
    if (acts.length) w.appendChild(h('div', { class: 'ora-acts' }, acts.map(goBtn)));
    if (isLast && m.quick_replies && m.quick_replies.length)
      w.appendChild(h('div', { class: 'ora-chips', role: 'group', 'aria-label': 'Quick replies' }, m.quick_replies.map(function (q) {
        return h('button', { type: 'button', class: 'ora-chip qr', text: q.label, onclick: function () { send(q.text); } });
      })));
    if (isLast && m.suggestions && m.suggestions.length)
      w.appendChild(h('div', { class: 'ora-chips', 'aria-label': 'Suggestions' }, m.suggestions.map(function (q) {
        return h('button', { type: 'button', class: 'ora-chip', text: q, onclick: function () { send(q); } });
      })));
    if (m.id && m.tool !== 'proposal') w.appendChild(feedbackRow(m));
    return w;
  }

  function sevBadge(s) { return s ? h('span', { class: 'ora-b ' + String(s).replace(/\s+/g, ''), text: s }) : null; }
  function renderItem(it) {
    var meta = it.due ? (it.overdue ? 'overdue ' : 'due ') + it.due : (it.asset || '');
    var a = h('a', { class: 'ora-item', href: it.path || '#', onclick: function (e) {
      if (!it.path) { e.preventDefault(); return; }
      if (!samePath(it.path)) { minimise(); }
    } }, [
      h('div', { class: 'r1' }, [h('span', { class: 'ref', text: it.ref }), sevBadge(it.severity), it.band && it.band !== it.severity ? sevBadge(it.band) : null,
        it.kev ? h('span', { class: 'ora-b kev', text: 'KEV' }) : null, it.level ? h('span', { class: 'ora-b lvl', text: it.level }) : null,
        it.overdue ? h('span', { class: 'ora-b over', text: 'Overdue' }) : null, h('span', { class: 'meta', text: it.overdue ? '' : meta })]),
      it.title ? h('div', { class: 'ti', text: it.title }) : null,
      it.why ? h('div', { class: 'why', text: it.why }) : null
    ]);
    return a;
  }

  function goBtn(a) {
    if (a.type === 'guide') {
      var g = h('button', { type: 'button', class: 'ora-go guide', onclick: function () { Guide.start(a.id); } }, [icon('map'), 'Show me how']);
      g.title = a.label || 'Guided walkthrough'; return g;
    }
    var b = h('button', { type: 'button', class: 'ora-go', onclick: function () { takeMeThere(a); } }, [icon('go'), samePath(a.path) ? 'Show me' : 'Take me there']);
    b.title = (a.label || '') + (a.where ? ' — ' + a.where : '');
    return b;
  }

  function feedbackRow(m) {
    function vote(v) {
      return function () {
        var nv = m.feedback === v ? 0 : v; m.feedback = nv || null; render();
        api('messages/' + m.id + '/feedback/', { body: { value: nv } });
      };
    }
    return h('div', { class: 'ora-fb', role: 'group', 'aria-label': 'Was this helpful?' }, [
      h('button', { type: 'button', class: m.feedback === 1 ? 'on' : '', 'aria-label': 'Helpful', 'aria-pressed': m.feedback === 1 ? 'true' : 'false', text: '👍', onclick: vote(1) }),
      h('button', { type: 'button', class: m.feedback === -1 ? 'on dn' : '', 'aria-label': 'Not helpful', 'aria-pressed': m.feedback === -1 ? 'true' : 'false', text: '👎', onclick: vote(-1) })
    ]);
  }

  function renderCard(p, m) {
    var c = p.card || {}, danger = !!c.danger;
    var card = h('div', { class: 'ora-card' + (danger ? ' danger' : ''), 'data-testid': 'ora-proposal' });
    var hd = h('div', { class: 'hd' }); hd.appendChild(icon(danger ? 'warn' : 'shield')); hd.appendChild(document.createTextNode(c.title || 'Confirm')); card.appendChild(hd);
    if (c.lines && c.lines.length) {
      var dl = h('dl'); c.lines.forEach(function (l) { dl.appendChild(h('dt', { text: l.label })); dl.appendChild(h('dd', { text: l.value })); }); card.appendChild(dl);
    }
    if (c.items && c.items.length) card.appendChild(h('ul', {}, c.items.map(function (it) {
      return h('li', {}, [h('a', { href: it.path, text: it.ref }), sevBadge(it.severity), h('span', { class: 't', text: it.title })]);
    })));
    if (p.status === 'pending') {
      if (c.warning) card.appendChild(h('div', { class: 'warn', text: c.warning }));
      var cancel = h('button', { type: 'button', class: 'ora-btn', text: 'Cancel' });
      var ok = h('button', { type: 'button', class: 'ora-btn ' + (danger ? 'd' : 'p'), text: c.confirm || 'Confirm' });
      function decide(confirm) {
        ok.disabled = cancel.disabled = true; ok.textContent = confirm ? 'Working…' : ok.textContent;
        setMood('working');
        api('proposals/' + p.id + '/', { body: { confirm: confirm } }).then(function (r) {
          if (r.ok) { m.proposal = r.data; setMood(r.data.status === 'confirmed' ? 'happy' : 'idle', 3500); }
          else { m.proposal = Object.assign({}, p, { status: 'failed', result: { ok: false, message: r.data.detail } }); setMood('sorry', 3500); }
          render();
        });
      }
      cancel.onclick = function () { decide(false); }; ok.onclick = function () { decide(true); };
      card.appendChild(h('div', { class: 'ft' }, [cancel, ok]));
    } else {
      var res = p.result || {}, cls = p.status === 'confirmed' ? 'ok' : (p.status === 'cancelled' || p.status === 'expired') ? 'no' : 'bad';
      var txt = res.message || (p.status === 'expired' ? 'This card expired — nothing was changed.' : p.status);
      card.appendChild(h('div', { class: 'res ' + cls, role: 'status' }, [txt, res.path ? h('a', { href: res.path, text: 'Open →' }) : null]));
    }
    return card;
  }

  function renderComposer() {
    var foot = h('div', { class: 'ora-foot' });
    var form = h('form', { class: 'ora-comp', onsubmit: function (e) { e.preventDefault(); send(input.value); } });
    form.appendChild(h('label', { for: 'ora-input', class: 'ora-sr', text: 'Ask Ora' }));
    input = h('textarea', { id: 'ora-input', rows: '1', maxlength: '2000', placeholder: 'Ask about findings, risks, or where things are…', 'aria-label': 'Ask Ora' });
    input.value = sget('ora.draft', '') || '';
    // Grow with the text up to 128px. scrollHeight leaves the border out, so add it back; a scroll bar shows only past the limit.
    var fit = function () {
      input.style.height = 'auto';
      var full = input.scrollHeight + (input.offsetHeight - input.clientHeight);
      input.style.height = Math.min(128, full) + 'px'; input.style.overflowY = full > 128 ? 'auto' : 'hidden';
    };
    if (input.value) setTimeout(function () { if (input.isConnected) fit(); }, 0);
    input.addEventListener('input', function () {
      fit();
      sendBtn.disabled = !input.value.trim() || S.busy; sset('ora.draft', input.value || null);
      if (!S.busy) setMood(input.value.trim() ? 'listening' : 'idle');
    });
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(input.value); } });
    input.addEventListener('blur', function () { if (!S.busy && S.mood === 'listening') setMood('idle'); });
    sendBtn = h('button', { type: 'submit', class: 'ora-send', 'aria-label': 'Send' }); sendBtn.appendChild(icon('send'));
    sendBtn.disabled = !input.value.trim() || S.busy;
    form.appendChild(input); form.appendChild(sendBtn);
    foot.appendChild(form);
    var left = h('span', { text: 'Ora can make mistakes.' });
    var right = h('span', {}, [
      h('button', { type: 'button', text: 'Notes', onclick: function () { S.view = 'notes'; save(); render(); } }), ' · ',
      S.status && S.status.superuser ? h('a', { href: '/orasec/ora/settings/', text: 'Settings', style: 'color:inherit' }) : null,
      S.status && S.status.superuser ? ' · ' : null,
      h('button', { type: 'button', text: 'Hide Ora', title: 'Hide the Ora button (Ctrl/⌘ + / still opens Ora)', onclick: function () {
        S.status.hidden = true; closePanel(); api('preference/', { body: { hidden: true } });
      } })
    ]);
    foot.appendChild(h('div', { class: 'ora-meta' }, [left, right]));
    return foot;
  }

  function send(text) {
    text = (text || '').trim();
    if (!text || S.busy) return;
    S.err = null; S.busy = true; S.msgs.push({ role: 'user', text: text });
    if (input) input.value = ''; sset('ora.draft', null);
    setMood('working'); render();
    api('chat/', { body: { message: text, conversation_id: S.cid, page: pageCtx() } }).then(function (r) {
      S.busy = false;
      if (r.ok) {
        S.cid = r.data.conversation_id; S.title = r.data.title; S.msgs.push(r.data.message); save();
        setMood(r.data.message.mood === 'sorry' ? 'sorry' : r.data.message.mood === 'listening' ? 'listening' : 'happy', 3500);
      } else {
        S.err = r.data.detail || 'Ora is having a moment — try again shortly.';
        setMood(r.data.mood || 'sorry', 4000);
      }
      render();
      if (S.min && S.open) { /* keep the pill's last line fresh */ }
      setTimeout(function () { input && input.focus(); }, 20);
    });
  }

  /* ── history + notes ── */
  function renderHistory() {
    body.appendChild(h('div', { class: 'ora-empty', text: 'Loading…' }));
    api('conversations/').then(function (r) {
      body.innerHTML = '';
      var rows = (r.ok && r.data.results) || [];
      if (!rows.length) { body.appendChild(h('div', { class: 'ora-empty', text: 'No chats yet.' })); return; }
      body.appendChild(h('div', { class: 'ora-list' }, rows.map(function (c) {
        var del = ib('trash', 'Delete this chat', function () {
          api('conversations/' + c.id + '/delete/', { body: {} }).then(function () { if (S.cid === c.id) newChat(); else render(); });
        });
        return h('div', { class: 'ora-row' }, [h('button', { type: 'button', class: 'open', onclick: function () { loadConversation(c.id, true); } }, [
          h('span', { class: 't', text: c.title }), h('span', { class: 'd', text: ago(c.updated) + (c.surface === 'mobile' ? ' · phone' : '') })]), del]);
      })));
    });
  }
  function renderNotes() {
    body.appendChild(h('p', { style: 'margin:0 0 10px;font-size:13px;color:var(--ora-muted)', text: (S.status && S.status.memory_notice) || 'Short notes of earlier chats help me pick up where we left off.' }));
    var box = h('div', { class: 'ora-list' }, [h('div', { class: 'ora-empty', text: 'Loading…' })]); body.appendChild(box);
    api('memories/').then(function (r) {
      box.innerHTML = '';
      var rows = (r.ok && r.data.results) || [];
      if (!rows.length) { box.appendChild(h('div', { class: 'ora-empty', text: 'Nothing saved yet.' })); return; }
      rows.forEach(function (n) {
        box.appendChild(h('div', { class: 'ora-row' }, [h('span', { style: 'flex:1;min-width:0' }, [h('span', { class: 't', style: 'white-space:normal;font-weight:500', text: n.summary }), h('span', { class: 'd', text: ago(n.created) })]),
          ib('trash', 'Forget this', function () { api('memories/forget/', { body: { id: n.id } }).then(render); })]));
      });
      box.appendChild(h('div', { style: 'text-align:right;margin-top:6px' }, [h('button', { type: 'button', class: 'ora-btn', text: 'Forget everything', onclick: function () {
        if (window.confirm('Forget all notes about your earlier chats?')) api('memories/forget/', { body: {} }).then(render);
      } })]));
    });
  }
  function loadConversation(cid, show) {
    return api('conversations/' + cid + '/').then(function (r) {
      if (!r.ok) { S.cid = null; S.msgs = []; save(); if (show) render(); return; }
      S.cid = r.data.id; S.title = r.data.title; S.msgs = r.data.messages; S.view = 'chat'; save();
      if (show) render();
    });
  }

  /* ───────────────────────── Take me there + spotlight ───────────────────────── */
  var spot = null;
  function clearSpot() {
    if (!spot) return;
    cancelAnimationFrame(spot.raf); clearTimeout(spot.timer);
    spot.ring && spot.ring.remove(); spot.bub && spot.bub.remove();
    document.removeEventListener('scroll', spot.onScroll, true);
    spot = null;
  }
  function openSidebarGroup(target) {
    /* narrow screens: the rail is off-canvas, slide it in first so the spotlight has something to point at */
    if (target.closest('#os-sidebar') && !document.body.classList.contains('os-nav-shown')) {
      var nt = document.getElementById('os-nav-toggle');
      if (nt && nt.offsetParent) nt.click();
    }
    var grp = target.closest('#os-sidebar div[x-data]');
    if (!grp) return;
    try { if (window.Alpine && window.Alpine.$data) { window.Alpine.$data(grp).open = true; return; } } catch (e) { /* fall through */ }
    var tog = grp.querySelector(':scope > a'); if (tog && !target.offsetParent) tog.click();
  }
  function findTarget(sel) {
    if (!sel) return null;
    var list; try { list = document.querySelectorAll(sel); } catch (e) { return null; }
    for (var i = 0; i < list.length; i++) if (list[i].offsetParent !== null || list[i].getClientRects().length) return list[i];
    return list[0] || null;
  }
  /** Ring the element and show a caption. opts: {caption, sub, actions:[{label, primary, fn}], step, persist} */
  function spotlight(target, opts) {
    clearSpot();
    opts = opts || {};
    openSidebarGroup(target);
    try { target.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' }); } catch (e) { target.scrollIntoView(); }
    var ring = h('div', { class: 'ora-spot', 'aria-hidden': 'true' });
    var bub = h('div', { class: 'ora-bub', role: 'status', 'aria-live': 'polite' });
    var top = h('div', { class: 'top' }); var o = new Orb(30, opts.mood || 'happy'); top.appendChild(o.svg);
    top.appendChild(h('p', {}, [opts.caption || 'Here it is.', opts.sub ? h('small', { text: opts.sub }) : null]));
    top.appendChild(h('button', { type: 'button', class: 'x', 'aria-label': 'Close', text: '×', onclick: function () { clearSpot(); if (opts.onClose) opts.onClose(); } }));
    bub.appendChild(top);
    if (opts.actions && opts.actions.length) {
      var ft = h('div', { class: 'ft' }, [opts.step ? h('span', { class: 'n', text: opts.step }) : h('span', { class: 'n' })]);
      opts.actions.forEach(function (a) { ft.appendChild(h('button', { type: 'button', class: a.primary ? 'p' : '', text: a.label, onclick: a.fn })); });
      bub.appendChild(ft);
    }
    root.appendChild(ring); root.appendChild(bub);
    spot = { ring: ring, bub: bub, target: target };
    function place() {
      if (!spot) return;
      var r = target.getBoundingClientRect(), pad = 5;
      ring.style.top = (r.top - pad) + 'px'; ring.style.left = (r.left - pad) + 'px';
      ring.style.width = (r.width + pad * 2) + 'px'; ring.style.height = (r.height + pad * 2) + 'px';
      var bw = bub.offsetWidth || 300, bh = bub.offsetHeight || 90, vw = window.innerWidth, vh = window.innerHeight;
      var x, y;
      if (r.right + 16 + bw < vw && target.closest('#os-sidebar')) { x = r.right + 16; y = Math.max(10, Math.min(vh - bh - 10, r.top - 6)); }
      else { x = Math.max(10, Math.min(vw - bw - 10, r.left)); y = r.bottom + 12 + bh < vh ? r.bottom + 12 : Math.max(10, r.top - bh - 12); }
      bub.style.left = x + 'px'; bub.style.top = y + 'px';
      spot.raf = requestAnimationFrame(place);
    }
    place();
    if (!opts.persist) spot.timer = setTimeout(clearSpot, 9000);
  }
  function whenTarget(sel, cb, waitMs) {
    var t0 = Date.now();
    (function poll() {
      var t = findTarget(sel);
      if (t) return cb(t);
      if (Date.now() - t0 > (waitMs || 3000)) return cb(null);
      setTimeout(poll, 150);
    })();
  }
  function takeMeThere(a) {
    var pending = { path: a.path, sel: a.highlight, label: a.label, where: a.where };
    if (samePath(a.path)) { minimise(); showSpot(pending); return; }
    sset('ora.spot', pending);
    if (window.innerWidth < 640) minimise(); else { S.open = true; S.min = true; save(); }
    location.href = a.path;
  }
  function showSpot(p) {
    var sel = p.sel || '#os-sidebar a[href="' + p.path + '"]';
    whenTarget(sel, function (t) {
      if (!t) t = findTarget('main h1, .osp h1, h1');
      if (t) spotlight(t, { caption: p.label ? 'Here’s ' + p.label + '.' : 'Here it is.', sub: p.where || '' });
    });
  }

  /* ───────────────────────── Guided walkthroughs ───────────────────────── */
  var Guide = {
    start: function (id) {
      api('guides/' + encodeURIComponent(id) + '/').then(function (r) {
        if (!r.ok) { S.err = r.data.detail || 'That walkthrough isn’t available.'; render(); return; }
        sset('ora.guide', { id: r.data.id, title: r.data.title, steps: r.data.steps, i: 0 });
        minimise(); Guide.run();
      });
    },
    stop: function () { sset('ora.guide', null); clearSpot(); },
    go: function (i) {
      var g = sget('ora.guide'); if (!g) return;
      if (i >= g.steps.length) { Guide.stop(); setMood('happy', 3000); return; }
      g.i = Math.max(0, i); sset('ora.guide', g); Guide.run();
    },
    run: function () {
      var g = sget('ora.guide'); if (!g) return;
      var st = g.steps[g.i], n = g.steps.length;
      if (!samePath(st.path)) {
        // The step lives on another page: offer to go there.
        var anchor = findTarget('main h1, .osp h1, h1') || document.body;
        spotlight(anchor, { persist: true, mood: 'listening', caption: g.title + ': the next step is on another page.', step: 'Step ' + (g.i + 1) + ' of ' + n,
          actions: [{ label: 'Stop', fn: Guide.stop }, { label: 'Go there', primary: true, fn: function () { location.href = st.path; } }], onClose: Guide.stop });
        return;
      }
      whenTarget(st.target, function (t) {
        var actions = [{ label: 'Stop', fn: Guide.stop }];
        if (g.i > 0) actions.push({ label: 'Back', fn: function () { Guide.go(g.i - 1); } });
        if (!t) {
          spotlight(findTarget('main h1, .osp h1, h1') || document.body, { persist: true, mood: 'sorry', caption: 'I can’t see that on your screen — you may not have permission for this step.',
            step: 'Step ' + (g.i + 1) + ' of ' + n, actions: actions.concat([{ label: g.i + 1 < n ? 'Skip' : 'Done', primary: true, fn: function () { Guide.go(g.i + 1); } }]), onClose: Guide.stop });
          return;
        }
        if (!st.click) actions.push({ label: g.i + 1 < n ? 'Next' : 'Done', primary: true, fn: function () { Guide.go(g.i + 1); } });
        spotlight(t, { persist: true, mood: 'happy', caption: st.caption, step: 'Step ' + (g.i + 1) + ' of ' + n, actions: actions, onClose: Guide.stop });
        if (st.click) {
          var onClick = function () {
            t.removeEventListener('click', onClick, true);
            var cur = sget('ora.guide'); if (!cur) return;
            cur.i = g.i + 1; sset('ora.guide', cur);
            setTimeout(function () { if (sget('ora.guide') && samePath(cur.steps[Math.min(cur.i, cur.steps.length - 1)].path)) { if (cur.i >= cur.steps.length) Guide.stop(); else Guide.run(); } }, 450);
          };
          t.addEventListener('click', onClick, true);
        }
      }, 3500);
    }
  };
  window.OraGuide = Guide;

  /* ───────────────────────── boot ───────────────────────── */
  function boot() {
    root = h('div', { id: 'ora-root' });
    document.body.appendChild(root);
    buildLauncher();
    var saved = sget('ora.state', {}) || {};
    S.open = !!saved.open; S.min = !!saved.min; S.cid = saved.cid || null; S.view = saved.view || 'chat';
    api('status/').then(function (r) {
      if (!r.ok) { if (r.status === 401) { root.remove(); } return; }
      S.status = r.data;
      if (!r.data.available && !r.data.superuser) { root.remove(); return; }  // only admins see a resting / unset Ora
      setMood(r.data.available ? 'idle' : 'sleeping');
      var go = S.cid ? loadConversation(S.cid, false) : Promise.resolve();
      go.then(function () {
        render();
        var sp = sget('ora.spot'); if (sp) { sset('ora.spot', null); if (samePath(sp.path)) showSpot(sp); }
        if (sget('ora.guide')) setTimeout(Guide.run, 250);
      });
    });
    document.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === '/' || e.code === 'Slash')) {
        e.preventDefault();
        if (S.status && S.status.hidden) { S.status.hidden = false; api('preference/', { body: { hidden: false } }); }
        if (S.open && !S.min) closePanel(); else openPanel();
      }
    });
    window.addEventListener('resize', function () { if (panel && window.innerWidth < 640) { panel.style.left = panel.style.top = ''; panel.style.right = panel.style.bottom = ''; } });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();

