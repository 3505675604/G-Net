(function (root, factory) {
  'use strict';
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.NetworkScene = api;
})(typeof window !== 'undefined' ? window : null, function (browser) {
  'use strict';

  const TAU = Math.PI * 2;
  const MAX_NODES = 24;
  const clamp = (value, minimum, maximum) => Math.min(maximum, Math.max(minimum, value));
  const DEFAULT_VIEW = Object.freeze({ yaw: -0.52, pitch: 0.34, distance: 8.2, zoom: 1 });

  function rotatePoint(point, yaw, pitch) {
    if (!point || ![point.x, point.y, point.z, yaw, pitch].every(Number.isFinite)) return null;
    const cy = Math.cos(yaw), sy = Math.sin(yaw);
    const cp = Math.cos(pitch), sp = Math.sin(pitch);
    const x = cy * point.x + sy * point.z;
    const z = -sy * point.x + cy * point.z;
    return { x, y: cp * point.y + sp * z, z: -sp * point.y + cp * z };
  }

  function project(point, camera) {
    camera = camera || {};
    const rotated = rotatePoint(point, camera.yaw || 0, camera.pitch || 0);
    if (!rotated) return null;
    const distance = Number.isFinite(camera.distance) ? camera.distance : DEFAULT_VIEW.distance;
    const focal = Number.isFinite(camera.focal) ? camera.focal : 500;
    const depth = distance + rotated.z;
    if (depth <= 0.1 || focal <= 0) return null;
    const scale = focal / depth;
    return { x: (camera.cx || 0) + rotated.x * scale,
      y: (camera.cy || 0) - rotated.y * scale, depth, scale };
  }

  function bezierPoint(start, control, end, t) {
    const u = 1 - t;
    return { x: u * u * start.x + 2 * u * t * control.x + t * t * end.x,
      y: u * u * start.y + 2 * u * t * control.y + t * t * end.y,
      z: u * u * start.z + 2 * u * t * control.z + t * t * end.z };
  }

  function sortByDepth(items) {
    return items.slice().sort((a, b) => b.depth - a.depth);
  }

  function layoutNodes(servers) {
    const count = servers.length;
    return servers.map((server, index) => {
      const twoRings = count > 12;
      const outer = twoRings && index >= 12;
      const localIndex = outer ? index - 12 : index;
      const localCount = outer ? count - 12 : (twoRings ? 12 : count);
      const radius = outer ? 3.5 : (twoRings ? 2.2 : 2.9);
      const angle = TAU * localIndex / Math.max(1, localCount) + (outer ? 0.16 : 0.45);
      return { server, position: { x: Math.cos(angle) * radius, y: 0, z: Math.sin(angle) * radius } };
    });
  }

  function viewportCamera(width, height, view, visibleNodes) {
    view = { ...DEFAULT_VIEW, ...view };
    const top = Math.min(60, height * 0.26);
    // The HTML legend sits 42px above the floor on desktop and 55–66px on
    // narrow layouts, with its own padded row. Reserve its full footprint.
    const bottom = Math.min(width <= 620 ? 110 : 100, height * 0.48);
    const availableHeight = Math.max(1, height - top - bottom);
    const unitCamera = { yaw: view.yaw, pitch: view.pitch, distance: view.distance, focal: 1 };
    // With no layout argument, expose a conservative camera for the pure math
    // API. The renderer always supplies the actual saved-node layout, including
    // an empty array, so sparse scenes do not inherit a 24-node size limit.
    const fittingNodes = visibleNodes || Array.from({ length: 64 }, (_, index) => ({
      server: { name: '服务器' },
      position: { x: Math.cos(index * TAU / 64) * 3.5, y: 0, z: Math.sin(index * TAU / 64) * 3.5 }
    }));
    const samples = [];
    function sample(point, horizontalPadding, verticalPadding) {
      const projected = project(point, unitCamera);
      if (projected) samples.push({ ...projected, px: horizontalPadding, py: verticalPadding });
    }
    function corners(position, halfWidth, low, high, halfDepth) {
      for (const x of [-halfWidth, halfWidth]) for (const y of [low, high]) for (const z of [-halfDepth, halfDepth]) {
        sample({ x: position.x + x, y, z: position.z + z }, 2, 2);
      }
    }
    corners({ x: 0, z: 0 }, 0.72, -0.65, 1.02, 0.65);
    sample({ x: 0, y: -1.02, z: 0 }, 39, 14);
    for (const node of fittingNodes) {
      corners(node.position, 0.43, -0.65, 0.31, 0.38);
      const fullName = Array.from(node.server.name || '服务器');
      const chars = fullName.slice(0, 12);
      const labelWidth = chars.reduce((sum, char) => sum + (char.codePointAt(0) > 255 ? 13 : 7.5), 0) + (fullName.length > 12 ? 13 : 0);
      sample({ ...node.position, y: -0.98 }, labelWidth / 2 + 13, 14);
    }
    function centerBounds(focal) {
      let left = 0, right = width, upper = top, lower = height - bottom;
      for (const point of samples) {
        left = Math.max(left, point.px - point.x * focal);
        right = Math.min(right, width - point.px - point.x * focal);
        upper = Math.max(upper, top + point.py - point.y * focal);
        lower = Math.min(lower, height - bottom - point.py - point.y * focal);
      }
      return { left, right, upper, lower, fits: left <= right && upper <= lower };
    }
    // Start at the spacious size appropriate to this canvas; reduce only when
    // the current layout's measured projection would collide with its margins.
    let focal = Math.min(width * 1.02, availableHeight * 2.3);
    let bounds = centerBounds(focal);
    if (!bounds.fits) {
      let low = 0, high = focal;
      for (let i = 0; i < 16; i++) {
        const middle = (low + high) / 2;
        if (centerBounds(middle).fits) low = middle; else high = middle;
      }
      focal = Math.max(1, low); bounds = centerBounds(focal);
    }
    return { yaw: view.yaw, pitch: view.pitch, distance: view.distance,
      focal: focal * view.zoom,
      cx: clamp(width * 0.5, bounds.left, bounds.right),
      cy: clamp(top + availableHeight * 0.40, bounds.upper, bounds.lower),
      top, bottom, availableHeight };
  }

  function init(options) {
    options = options || {};
    const canvas = options.canvas;
    let context = null;
    try { context = canvas && canvas.getContext && canvas.getContext('2d'); } catch (_) { /* Optional view. */ }
    let servers = [], nodes = [], selected = null, hovered = null;
    const connections = new Map();
    let view = { ...DEFAULT_VIEW }, width = 0, height = 0, dpr = 1;
    let frame = null, previousFrame = 0, animationTime = 0, dirty = true;
    let active = true, disposed = false, motionWanted = true, reduced = false;
    let pointer = null, hits = [], labels = [], resizeObserver = null, media = null;
    const listeners = [];
    const usable = !!(browser && canvas && context && typeof browser.requestAnimationFrame === 'function');
    const doc = browser && browser.document;

    function listen(target, type, handler, settings) {
      if (!target || typeof target.addEventListener !== 'function') return;
      target.addEventListener(type, handler, settings);
      listeners.push(() => target.removeEventListener(type, handler, settings));
    }

    function visible() { return usable && active && !disposed && !(doc && doc.hidden); }
    function animating() {
      // Closed decorative orbits can move before any connection is verified.
      // Network-wire particles remain restricted to explicitly connected IDs.
      return visible() && motionWanted && !reduced;
    }
    function stopFrame() {
      if (frame !== null && browser) browser.cancelAnimationFrame(frame);
      frame = null;
      previousFrame = 0;
    }
    function requestDraw() {
      dirty = true;
      if (visible() && frame === null) frame = browser.requestAnimationFrame(drawFrame);
    }
    function rebuild() {
      let shown = servers.slice(0, MAX_NODES);
      const chosen = selected && servers.find(server => server.id === selected);
      if (chosen && !shown.some(server => server.id === selected)) shown[shown.length - 1] = chosen;
      nodes = layoutNodes(shown);
      requestDraw();
    }

    function measure() {
      if (!usable || disposed) return;
      const bounds = canvas.getBoundingClientRect();
      const nextWidth = Math.max(0, bounds.width), nextHeight = Math.max(0, bounds.height);
      const nextDpr = clamp(Number(browser.devicePixelRatio) || 1, 1, 2);
      if (nextWidth === width && nextHeight === height && nextDpr === dpr) return;
      width = nextWidth; height = nextHeight; dpr = nextDpr;
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      requestDraw();
    }

    function camera() {
      return viewportCamera(width, height, view, nodes);
    }

    function path(points, close) {
      if (!points.length || points.some(point => !point)) return false;
      context.beginPath();
      context.moveTo(points[0].x, points[0].y);
      for (let i = 1; i < points.length; i++) context.lineTo(points[i].x, points[i].y);
      if (close) context.closePath();
      return true;
    }

    function floorCircle(position, radius, color, lineWidth, cam) {
      const points = [];
      for (let i = 0; i <= 48; i++) {
        const angle = TAU * i / 48;
        points.push(project({ x: position.x + Math.cos(angle) * radius, y: -0.58,
          z: position.z + Math.sin(angle) * radius }, cam));
      }
      if (path(points, false)) {
        context.strokeStyle = color; context.lineWidth = lineWidth; context.stroke();
      }
    }

    function glow(point, radius, color) {
      if (!point || radius <= 0) return;
      const gradient = context.createRadialGradient(point.x, point.y, 0, point.x, point.y, radius);
      gradient.addColorStop(0, color); gradient.addColorStop(1, 'rgba(20,40,70,0)');
      context.fillStyle = gradient;
      context.beginPath(); context.arc(point.x, point.y, radius, 0, TAU); context.fill();
    }

    function box(position, dimensions, palette, cam) {
      const vertices = [];
      for (const y of [-1, 1]) for (const z of [-1, 1]) for (const x of [-1, 1]) {
        vertices.push(project({ x: position.x + x * dimensions.x / 2,
          y: position.y + y * dimensions.y / 2, z: position.z + z * dimensions.z / 2 }, cam));
      }
      const faces = [[0, 1, 3, 2], [0, 4, 5, 1], [1, 5, 7, 3],
        [3, 7, 6, 2], [2, 6, 4, 0], [4, 6, 7, 5]];
      const drawn = faces.map((indices, index) => ({ index, points: indices.map(i => vertices[i]),
        depth: indices.reduce((sum, i) => sum + (vertices[i] ? vertices[i].depth : 0), 0) / 4 }));
      for (const face of sortByDepth(drawn)) if (path(face.points, true)) {
        const fill = face.index === 5 ? palette.top : (face.index % 2 ? palette.side : palette.front);
        const gradient = context.createLinearGradient(face.points[0].x, face.points[0].y,
          face.points[2].x + 1, face.points[2].y + 1);
        gradient.addColorStop(0, face.index === 5 ? (palette.highlight || fill) : fill);
        gradient.addColorStop(1, face.index === 5 ? fill : (palette.shade || fill));
        context.fillStyle = gradient; context.fill();
        context.shadowColor = palette.glow || 'transparent'; context.shadowBlur = face.index === 5 ? 7 : 3;
        context.strokeStyle = palette.edge; context.lineWidth = face.index === 5 ? 1.25 : 0.85; context.stroke();
        context.shadowBlur = 0;
        if (face.index === 5 && palette.highlight) {
          const middle = face.points.reduce((sum, point) => ({ x: sum.x + point.x / 4, y: sum.y + point.y / 4 }), { x: 0, y: 0 });
          const inner = face.points.map(point => ({ x: point.x * 0.80 + middle.x * 0.20, y: point.y * 0.80 + middle.y * 0.20 }));
          if (path(inner, true)) { context.strokeStyle = palette.highlight; context.lineWidth = 0.5; context.stroke(); }
        }
      }
    }

    function drawGrid(cam) {
      context.setLineDash([]);
      for (let i = -8; i <= 8; i++) {
        const offset = i * 0.5;
        context.lineWidth = i % 4 === 0 ? 0.9 : 0.55;
        context.strokeStyle = i % 4 === 0 ? 'rgba(59,155,210,.23)' : 'rgba(76,111,179,.11)';
        for (const ends of [[{ x: -4, y: -0.58, z: offset }, { x: 4, y: -0.58, z: offset }],
          [{ x: offset, y: -0.58, z: -4 }, { x: offset, y: -0.58, z: 4 }]]) {
          if (path(ends.map(point => project(point, cam)), false)) context.stroke();
        }
      }
      floorCircle({ x: 0, z: 0 }, 1.28, 'rgba(58,196,221,.32)', 1.1, cam);
      floorCircle({ x: 0, z: 0 }, 3.35, 'rgba(109,91,217,.28)', 0.9, cam);
      floorCircle({ x: 0, z: 0 }, 3.44, 'rgba(69,133,200,.10)', 0.6, cam);
      if (!nodes.length) floorCircle({ x: 0, z: 0 }, 2.02, 'rgba(99,115,228,.24)', 0.9, cam);
      const phase = animationTime / 21000;
      orbitArc({ x: 0, y: -0.58, z: 0 }, 3.35, 0, phase, phase + 0.58, 'rgba(114,111,252,.52)', 1.15, cam);
    }

    function curveFor(node) {
      const end = { ...node.position, y: 0.29 };
      return { start: { x: 0, y: 0.54, z: 0 }, end,
        control: { x: end.x * 0.44, y: 1.32, z: end.z * 0.44 } };
    }

    function drawLink(node, cam) {
      const status = connections.get(node.server.id) || 'pending';
      const curve = curveFor(node);
      const points = [];
      for (let i = 0; i <= 32; i++) points.push(project(bezierPoint(curve.start, curve.control, curve.end, i / 32), cam));
      context.setLineDash(status === 'connected' ? [] : [3, 6]);
      context.strokeStyle = status === 'connected' ? 'rgba(49,237,209,.72)'
        : status === 'error' ? 'rgba(234,131,157,.44)' : 'rgba(128,154,186,.34)';
      context.shadowColor = status === 'connected' ? '#22d9ca' : 'transparent';
      context.shadowBlur = status === 'connected' ? 9 : 0;
      context.lineWidth = status === 'connected' ? 1.65 : 1.05;
      if (path(points, false)) context.stroke();
      context.shadowBlur = 0;
      context.setLineDash([]);
      if (status === 'connected' && motionWanted && !reduced) {
        const phase = (animationTime / 4600 + nodes.indexOf(node) * 0.173) % 1;
        const particle = project(bezierPoint(curve.start, curve.control, curve.end, phase), cam);
        if (particle) {
          glow(particle, 12, 'rgba(72,253,221,.43)');
          context.fillStyle = '#bcfff0'; context.beginPath();
          context.arc(particle.x, particle.y, 2.2, 0, TAU); context.fill();
        }
      }
    }

    function orbitArc(center, radius, tilt, start, end, color, lineWidth, cam) {
      const points = [];
      const steps = Math.max(10, Math.ceil((end - start) * 11));
      for (let i = 0; i <= steps; i++) {
        const angle = start + (end - start) * i / steps;
        points.push(project({ x: center.x + Math.cos(angle) * radius,
          y: center.y + Math.sin(angle) * radius * Math.sin(tilt),
          z: center.z + Math.sin(angle) * radius * Math.cos(tilt) }, cam));
      }
      if (path(points, false)) {
        context.strokeStyle = color; context.lineWidth = lineWidth;
        context.shadowColor = color; context.shadowBlur = lineWidth > 1 ? 8 : 0;
        context.stroke(); context.shadowBlur = 0;
      }
    }

    function drawDecorations(cam) {
      // This globe and these closed orbital particles are decorative geometry,
      // not additional devices or measured network traffic.
      const globe = { x: 4.0, y: 0.15, z: 3.6 }, radius = 1.65;
      const spin = animationTime / 25000;
      const globePoint = project(globe, cam);
      glow(globePoint, globePoint ? globePoint.scale * 2.0 : 0, 'rgba(70,91,223,.11)');
      function onGlobe(latitude, longitude) {
        const local = rotatePoint({ x: Math.cos(latitude) * Math.cos(longitude) * radius,
          y: Math.sin(latitude) * radius, z: Math.cos(latitude) * Math.sin(longitude) * radius }, spin, 0.10);
        return project({ x: globe.x + local.x, y: globe.y + local.y, z: globe.z + local.z }, cam);
      }
      context.lineWidth = 0.65;
      for (const latitude of [-1.05, -0.52, 0, 0.52, 1.05]) {
        const points = Array.from({ length: 49 }, (_, i) => onGlobe(latitude, TAU * i / 48));
        if (path(points, false)) { context.strokeStyle = 'rgba(85,153,221,.17)'; context.stroke(); }
      }
      for (let longitude = 0; longitude < 10; longitude++) {
        const points = Array.from({ length: 33 }, (_, i) => onGlobe(-Math.PI / 2 + Math.PI * i / 32, TAU * longitude / 10));
        if (path(points, false)) { context.strokeStyle = 'rgba(119,111,233,.14)'; context.stroke(); }
      }
      orbitArc(globe, 1.88, 0.38, 0, TAU, 'rgba(86,150,242,.21)', 0.85, cam);
      orbitArc(globe, 1.88, 0.38, spin * 2, spin * 2 + 0.7, 'rgba(150,131,255,.46)', 1.15, cam);
      const annotation = project({ x: globe.x + 1.1, y: globe.y - 1.75, z: globe.z }, cam);
      if (annotation) {
        context.font = '10px "Segoe UI", "Microsoft YaHei", sans-serif';
        context.textAlign = 'center'; context.textBaseline = 'middle';
        context.fillStyle = 'rgba(132,156,204,.48)'; context.fillText('装饰轨道', annotation.x, annotation.y);
      }
      const phase = animationTime / 15000;
      orbitArc({ x: 0, y: -0.48, z: 0 }, 1.57, 0, 0, TAU, 'rgba(85,145,208,.15)', 0.7, cam);
      for (let i = 0; i < 7; i++) {
        const angle = phase + i * TAU / 7;
        const point = project({ x: Math.cos(angle) * 1.57, y: -0.48, z: Math.sin(angle) * 1.57 }, cam);
        if (!point) continue;
        glow(point, 7, i % 3 ? 'rgba(65,211,240,.24)' : 'rgba(163,120,255,.29)');
        context.fillStyle = i % 3 ? '#78dceb' : '#be9dff';
        context.beginPath(); context.arc(point.x, point.y, 1.25, 0, TAU); context.fill();
      }
    }

    function drawShadow(position, radius, cam) {
      const points = [];
      for (let i = 0; i <= 40; i++) {
        const angle = i * TAU / 40;
        points.push(project({ x: position.x + Math.cos(angle) * radius,
          y: -0.655, z: position.z + Math.sin(angle) * radius }, cam));
      }
      if (path(points, true)) { context.fillStyle = 'rgba(0,3,13,.45)'; context.fill(); }
    }

    function drawServer(node, cam) {
      const status = connections.get(node.server.id) || 'pending';
      const chosen = node.server.id === selected, hot = node.server.id === hovered;
      const center = project({ ...node.position, y: 0.07 }, cam);
      if (!center) return;
      const accent = status === 'connected' ? '#74ffdc' : status === 'error' ? '#ec98b1' : '#7cb7f2';
      drawShadow(node.position, 0.63, cam);
      floorCircle(node.position, 0.64, chosen ? 'rgba(188,137,255,.85)' : (hot ? 'rgba(108,196,241,.62)' : 'rgba(83,152,229,.32)'), chosen ? 2.25 : 1.1, cam);
      if (chosen) floorCircle(node.position, 0.71, 'rgba(155,111,250,.32)', 0.85, cam);
      glow(center, Math.max(25, center.scale * 0.85), chosen ? 'rgba(142,88,241,.21)'
        : status === 'connected' ? 'rgba(34,230,192,.14)' : 'rgba(37,116,222,.12)');
      box({ ...node.position, y: -0.55 }, { x: 0.84, y: 0.12, z: 0.73 },
        { top: 'rgba(23,80,109,.57)', highlight: 'rgba(70,175,210,.44)', front: 'rgba(12,47,77,.70)',
          side: 'rgba(14,58,88,.64)', edge: chosen ? '#936dde' : '#418cb8', glow: chosen ? '#8245da' : '#147ac0' }, cam);
      const palette = { top: chosen ? '#46567e' : '#355b79', highlight: chosen ? '#8490c7' : '#83bad3',
        front: '#172b49', side: '#203b5a', shade: '#0d1b34', edge: chosen ? '#a488e1' : '#5795be', glow: chosen ? '#6247bb' : '#174a82' };
      for (let tier = 0; tier < 3; tier++) {
        const position = { ...node.position, y: -0.32 + tier * 0.24 };
        box(position, { x: 0.60, y: 0.185, z: 0.47 }, palette, cam);
        const light = project({ x: position.x - 0.20, y: position.y, z: position.z - 0.239 }, cam);
        if (light) {
          glow(light, 6, status === 'connected' ? 'rgba(67,255,210,.45)' : 'rgba(72,156,250,.30)');
          context.fillStyle = accent; context.beginPath(); context.arc(light.x, light.y, chosen ? 2.0 : 1.7, 0, TAU); context.fill();
        }
        for (let row = -1; row <= 1; row++) {
          const vents = [project({ x: position.x - 0.05, y: position.y + row * 0.028, z: position.z - 0.242 }, cam),
            project({ x: position.x + 0.22, y: position.y + row * 0.028, z: position.z - 0.242 }, cam)];
          if (path(vents, false)) { context.strokeStyle = row === 0 ? '#79a9c4' : '#3a6789'; context.lineWidth = 0.75; context.stroke(); }
        }
      }
      hits.push({ id: node.server.id, x: center.x, y: center.y, depth: center.depth,
        radius: Math.max(23, center.scale * 0.50) });
      const label = Array.from(node.server.name).slice(0, 12).join('') + (Array.from(node.server.name).length > 12 ? '…' : '');
      const labelPoint = project({ ...node.position, y: -0.98 }, cam);
      if (labelPoint) labels.push({ point: labelPoint, text: label, selected: chosen, hub: false });
    }

    function drawHub(cam) {
      const center = project({ x: 0, y: 0.24, z: 0 }, cam);
      glow(center, Math.max(65, center ? center.scale * 1.65 : 0), 'rgba(18,202,231,.22)');
      glow(project({ x: 0.4, y: 0.0, z: 0 }, cam), Math.max(42, center ? center.scale * 1.2 : 0), 'rgba(126,74,231,.16)');
      drawShadow({ x: 0, z: 0 }, 1.1, cam);
      floorCircle({ x: 0, z: 0 }, 1.04, 'rgba(95,195,240,.59)', 1.8, cam);
      const metal = { top: '#285b75', highlight: '#7dc5d4', front: '#173553', side: '#214969', shade: '#0b233b', edge: '#5aafce', glow: '#157596' };
      const glass = { top: 'rgba(46,116,157,.65)', highlight: '#9dccff', front: 'rgba(21,63,101,.78)',
        side: 'rgba(27,84,122,.70)', shade: 'rgba(8,29,59,.80)', edge: '#6ab8e8', glow: '#167bc0' };
      box({ x: 0, y: -0.55, z: 0 }, { x: 1.38, y: 0.16, z: 1.22 }, glass, cam);
      box({ x: 0, y: -0.34, z: 0 }, { x: 1.06, y: 0.22, z: 0.95 }, metal, cam);
      box({ x: 0, y: 0.10, z: 0 }, { x: 0.72, y: 0.66, z: 0.65 }, glass, cam);
      box({ x: 0, y: 0.47, z: 0 }, { x: 0.86, y: 0.13, z: 0.77 }, metal, cam);
      const core = project({ x: 0, y: 0.13, z: -0.335 }, cam);
      if (core) {
        glow(core, Math.max(14, core.scale * 0.25), 'rgba(65,244,241,.50)');
        context.fillStyle = '#b6fff7'; context.shadowColor = '#32e1ef'; context.shadowBlur = 16;
        context.beginPath(); context.arc(core.x, core.y, Math.max(3.5, core.scale * 0.075), 0, TAU); context.fill(); context.shadowBlur = 0;
      }
      for (const x of [-0.27, 0.27]) {
        const rail = [project({ x, y: -0.17, z: -0.338 }, cam), project({ x, y: 0.35, z: -0.338 }, cam)];
        if (path(rail, false)) { context.strokeStyle = x < 0 ? '#4fe4e8' : '#a58bfa'; context.lineWidth = 1.6;
          context.shadowColor = context.strokeStyle; context.shadowBlur = 6; context.stroke(); context.shadowBlur = 0; }
      }
      const phase = animationTime / 10000;
      orbitArc({ x: 0, y: 0.77, z: 0 }, 0.50, 0.14, 0, TAU, 'rgba(119,126,248,.49)', 1.0, cam);
      orbitArc({ x: 0, y: 0.77, z: 0 }, 0.50, 0.14, phase, phase + 1.7, 'rgba(119,252,250,.87)', 1.75, cam);
      orbitArc({ x: 0, y: 0.77, z: 0 }, 0.62, 0.14, phase + Math.PI, phase + Math.PI + 0.9, 'rgba(180,146,255,.83)', 1.55, cam);
      const top = project({ x: 0, y: 0.77, z: 0 }, cam);
      glow(top, Math.max(13, top ? top.scale * 0.22 : 0), 'rgba(67,207,255,.32)');
      if (top) { context.fillStyle = '#c4faff'; context.beginPath(); context.arc(top.x, top.y, 2.5, 0, TAU); context.fill(); }
      const label = project({ x: 0, y: -1.02, z: 0 }, cam);
      if (label) labels.push({ point: label, text: '管理核心', hub: true, selected: false });
    }

    function drawLabels() {
      context.textAlign = 'center'; context.textBaseline = 'middle';
      for (const label of labels) {
        context.font = '600 ' + (label.hub ? '14' : '13') + 'px "Segoe UI", "Microsoft YaHei", sans-serif';
        const textWidth = context.measureText(label.text).width;
        const x = label.point.x - textWidth / 2 - 10, y = label.point.y - 12;
        context.beginPath();
        if (context.roundRect) context.roundRect(x, y, textWidth + 20, 25, 5);
        else context.rect(x, y, textWidth + 20, 25);
        context.fillStyle = label.selected ? 'rgba(31,28,68,.95)' : 'rgba(9,25,48,.95)'; context.fill();
        context.lineWidth = 0.8;
        context.strokeStyle = label.selected ? 'rgba(177,145,255,.70)' : (label.hub ? 'rgba(77,189,224,.54)' : 'rgba(89,149,198,.37)');
        context.stroke();
        context.fillStyle = label.selected ? '#e0d5ff' : (label.hub ? '#b0f2f0' : '#d1e5f7');
        context.fillText(label.text, label.point.x, label.point.y);
      }
    }

    function render() {
      if (!width || !height) return;
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      context.clearRect(0, 0, width, height);
      const background = context.createLinearGradient(0, 0, width, height);
      background.addColorStop(0, '#111d3c'); background.addColorStop(0.46, '#07152e'); background.addColorStop(1, '#101734');
      context.fillStyle = background; context.fillRect(0, 0, width, height);
      glow({ x: width * 0.47, y: height * 0.46 }, Math.min(width, height) * 0.65, 'rgba(18,120,183,.16)');
      glow({ x: width * 0.80, y: height * 0.27 }, Math.min(width, height) * 0.52, 'rgba(119,54,211,.12)');
      const cam = camera();
      // Keep the stage's controls and legend clear, including the projected
      // floor grid. Deliberate zooming can crop geometry inside this viewport.
      context.save();
      context.beginPath(); context.rect(0, cam.top, width, cam.availableHeight); context.clip();
      for (let i = 0; i < 38; i++) {
        const x = (Math.sin(i * 127.1 + 7) * 0.5 + 0.5) * width;
        const y = cam.top + (Math.sin(i * 91.7 + 17) * 0.5 + 0.5) * cam.availableHeight;
        context.fillStyle = i % 4 ? 'rgba(126,176,227,.11)' : 'rgba(182,145,255,.16)';
        context.fillRect(x, y, i % 4 ? 1 : 1.4, i % 4 ? 1 : 1.4);
      }
      drawDecorations(cam);
      drawGrid(cam);
      hits = []; labels = [];
      const entities = [{ type: 'hub', depth: project({ x: 0, y: 0, z: 0 }, cam).depth }];
      for (const node of nodes) {
        const projected = project(node.position, cam);
        if (projected) entities.push({ type: 'server', node, depth: projected.depth });
        const midpoint = project(bezierPoint(curveFor(node).start, curveFor(node).control, curveFor(node).end, 0.5), cam);
        if (midpoint) entities.push({ type: 'link', node, depth: midpoint.depth + 0.025 });
      }
      for (const entity of sortByDepth(entities)) {
        if (entity.type === 'hub') drawHub(cam);
        else if (entity.type === 'server') drawServer(entity.node, cam);
        else drawLink(entity.node, cam);
      }
      drawLabels();
      context.restore();
      hits.sort((a, b) => a.depth - b.depth);
    }

    function drawFrame(timestamp) {
      frame = null;
      if (!visible()) return;
      const delta = previousFrame ? Math.min(100, timestamp - previousFrame) : 0;
      if (!dirty && previousFrame && delta < 32) {
        if (animating()) frame = browser.requestAnimationFrame(drawFrame);
        return;
      }
      previousFrame = timestamp;
      if (animating()) animationTime += delta;
      dirty = false;
      try { render(); } catch (_) { motionWanted = false; return; }
      if (animating()) frame = browser.requestAnimationFrame(drawFrame);
    }

    function pointAt(event) {
      const bounds = canvas.getBoundingClientRect();
      return { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
    }
    function hitAt(point) {
      const cam = camera();
      if (point.x < 0 || point.x > width || point.y < cam.top || point.y > height - cam.bottom) return null;
      return hits.find(hit => (hit.x - point.x) ** 2 + (hit.y - point.y) ** 2 <= hit.radius ** 2);
    }
    function selectHit(event) {
      const hit = hitAt(pointAt(event));
      if (!hit) return;
      controller.setSelected(hit.id);
      if (typeof options.onSelect === 'function') try { options.onSelect(hit.id); } catch (_) { /* Keep the host UI usable. */ }
    }
    function zoom(multiplier) {
      if (disposed) return view.zoom;
      view.zoom = clamp(view.zoom * multiplier, 0.7, 1.45);
      requestDraw(); return view.zoom;
    }

    const controller = {
      setServers(list) {
        if (disposed) return;
        const seen = new Set();
        servers = (Array.isArray(list) ? list : []).filter(server => server && typeof server.id === 'string' && server.id && !seen.has(server.id) && seen.add(server.id))
          .map(server => ({ id: server.id, name: typeof server.name === 'string' && server.name.trim() ? server.name.trim() : '服务器' }));
        for (const id of connections.keys()) if (!seen.has(id)) connections.delete(id);
        if (!seen.has(selected)) selected = null;
        rebuild();
      },
      setSelected(id) {
        if (disposed) return;
        selected = typeof id === 'string' && servers.some(server => server.id === id) ? id : null;
        rebuild();
      },
      setConnection(id, status) {
        if (disposed || !servers.some(server => server.id === id)) return;
        if (!['pending', 'connected', 'error'].includes(status)) return;
        connections.set(id, status); requestDraw();
      },
      setActive(value) {
        if (disposed) return;
        active = !!value;
        if (!active) stopFrame(); else { measure(); requestDraw(); }
      },
      resetView() { if (!disposed) { view = { ...DEFAULT_VIEW }; requestDraw(); } },
      toggleMotion() { if (disposed) return false; motionWanted = !motionWanted; requestDraw(); return motionWanted && !reduced; },
      zoomIn() { return zoom(1.13); },
      zoomOut() { return zoom(1 / 1.13); },
      getStats() { return { total: servers.length, rendered: nodes.length, hidden: Math.max(0, servers.length - nodes.length),
        connected: servers.filter(server => connections.get(server.id) === 'connected').length, motion: motionWanted && !reduced }; },
      destroy() {
        if (disposed) return;
        disposed = true; stopFrame();
        if (resizeObserver) resizeObserver.disconnect();
        if (pointer && canvas && canvas.releasePointerCapture) try { canvas.releasePointerCapture(pointer.id); } catch (_) { /* Capture already released. */ }
        for (const remove of listeners) try { remove(); } catch (_) { /* Already detached. */ }
        listeners.length = 0;
        if (canvas && canvas.style) canvas.style.cursor = '';
        servers = []; nodes = []; hits = []; labels = []; connections.clear(); pointer = null;
      }
    };

    if (usable) {
      try {
        media = browser.matchMedia && browser.matchMedia('(prefers-reduced-motion: reduce)');
        reduced = !!(media && media.matches);
        const onReduced = event => { reduced = !!event.matches; stopFrame(); requestDraw(); };
        if (media && media.addEventListener) listen(media, 'change', onReduced);
        else if (media && media.addListener) { media.addListener(onReduced); listeners.push(() => media.removeListener(onReduced)); }
        if (typeof browser.ResizeObserver === 'function') {
          resizeObserver = new browser.ResizeObserver(() => { measure(); requestDraw(); });
          resizeObserver.observe(canvas);
        } else listen(browser, 'resize', measure);
        listen(doc, 'visibilitychange', () => { stopFrame(); if (visible()) requestDraw(); });
        listen(canvas, 'pointerdown', event => {
          if (event.button !== undefined && event.button !== 0) return;
          const point = pointAt(event);
          pointer = { id: event.pointerId, x: point.x, y: point.y, yaw: view.yaw, pitch: view.pitch, dragged: false };
          if (canvas.setPointerCapture) try { canvas.setPointerCapture(event.pointerId); } catch (_) { /* Detached canvas. */ }
        });
        listen(canvas, 'pointermove', event => {
          const point = pointAt(event);
          if (pointer && pointer.id === event.pointerId) {
            const dx = point.x - pointer.x, dy = point.y - pointer.y;
            if (dx * dx + dy * dy > 36) pointer.dragged = true;
            if (pointer.dragged) {
              view.yaw = pointer.yaw + dx * 0.006;
              view.pitch = clamp(pointer.pitch + dy * 0.0035, 0.14, 0.67);
              canvas.style.cursor = 'grabbing'; requestDraw();
            }
          } else {
            const hit = hitAt(point), id = hit ? hit.id : null;
            if (id !== hovered) { hovered = id; canvas.style.cursor = hit ? 'pointer' : 'grab'; requestDraw(); }
          }
        });
        listen(canvas, 'pointerup', event => {
          if (!pointer || pointer.id !== event.pointerId) return;
          const wasDragged = pointer.dragged; pointer = null;
          if (canvas.releasePointerCapture) try { canvas.releasePointerCapture(event.pointerId); } catch (_) { /* Capture already released. */ }
          canvas.style.cursor = 'grab';
          if (!wasDragged) selectHit(event);
        });
        listen(canvas, 'pointercancel', () => { pointer = null; canvas.style.cursor = 'grab'; });
        listen(canvas, 'pointerleave', () => { hovered = null; if (!pointer) canvas.style.cursor = 'grab'; requestDraw(); });
        // No wheel handler: the surrounding page keeps its normal scroll behavior.
        measure(); requestDraw();
      } catch (_) { stopFrame(); }
    }
    return controller;
  }

  return Object.freeze({ init, project, rotatePoint, bezierPoint, sortByDepth, layoutNodes, viewportCamera, MAX_NODES });
});
