'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const scene = require('../server-manager/static/network-scene.js');

function near(actual, expected, tolerance = 1e-9) {
  assert.ok(Math.abs(actual - expected) <= tolerance, `${actual} differs from ${expected}`);
}

test('rotation preserves the length of a 3D vector', () => {
  const point = { x: 2, y: -3, z: 4 };
  for (const yaw of [0, 0.4, Math.PI / 2, Math.PI]) {
    for (const pitch of [-0.3, 0, 0.5]) {
      const result = scene.rotatePoint(point, yaw, pitch);
      near(Math.hypot(result.x, result.y, result.z), Math.hypot(point.x, point.y, point.z));
    }
  }
});

test('a quarter turn maps world X into depth', () => {
  const point = scene.rotatePoint({ x: 1, y: 0, z: 0 }, Math.PI / 2, 0);
  near(point.x, 0);
  near(point.y, 0);
  near(point.z, -1);
});

test('the world origin projects to the chosen screen center', () => {
  const point = scene.project({ x: 0, y: 0, z: 0 }, { yaw: 0.8, pitch: 0.4, distance: 8, focal: 600, cx: 320, cy: 200 });
  near(point.x, 320);
  near(point.y, 200);
  near(point.depth, 8);
});

test('perspective shrinks farther geometry rather than using flat coordinates', () => {
  const camera = { distance: 8, focal: 400, cx: 200, cy: 150 };
  const nearPoint = scene.project({ x: 2, y: 1, z: -2 }, camera);
  const farPoint = scene.project({ x: 2, y: 1, z: 2 }, camera);
  assert.ok(nearPoint.x - camera.cx > farPoint.x - camera.cx);
  assert.ok(camera.cy - nearPoint.y > camera.cy - farPoint.y);
  near((nearPoint.x - camera.cx) / (farPoint.x - camera.cx), 10 / 6);
});

test('projection rejects geometry behind the camera and invalid values', () => {
  assert.equal(scene.project({ x: 1, y: 0, z: -9 }, { distance: 8 }), null);
  assert.equal(scene.project({ x: Infinity, y: 0, z: 1 }, {}), null);
  assert.equal(scene.project(null, {}), null);
});

test('an arched wire has the correct endpoints and rises above both', () => {
  const start = { x: 0, y: 0.3, z: 0 };
  const control = { x: 1, y: 1.4, z: 1 };
  const end = { x: 2, y: 0.1, z: 2 };
  assert.deepEqual(scene.bezierPoint(start, control, end, 0), start);
  assert.deepEqual(scene.bezierPoint(start, control, end, 1), end);
  const middle = scene.bezierPoint(start, control, end, 0.5);
  near(middle.x, 1);
  near(middle.z, 1);
  assert.ok(middle.y > start.y && middle.y > end.y);
});

test('painter ordering puts distant geometry first without mutating caller data', () => {
  const items = [{ id: 'near', depth: 4 }, { id: 'far', depth: 10 }, { id: 'middle', depth: 7 }];
  assert.deepEqual(scene.sortByDepth(items).map(item => item.id), ['far', 'middle', 'near']);
  assert.deepEqual(items.map(item => item.id), ['near', 'far', 'middle']);
});

test('empty layouts add no invented servers and all saved labels remain attached', () => {
  assert.deepEqual(scene.layoutNodes([]), []);
  const servers = Array.from({ length: 24 }, (_, i) => ({ id: String(i), name: `Server ${i}` }));
  const nodes = scene.layoutNodes(servers);
  assert.equal(nodes.length, servers.length);
  assert.deepEqual(nodes.map(node => node.server.id), servers.map(server => server.id));
  const positions = new Set(nodes.map(node => `${node.position.x},${node.position.y},${node.position.z}`));
  assert.equal(positions.size, 24);
  assert.ok(nodes.every(node => Object.values(node.position).every(Number.isFinite)));
  // All default labels must fit above the external legend on both the tested
  // desktop canvas and the short mobile canvas, even with two rings of nodes.
  for (const [width, height] of [[550, 352], [390, 238]]) {
    const camera = scene.viewportCamera(width, height);
    for (let count = 1; count <= 24; count++) {
      for (const node of scene.layoutNodes(servers.slice(0, count))) {
        const label = scene.project({ ...node.position, y: -0.82 }, camera);
        assert.ok(label.y - 8 >= camera.top, `label overlaps top controls at ${width}×${height}`);
        assert.ok(label.y + 8 <= height - camera.bottom, `label overlaps legend at ${width}×${height}`);
      }
    }
  }
  // The larger glass platforms and 13px labels use their current layout's
  // fitted camera, including a short mobile stage and the dense 24-node view.
  for (const [width, height] of [[830, 420], [700, 420], [520, 376], [358, 354], [390, 238]]) {
    for (let count = 0; count <= 24; count++) {
      const visible = scene.layoutNodes(servers.slice(0, count));
      const camera = scene.viewportCamera(width, height, undefined, visible);
      assert.ok(camera.bottom >= 100, 'the padded HTML legend needs a full bottom safety band');
      for (const node of visible) {
        const label = scene.project({ ...node.position, y: -0.98 }, camera);
        assert.ok(label.y - 13 >= camera.top);
        assert.ok(label.y + 13 <= height - camera.bottom);
      }
      for (const x of [-0.72, 0.72]) for (const y of [-0.65, 1.02]) for (const z of [-0.65, 0.65]) {
        const vertex = scene.project({ x, y, z }, camera);
        assert.ok(vertex.y >= camera.top && vertex.y <= height - camera.bottom);
      }
    }
  }
});

test('optional canvas fallback keeps the host UI working and retains all server data', () => {
  const controller = scene.init({ canvas: { getContext() { return null; } }, onSelect() { throw new Error('unused'); } });
  const servers = Array.from({ length: 30 }, (_, i) => ({ id: `saved-${i}`, name: `Node ${i}`, password: 'never-rendered' }));
  controller.setServers(servers);
  assert.deepEqual(controller.getStats(), { total: 30, rendered: 24, hidden: 6, connected: 0, motion: true });
  controller.setConnection('saved-29', 'connected');
  controller.setSelected('saved-29');
  assert.equal(controller.getStats().connected, 1);
  controller.setConnection('invented-id', 'connected');
  assert.equal(controller.getStats().connected, 1);
  controller.setConnection('saved-0', 'unsupported');
  assert.equal(controller.getStats().connected, 1);
  for (let i = 0; i < 20; i++) controller.zoomIn();
  near(controller.zoomIn(), 1.45);
  for (let i = 0; i < 20; i++) controller.zoomOut();
  near(controller.zoomOut(), 0.7);
  controller.setActive(false);
  controller.resetView();
  assert.equal(controller.toggleMotion(), false);
  controller.destroy();
  controller.destroy();
  controller.setServers(servers);
  assert.equal(controller.getStats().total, 0);
});

test('failure to obtain a canvas context is handled without throwing', () => {
  assert.doesNotThrow(() => scene.init({ canvas: { getContext() { throw new Error('disabled canvas'); } } }).destroy());
  assert.doesNotThrow(() => scene.init({}).setServers(null));
});
