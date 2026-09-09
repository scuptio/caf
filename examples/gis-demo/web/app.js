"use strict";

const COLORS = {
  Africa: { fill: "rgba(255,196,90,0.35)", stroke: "#ffc45a" },
  Asia: { fill: "rgba(255,92,92,0.35)", stroke: "#ff5c5c" },
  Europe: { fill: "rgba(79,140,255,0.35)", stroke: "#4f8cff" },
  "North America": { fill: "rgba(61,220,132,0.35)", stroke: "#3ddc84" },
  "South America": { fill: "rgba(255,160,60,0.35)", stroke: "#ffa03c" },
  Oceania: { fill: "rgba(180,120,255,0.35)", stroke: "#b478ff" },
  Antarctica: { fill: "rgba(160,200,255,0.35)", stroke: "#a0c8ff" },
  "Seven seas (open ocean)": { fill: "rgba(120,200,220,0.35)", stroke: "#78c8dc" },
};

const state = {
  caf: null,
  comp: null,
  features: [],
  projection: 3857,
  layer: "all",
  format: "global.geo.json",
  view: { scale: 1, tx: 0, ty: 0 },
  bounds: null,
  dirty: true,
};

const $ = (id) => document.getElementById(id);
const canvas = $("map");
const ctx = canvas.getContext("2d");

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------
async function loadBuffer(arrayBuffer) {
  try {
    const caf = CAF.parseCaf(arrayBuffer);
    const comp = await CAF.instantiate(caf.wasm, caf.files, arrayBuffer);

    const result = comp.featuresFromFile(state.format);
    if (result.error) throw new Error(result.error);

    state.caf = caf;
    state.comp = comp;
    state.features = result.features;
    state.dirty = true;

    updateInfo(caf, comp, caf.files);
    fitView();
    render();
    $("status").textContent =
      "Loaded " + state.format + " — " + state.features.length + " features";
    $("dropHint").classList.add("hidden");
  } catch (err) {
    $("status").textContent = "Error: " + err.message;
    console.error(err);
  }
}

async function openFile(file) {
  const buf = await file.arrayBuffer();
  await loadBuffer(buf);
}

// ---------------------------------------------------------------------------
// Info panel
// ---------------------------------------------------------------------------
function updateInfo(caf, comp, files) {
  const m = caf.manifest;
  $("artifactInfo").innerHTML = [
    ["name", m.name],
    ["version", m.version],
    ["format", "v" + m.format_version],
    ["crs", m.payloads && m.payloads.length ? "EPSG:4326" : "—"],
    ["root", m.hashes ? m.hashes.root.slice(0, 16) + "…" : "—"],
  ]
    .map(([k, v]) => `<div class="row"><span class="k">${k}</span><span class="v">${v}</span></div>`)
    .join("");

  $("capsInfo").innerHTML = (m.capabilities || [])
    .map((c) => `<span class="badge">${c}</span>`)
    .join("");

  $("payloadInfo").innerHTML = Array.from(files.entries())
    .map(
      ([path, f]) =>
        `<div class="row"><span class="k">${path}</span><span class="v">${f.length} B</span></div>`
    )
    .join("");

  $("exportsInfo").innerHTML = comp
    .exports()
    .filter((n) => ["features", "features_from_file", "reproject_x", "reproject_y", "alloc", "dealloc"].includes(n))
    .map((n) => `<span class="badge">${n}()</span>`)
    .join("");
}

// ---------------------------------------------------------------------------
// Projection + rendering
// ---------------------------------------------------------------------------
function projectPoint(x, y) {
  if (state.projection === 4326) return [x, y];
  return state.comp.reproject(x, y, 4326, state.projection);
}

function projectedFeature(f) {
  if (f.kind === "point") {
    return projectPoint(f.coords[0], f.coords[1]);
  }
  if (f.kind === "line") {
    return f.coords.map(([x, y]) => projectPoint(x, y));
  }
  if (f.kind === "polygon") {
    return f.coords.map((ring) => ring.map(([x, y]) => projectPoint(x, y)));
  }
  if (f.kind === "multipolygon") {
    return f.coords.map((poly) => poly.map((ring) => ring.map(([x, y]) => projectPoint(x, y))));
  }
  return f.coords;
}

function computeBounds() {
  let minX = Infinity,
    minY = Infinity,
    maxX = -Infinity,
    maxY = -Infinity;
  const visit = (pt) => {
    if (pt[0] < minX) minX = pt[0];
    if (pt[0] > maxX) maxX = pt[0];
    if (pt[1] < minY) minY = pt[1];
    if (pt[1] > maxY) maxY = pt[1];
  };
  for (const f of visibleFeatures()) {
    const p = projectedFeature(f);
    if (f.kind === "point") visit(p);
    else if (f.kind === "line") p.forEach(visit);
    else if (f.kind === "polygon") p.forEach((ring) => ring.forEach(visit));
    else if (f.kind === "multipolygon") p.forEach((poly) => poly.forEach((ring) => ring.forEach(visit)));
  }
  if (minX === Infinity) return { minX: 0, minY: 0, maxX: 1, maxY: 1 };
  return { minX, minY, maxX, maxY };
}

function visibleFeatures() {
  if (state.layer === "all") return state.features;
  return state.features.filter((f) => f.layer === state.layer);
}

function screenExtent(f, p) {
  let minX = Infinity,
    minY = Infinity,
    maxX = -Infinity,
    maxY = -Infinity;
  const visit = (x, y) => {
    const sx = screenX(x);
    const sy = screenY(y);
    if (sx < minX) minX = sx;
    if (sx > maxX) maxX = sx;
    if (sy < minY) minY = sy;
    if (sy > maxY) maxY = sy;
  };
  if (f.kind === "point") visit(p[0], p[1]);
  else if (f.kind === "line") p.forEach(([x, y]) => visit(x, y));
  else if (f.kind === "polygon") p.forEach((ring) => ring.forEach(([x, y]) => visit(x, y)));
  else if (f.kind === "multipolygon")
    p.forEach((poly) => poly.forEach((ring) => ring.forEach(([x, y]) => visit(x, y))));
  return { minX, minY, maxX, maxY };
}

function screenX(x) {
  return x * state.view.scale + state.view.tx;
}
function screenY(y) {
  return -y * state.view.scale + state.view.ty;
}

function fitView() {
  const b = computeBounds();
  state.bounds = b;
  const cw = canvas.clientWidth;
  const ch = canvas.clientHeight;
  const w = Math.max(b.maxX - b.minX, 1e-9);
  const h = Math.max(b.maxY - b.minY, 1e-9);
  const scale = Math.min(cw / w, ch / h) * 0.9;
  const cx = (b.minX + b.maxX) / 2;
  const cy = (b.minY + b.maxY) / 2;
  state.view.scale = scale;
  state.view.tx = cw / 2 - cx * scale;
  state.view.ty = ch / 2 + cy * scale;
}

function render() {
  const cw = canvas.clientWidth;
  const ch = canvas.clientHeight;
  const dpr = window.devicePixelRatio || 1;
  if (canvas.width !== cw * dpr || canvas.height !== ch * dpr) {
    canvas.width = cw * dpr;
    canvas.height = ch * dpr;
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cw, ch);
  ctx.fillStyle = "#12141a";
  ctx.fillRect(0, 0, cw, ch);

  for (const f of visibleFeatures()) {
    const color = COLORS[f.layer] || { fill: "rgba(200,200,200,0.3)", stroke: "#ccc" };
    drawFeature(f, projectedFeature(f), color);
  }
}

function drawFeature(f, p, color) {
  ctx.lineWidth = 2;
  ctx.strokeStyle = color.stroke;
  if (f.kind === "point") {
    ctx.fillStyle = color.fill || color.stroke;
    ctx.beginPath();
    ctx.arc(screenX(p[0]), screenY(p[1]), 4, 0, Math.PI * 2);
    ctx.fill();
    return;
  }
  if (f.kind === "line") {
    ctx.beginPath();
    p.forEach(([x, y], i) => {
      if (i === 0) ctx.moveTo(screenX(x), screenY(y));
      else ctx.lineTo(screenX(x), screenY(y));
    });
    ctx.stroke();
    return;
  }
  // Features whose screen extent is a couple of pixels (small countries /
  // islands at world zoom) are drawn as a dot so they stay visible.
  const e = screenExtent(f, p);
  if (e.maxX - e.minX < 3 && e.maxY - e.minY < 3) {
    ctx.fillStyle = color.fill || color.stroke;
    ctx.strokeStyle = color.stroke;
    ctx.beginPath();
    ctx.arc((e.minX + e.maxX) / 2, (e.minY + e.maxY) / 2, 2.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
    return;
  }
  if (f.kind === "polygon") {
    ctx.beginPath();
    for (const ring of p) {
      ring.forEach(([x, y], i) => {
        if (i === 0) ctx.moveTo(screenX(x), screenY(y));
        else ctx.lineTo(screenX(x), screenY(y));
      });
      ctx.closePath();
    }
    if (color.fill) {
      ctx.fillStyle = color.fill;
      ctx.fill();
    }
    ctx.stroke();
  }
  if (f.kind === "multipolygon") {
    for (const poly of p) {
      ctx.beginPath();
      for (const ring of poly) {
        ring.forEach(([x, y], i) => {
          if (i === 0) ctx.moveTo(screenX(x), screenY(y));
          else ctx.lineTo(screenX(x), screenY(y));
        });
        ctx.closePath();
      }
      if (color.fill) {
        ctx.fillStyle = color.fill;
        ctx.fill();
      }
      ctx.stroke();
    }
  }
}

// ---------------------------------------------------------------------------
// Interaction
// ---------------------------------------------------------------------------
let dragging = false;
let lastX = 0;
let lastY = 0;

canvas.addEventListener("mousedown", (e) => {
  dragging = true;
  lastX = e.clientX;
  lastY = e.clientY;
});
window.addEventListener("mousemove", (e) => {
  if (!dragging) return;
  state.view.tx += e.clientX - lastX;
  state.view.ty += e.clientY - lastY;
  lastX = e.clientX;
  lastY = e.clientY;
  render();
});
window.addEventListener("mouseup", () => (dragging = false));

canvas.addEventListener(
  "wheel",
  (e) => {
    e.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1;
    const s = state.view.scale;
    const ns = s * factor;
    state.view.tx = mx - ((mx - state.view.tx) / s) * ns;
    state.view.ty = my - ((my - state.view.ty) / s) * ns;
    state.view.scale = ns;
    render();
  },
  { passive: false }
);

// Track the canvas element's layout size (it changes when the settings panel
// collapses/expands or the window resizes). Re-render at the new resolution
// WITHOUT calling fitView(), so the current zoom/pan is preserved.
const resizeObserver = new ResizeObserver(() => {
  if (state.features.length) render();
});
resizeObserver.observe(canvas);

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------
$("projSelect").addEventListener("change", (e) => {
  state.projection = Number(e.target.value);
  fitView();
  render();
});

$("layerSelect").addEventListener("change", (e) => {
  state.layer = e.target.value;
  render();
});

// Payload format: pick exactly one carrier file; the WASM component decodes it
// with the codec matched by filename (*.wkb -> WKB, else GeoJSON).
function chooseFormat(name) {
  state.format = name;
  $("fmtGeojson").checked = name === "global.geo.json";
  $("fmtWkb").checked = name === "global.wkb";
  if (state.comp) reloadFeatures();
}

function reloadFeatures() {
  const result = state.comp.featuresFromFile(state.format);
  if (result.error) {
    $("status").textContent = "Error: " + result.error;
    return;
  }
  state.features = result.features;
  fitView();
  render();
  $("status").textContent =
    "Loaded " + state.format + " — " + state.features.length + " features";
}

$("fmtGeojson").addEventListener("change", () => chooseFormat("global.geo.json"));
$("fmtWkb").addEventListener("change", () => chooseFormat("global.wkb"));

$("toggleBtn").addEventListener("click", () => {
  $("panel").classList.toggle("collapsed");
});

$("openBtn").addEventListener("click", () => $("fileInput").click());
$("fileInput").addEventListener("change", (e) => {
  if (e.target.files.length) openFile(e.target.files[0]);
});

const wrap = $("canvasWrap");
wrap.addEventListener("dragover", (e) => e.preventDefault());
wrap.addEventListener("drop", (e) => {
  e.preventDefault();
  if (e.dataTransfer.files.length) openFile(e.dataTransfer.files[0]);
});

// ---------------------------------------------------------------------------
// Bootstrap: try to load demo.caf (works when served over HTTP); otherwise the
// user opens it via the file picker / drag-and-drop.
// ---------------------------------------------------------------------------
(async () => {
  try {
    const resp = await fetch("demo.caf");
    if (resp.ok) {
      await loadBuffer(await resp.arrayBuffer());
    }
  } catch (_) {
    /* static file:// — wait for user to open the file */
  }
})();
