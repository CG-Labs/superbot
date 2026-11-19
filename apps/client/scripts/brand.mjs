// Renders every SuperBot raster asset from the SVG sources in assets/brand/.
//   npm run brand        regenerate assets (and the web admin favicon)
//   npm run brand:check  verify committed assets match the sources (CI)
import { Resvg } from "@resvg/resvg-js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const brandDir = path.join(root, "assets/brand");
const webIndex = path.resolve(root, "../../web/index.html");

export const palette = {
  ink: "#171717",
  night: "#0d0d0d",
  blue: "#2f72e4",
  sky: "#4b8df8",
  paper: "#ececec",
};

const inner = (file) => {
  const svg = fs.readFileSync(path.join(brandDir, file), "utf8");
  return svg.slice(svg.indexOf(">", svg.indexOf("<svg")) + 1, svg.lastIndexOf("</svg>"));
};
const mark = inner("mark.svg");
const mono = inner("mark-mono.svg");

// Places a 100x100 mark source centered on a w x h canvas at `size` px.
const compose = (w, h, { bg = "", art = mark, size }) =>
  `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">${bg}` +
  `<svg x="${(w - size) / 2}" y="${(h - size) / 2}" width="${size}" height="${size}" viewBox="0 0 100 100">${art}</svg></svg>`;

const solid = (w, h) => `<rect width="${w}" height="${h}" fill="${palette.ink}"/>`;
const tile = (s) => `<rect width="${s}" height="${s}" rx="${s * 0.22}" fill="${palette.ink}"/>`;
const glow = (w, h) =>
  `<defs><radialGradient id="g" cx="50%" cy="50%" r="60%"><stop offset="0" stop-color="#1d2a45"/>` +
  `<stop offset="1" stop-color="${palette.ink}"/></radialGradient></defs><rect width="${w}" height="${h}" fill="url(#g)"/>`;

// Adaptive icons are masked to a 66/108 circle; size 600 keeps the mark inside it.
export const assets = [
  { file: "assets/images/icon.png", w: 1024, h: 1024, alpha: false, svg: compose(1024, 1024, { bg: solid(1024, 1024), size: 760 }) },
  { file: "assets/images/android-icon-foreground.png", w: 1024, h: 1024, alpha: true, svg: compose(1024, 1024, { size: 600 }) },
  { file: "assets/images/android-icon-background.png", w: 1024, h: 1024, alpha: false, svg: compose(1024, 1024, { bg: solid(1024, 1024), art: "", size: 0 }) },
  { file: "assets/images/android-icon-monochrome.png", w: 1024, h: 1024, alpha: true, svg: compose(1024, 1024, { art: mono, size: 600 }) },
  { file: "assets/images/splash-icon.png", w: 1024, h: 1024, alpha: true, svg: compose(1024, 1024, { size: 1024 }) },
  { file: "assets/images/favicon.png", w: 48, h: 48, alpha: true, svg: compose(48, 48, { bg: tile(48), size: 44 }) },
  { file: "assets/brand/store/play-store-icon.png", w: 512, h: 512, alpha: false, svg: compose(512, 512, { bg: solid(512, 512), size: 380 }) },
  { file: "assets/brand/store/feature-graphic.png", w: 1024, h: 500, alpha: false, svg: compose(1024, 500, { bg: glow(1024, 500), size: 400 }) },
];

const faviconSvg = compose(64, 64, { bg: tile(64), size: 58 });
const faviconTag = `<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(faviconSvg)}" /><!-- brand:favicon -->`;

// PNG encode/decode for 8-bit RGB/RGBA, so output does not depend on a native image library.
const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, "ascii");
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
};
const PNG_SIG = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

function encodePng(w, h, rgba, alpha) {
  const ch = alpha ? 4 : 3;
  const raw = Buffer.alloc((w * ch + 1) * h);
  for (let y = 0; y < h; y++) {
    const row = y * (w * ch + 1);
    for (let x = 0; x < w; x++) {
      for (let c = 0; c < ch; c++) raw[row + 1 + x * ch + c] = rgba[(y * w + x) * 4 + c];
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = alpha ? 6 : 2;
  return Buffer.concat([
    PNG_SIG,
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

export function decodePng(buf) {
  if (!buf.subarray(0, 8).equals(PNG_SIG)) throw new Error("not a PNG");
  let off = 8, w = 0, h = 0, type = -1, depth = 0, interlace = 0;
  const idat = [];
  while (off < buf.length) {
    const len = buf.readUInt32BE(off);
    const kind = buf.toString("ascii", off + 4, off + 8);
    const data = buf.subarray(off + 8, off + 8 + len);
    if (kind === "IHDR") [w, h, depth, type, interlace] = [data.readUInt32BE(0), data.readUInt32BE(4), data[8], data[9], data[12]];
    if (kind === "IDAT") idat.push(data);
    off += 12 + len;
  }
  const ch = { 2: 3, 6: 4 }[type];
  if (depth !== 8 || !ch || interlace) return { w, h, type, rgba: null };
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = w * ch;
  const px = Buffer.alloc(stride * h);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)];
    for (let i = 0; i < stride; i++) {
      const v = raw[y * (stride + 1) + 1 + i];
      const a = i >= ch ? px[y * stride + i - ch] : 0;
      const b = y ? px[(y - 1) * stride + i] : 0;
      const c = y && i >= ch ? px[(y - 1) * stride + i - ch] : 0;
      const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
      const pred = [0, a, b, (a + b) >> 1, pa <= pb && pa <= pc ? a : pb <= pc ? b : c][f];
      px[y * stride + i] = (v + pred) & 0xff;
    }
  }
  const rgba = Buffer.alloc(w * h * 4, 255);
  for (let i = 0; i < w * h; i++) for (let c = 0; c < ch; c++) rgba[i * 4 + c] = px[i * ch + c];
  return { w, h, type, rgba };
}

const render = (a) => {
  const img = new Resvg(a.svg, { fitTo: { mode: "original" }, font: { loadSystemFonts: false } }).render();
  if (img.width !== a.w || img.height !== a.h) throw new Error(`${a.file}: rendered ${img.width}x${img.height}`);
  return img.pixels;
};

const withFavicon = (html) => {
  const lines = html.split("\n").filter((l) => !l.includes("<!-- brand:favicon -->"));
  const at = lines.findIndex((l) => l.includes("<title>"));
  lines.splice(at + 1, 0, `  ${faviconTag}`);
  return lines.join("\n");
};

function generate() {
  for (const a of assets) {
    const out = path.join(root, a.file);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, encodePng(a.w, a.h, render(a), a.alpha));
    console.log(`wrote ${a.file} (${a.w}x${a.h}${a.alpha ? ", alpha" : ""})`);
  }
  fs.writeFileSync(webIndex, withFavicon(fs.readFileSync(webIndex, "utf8")));
  console.log("updated web/index.html favicon");
}

// Rasterizers can differ by a rounding step across CPUs, so compare pixels with a small tolerance.
const TOLERANCE = 3;

function check() {
  const errors = [];
  for (const a of assets) {
    const file = path.join(root, a.file);
    if (!fs.existsSync(file)) {
      errors.push(`${a.file}: missing`);
      continue;
    }
    const png = decodePng(fs.readFileSync(file));
    const before = errors.length;
    if (png.w !== a.w || png.h !== a.h) errors.push(`${a.file}: ${png.w}x${png.h}, want ${a.w}x${a.h}`);
    if (png.type !== (a.alpha ? 6 : 2)) errors.push(`${a.file}: PNG color type ${png.type}, want ${a.alpha ? "RGBA (6)" : "RGB (2), no alpha"}`);
    if (!png.rgba || errors.length > before) continue;
    const want = render(a);
    let bad = 0;
    for (let i = 0; i < want.length; i++) {
      if ((a.alpha || i % 4 !== 3) && Math.abs(want[i] - png.rgba[i]) > TOLERANCE) bad++;
    }
    if (bad) errors.push(`${a.file}: ${bad} channel values differ from the SVG source; run npm run brand`);
  }

  const app = JSON.parse(fs.readFileSync(path.join(root, "app.json"), "utf8")).expo;
  const splash = app.plugins.find((p) => Array.isArray(p) && p[0] === "expo-splash-screen")?.[1] ?? {};
  const adaptive = app.android?.adaptiveIcon ?? {};
  const referenced = [app.icon, app.web?.favicon, splash.image, adaptive.foregroundImage, adaptive.backgroundImage, adaptive.monochromeImage];
  for (const ref of referenced) {
    if (!ref) continue;
    if (!assets.some((a) => path.join(root, a.file) === path.join(root, ref))) errors.push(`app.json references ${ref}, which is not generated`);
  }
  for (const [where, color] of [["splash backgroundColor", splash.backgroundColor], ["adaptiveIcon backgroundColor", adaptive.backgroundColor]]) {
    if (color?.toLowerCase() !== palette.ink) errors.push(`app.json ${where} is ${color}, want ${palette.ink}`);
  }

  const html = fs.readFileSync(webIndex, "utf8");
  if (withFavicon(html) !== html) errors.push("web/index.html favicon is out of date; run npm run brand");

  if (errors.length) {
    console.error(errors.map((e) => `brand: ${e}`).join("\n"));
    process.exit(1);
  }
  console.log(`brand: ${assets.length} assets OK (${os.platform()}-${os.arch()})`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.argv.includes("--check") ? check() : generate();
}
