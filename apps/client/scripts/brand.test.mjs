// node --test scripts/brand.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { assets, checkPng, chunk, decodePng } from "./brand.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const asset = (file) => assets.find((a) => a.file === file);
const icon = asset("assets/images/icon.png");
const foreground = asset("assets/images/android-icon-foreground.png");
const read = (a) => fs.readFileSync(path.join(root, a.file));

// Inserts a chunk right after IHDR (8-byte signature + 25-byte IHDR chunk).
const withChunk = (buf, type, data) => Buffer.concat([buf.subarray(0, 33), chunk(type, data), buf.subarray(33)]);
const rgbKey = (r, g, b) => {
  const d = Buffer.alloc(6);
  [r, g, b].forEach((v, i) => d.writeUInt16BE(v, i * 2));
  return d;
};

test("committed opaque icon passes", () => {
  assert.deepEqual(checkPng(icon, read(icon)), []);
});

test("tRNS on an RGB icon is applied to alpha", () => {
  const png = decodePng(withChunk(read(icon), "tRNS", rgbKey(0x17, 0x17, 0x17)));
  assert.equal(png.type, 2);
  assert.equal(png.rgba[3], 0, "ink background pixel should be transparent");
});

test("tRNS on an RGB icon fails the check", () => {
  const errors = checkPng(icon, withChunk(read(icon), "tRNS", rgbKey(0x17, 0x17, 0x17)));
  assert.ok(errors.some((e) => e.includes("tRNS")), errors.join("\n"));
});

test("tRNS on an RGBA icon fails the check", () => {
  const errors = checkPng(foreground, withChunk(read(foreground), "tRNS", rgbKey(0, 0, 0)));
  assert.ok(errors.some((e) => e.includes("tRNS")), errors.join("\n"));
});
