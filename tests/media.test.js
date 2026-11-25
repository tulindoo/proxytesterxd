import { test } from "node:test";
import assert from "node:assert/strict";
import { rewriteDash, rewritePlaylist, classifyMedia, applyDashMarkers } from "../src/media.js";

const px = (value, base) => {
  try { const u = new URL(value, base); return `/service/${Buffer.from(u.origin + u.pathname).toString("base64url")}${u.search}`; }
  catch { return null; }
};

test("DASH manifest URLs and BaseURL text are proxified", () => {
  const input = '<MPD><BaseURL>video/</BaseURL><SegmentTemplate media="chunk-$Number$.m4s" initialization="init.mp4"/><Location href="https://cdn.example/live.mpd"/></MPD>';
  const out = rewriteDash(input, "https://media.example/path/manifest.mpd", px);
  assert.ok(out.includes("<BaseURL>/service/"));
  assert.ok(out.includes("__pxdash_0=$Number$"));
  assert.ok(out.includes('initialization="/service/'));
});

test("HLS rewrites segment and URI attribute URLs", () => {
  const playlist = '#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI="key.bin"\nseg-1.ts';
  const out = rewritePlaylist(playlist, "https://media.example/live/master.m3u8", px);
  assert.ok(out.includes('URI="/service/'));
  assert.ok(out.includes("/service/"));
  assert.ok(out.includes("#EXTM3U"));
});

test("DASH template markers resolve dynamic path values and retain real query params", () => {
  const template = new URL("https://media.example/seg-$Number$-$RepresentationID$.m4s?token=abc");
  const resolved = applyDashMarkers(template, "?__pxdash_0=42&__pxdash_1=video&quality=hd");
  assert.equal(resolved.pathname, "/seg-42-video.m4s");
  assert.equal(resolved.search, "?token=abc&quality=hd");
});

test("media classification identifies HLS and DASH resources", () => {
  assert.equal(classifyMedia("application/vnd.apple.mpegurl", "/master.m3u8"), "hls");
  assert.equal(classifyMedia("application/dash+xml", "/manifest.mpd"), "dash");
  assert.equal(classifyMedia("application/octet-stream", "/clip.mp4"), null);
});
