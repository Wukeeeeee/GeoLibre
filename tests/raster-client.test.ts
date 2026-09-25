import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  aspect,
  clipByExtent,
  focalStatistics,
  hillshade,
  parseReclassTable,
  rasterCalc,
  readRasterData,
  reclassify,
  runRasterToolClient,
  slope,
  supportsClientRaster,
  writeRasterBands,
  TERRAIN_NODATA,
  type RasterData,
} from "@geolibre/processing";

/** Build a small in-memory raster for tests (top-left origin, 1-unit pixels). */
function makeRaster(
  bands: number[][],
  width: number,
  height: number,
  overrides: Partial<RasterData> = {},
): RasterData {
  return {
    bands: bands.map((b) => Float32Array.from(b)),
    width,
    height,
    originX: 0,
    originY: height, // top edge
    resX: 1,
    resY: 1,
    nodata: null,
    geoKeys: { GTModelTypeGeoKey: 2, GeographicTypeGeoKey: 4326 },
    ...overrides,
  };
}

describe("raster-client compute", () => {
  it("reports which tools have a client implementation", () => {
    assert.equal(supportsClientRaster("hillshade"), true);
    assert.equal(supportsClientRaster("focal"), true);
    assert.equal(supportsClientRaster("polygonize"), false);
    assert.equal(supportsClientRaster("reproject"), false);
  });

  it("parses reclassify rule tables with min/max bounds", () => {
    const rules = parseReclassTable("0:10:1, 10:max:2");
    assert.deepEqual(rules, [
      { min: 0, max: 10, value: 1 },
      { min: 10, max: Infinity, value: 2 },
    ]);
    assert.throws(() => parseReclassTable("bad"));
    assert.throws(() => parseReclassTable(""));
  });

  it("reclassifies values into half-open ranges", () => {
    const raster = makeRaster([[5, 10, 15, 25]], 4, 1);
    const out = reclassify(raster, { table: "0:10:1, 10:20:2", unmatched: "nodata" });
    // 5 -> 1, 10 -> 2 (half-open [10,20)), 15 -> 2, 25 -> unmatched (nodata)
    assert.equal(out.bands[0][0], 1);
    assert.equal(out.bands[0][1], 2);
    assert.equal(out.bands[0][2], 2);
    assert.equal(out.bands[0][3], TERRAIN_NODATA);
  });

  it("keeps original values for unmatched cells when requested", () => {
    const raster = makeRaster([[5, 99]], 2, 1);
    const out = reclassify(raster, { table: "0:10:1", unmatched: "original" });
    assert.equal(out.bands[0][0], 1);
    assert.equal(out.bands[0][1], 99);
  });

  it("computes zero slope on a flat surface", () => {
    const flat = makeRaster([Array(9).fill(7)], 3, 3);
    const out = slope(flat, { units: "degrees" });
    // The single interior pixel of a flat 3x3 has zero gradient.
    assert.equal(out.bands[0][4], 0);
  });

  it("computes a non-zero slope on an inclined surface", () => {
    // West-to-east ramp on a projected (metres) raster: each column one metre
    // higher than the last, so the gradient is exactly 1:1.
    const ramp = makeRaster([[0, 1, 2, 0, 1, 2, 0, 1, 2]], 3, 3, {
      geoKeys: { GTModelTypeGeoKey: 1, ProjectedCSTypeGeoKey: 32650 },
    });
    const deg = slope(ramp, { units: "degrees" }).bands[0][4];
    assert.ok(Math.abs(deg - 45) < 1e-9);
    // A 1:1 (45 degree-ish) gradient: percent form is gradient * 100.
    const pct = slope(ramp, { units: "percent" }).bands[0][4];
    assert.ok(Math.abs(pct - 100) < 1e-6);
  });

  it("scales gradients to metres for geographic-CRS (4326) DEMs", () => {
    // A 10 m rise per pixel on a ~30.87 m ground grid near the equator (a ~32%
    // grade, atan(10/30.87) ~ 17.9 deg). The cell size arrives in degrees
    // (30.87 / 111320), which the engine used to divide as if they were
    // metres, saturating the slope at 90 deg.
    const resDeg = 30.87 / 111320;
    const ramp = makeRaster([[0, 10, 20, 0, 10, 20, 0, 10, 20]], 3, 3, {
      resX: resDeg,
      resY: resDeg,
      originY: resDeg * 3, // top (northern) edge, so mid-latitude ~ equator
    });
    const deg = slope(ramp, { units: "degrees" }).bands[0][4];
    assert.ok(Math.abs(deg - (Math.atan(10 / 30.87) * 180) / Math.PI) < 0.01);
    const pct = slope(ramp, { units: "percent" }).bands[0][4];
    assert.ok(Math.abs(pct - (10 / 30.87) * 100) < 0.01);
  });

  it("does not skew east-west gradients at high latitude", () => {
    // Same 10 m rise per pixel in both axes at 60 N, where one degree of
    // longitude spans only ~55.7 km. Equal metre gradients must give equal
    // axis gradients (slope atan(sqrt(2) * 10/30.87) ~ 24.6 deg, downhill
    // toward north-west, aspect 315) instead of the ~1/cos(lat) skew toward
    // north-south that raw degree divisions produced.
    const resYDeg = 30.87 / 111320;
    const resXDeg = resYDeg / Math.cos((60 * Math.PI) / 180);
    const ramp = makeRaster([[0, 10, 20, 10, 20, 30, 20, 30, 40]], 3, 3, {
      resX: resXDeg,
      resY: resYDeg,
      originY: 60 + resYDeg * 3, // top edge just north of 60 N
    });
    const deg = slope(ramp, { units: "degrees" }).bands[0][4];
    assert.ok(Math.abs(deg - (Math.atan(Math.sqrt(2) * (10 / 30.87)) * 180) / Math.PI) < 0.05);
    const asp = aspect(ramp).bands[0][4];
    assert.ok(Math.abs(asp - 315) < 0.05);
  });

  it("computes hillshade within 0-255 and aspect within range", () => {
    const ramp = makeRaster([[0, 1, 2, 0, 1, 2, 0, 1, 2]], 3, 3);
    const hs = hillshade(ramp, { azimuth: 315, altitude: 45, z_factor: 1 }).bands[0][4];
    assert.ok(hs >= 0 && hs <= 255);
    const asp = aspect(ramp).bands[0][4];
    assert.ok(asp >= 0 && asp <= 360);
  });

  it("emits NoData (not -1) for flat aspect cells", () => {
    const flat = makeRaster([Array(9).fill(7)], 3, 3);
    assert.equal(aspect(flat).bands[0][4], TERRAIN_NODATA);
  });

  it("computes correct aspect for north-south slopes", () => {
    // Top row (north) highest -> steepest descent points south -> aspect 180.
    const northHigh = makeRaster([[9, 9, 9, 5, 5, 5, 1, 1, 1]], 3, 3);
    assert.equal(aspect(northHigh).bands[0][4], 180);
    // Bottom row (south) highest -> descent points north -> aspect 0/360.
    const southHigh = makeRaster([[1, 1, 1, 5, 5, 5, 9, 9, 9]], 3, 3);
    const a = aspect(southHigh).bands[0][4];
    assert.ok(a === 0 || a === 360);
  });

  it("clips to a sub-window in CRS coordinates", () => {
    // 4x4 raster, values = row*4 + col, origin (0,4), 1-unit pixels.
    const values = Array.from({ length: 16 }, (_, i) => i);
    const raster = makeRaster([values], 4, 4);
    const clip = clipByExtent(raster, { minx: 1, miny: 1, maxx: 3, maxy: 3 });
    assert.equal(clip.width, 2);
    assert.equal(clip.height, 2);
    assert.equal(clip.originX, 1);
    assert.equal(clip.originY, 3);
    assert.throws(() => clipByExtent(raster, { minx: 10, miny: 10, maxx: 20, maxy: 20 }));
  });

  it("evaluates single-input band math (NDVI)", () => {
    // Two bands: A1 (red), A2 (nir).
    const raster = makeRaster(
      [
        [1, 2],
        [3, 6],
      ],
      2,
      1,
    );
    const out = rasterCalc(raster, { expression: "(A2 - A1) / (A2 + A1)" });
    assert.ok(Math.abs(out.bands[0][0] - (3 - 1) / (3 + 1)) < 1e-6);
    assert.ok(Math.abs(out.bands[0][1] - (6 - 2) / (6 + 2)) < 1e-6);
  });

  it("converts comparison results to a numeric raster mask", () => {
    const raster = makeRaster([[100, 200, 201, 300]], 4, 1);
    const out = rasterCalc(raster, { expression: "A > 200" });
    assert.deepEqual([...out.bands[0]], [0, 0, 1, 1]);
  });

  it("rejects multi-raster references in client band math", () => {
    const raster = makeRaster([[1, 2]], 2, 1);
    assert.throws(() => rasterCalc(raster, { expression: "A + B" }), /single input/);
  });

  it("rejects expressions that reach browser globals", () => {
    const raster = makeRaster([[1, 2]], 2, 1);
    assert.throws(
      () => rasterCalc(raster, { expression: "A + fetch('x')" }),
      /unsupported identifiers/,
    );
    assert.throws(
      () => rasterCalc(raster, { expression: "globalThis" }),
      /unsupported identifiers/,
    );
    // Letter-free "JSFuck"-style payloads must be blocked by the char allowlist.
    assert.throws(() => rasterCalc(raster, { expression: "[]+[]" }), /unsupported characters/);
  });

  it("allows numeric literals including scientific notation", () => {
    const raster = makeRaster([[1, 2]], 2, 1);
    const out = rasterCalc(raster, { expression: "A * 1e3 + 0.5" });
    assert.equal(out.bands[0][0], 1 * 1e3 + 0.5);
    assert.equal(out.bands[0][1], 2 * 1e3 + 0.5);
  });

  it("computes a focal mean over a neighbourhood", () => {
    const raster = makeRaster([[1, 2, 3, 4, 5, 6, 7, 8, 9]], 3, 3);
    const out = focalStatistics(raster, { statistic: "mean", size: 3 });
    // Centre pixel mean of all nine values is 5.
    assert.equal(out.bands[0][4], 5);
  });

  it("propagates NoData through compute", () => {
    const raster = makeRaster([[1, -9999, 3, 4]], 4, 1, { nodata: -9999 });
    const out = reclassify(raster, { table: "0:100:1" });
    assert.equal(out.bands[0][1], -9999);
  });
});

describe("raster-client GeoTIFF round-trip", () => {
  it("writes and reads back a single-band raster preserving geo info", async () => {
    const raster = makeRaster([[1, 2, 3, 4, 5, 6]], 3, 2, {
      originX: 100,
      originY: 200,
      resX: 10,
      resY: 5,
      nodata: -1,
    });
    const bytes = writeRasterBands(raster);
    const back = await readRasterData(bytes);
    assert.equal(back.width, 3);
    assert.equal(back.height, 2);
    assert.equal(back.originX, 100);
    assert.equal(back.originY, 200);
    assert.equal(back.resX, 10);
    assert.equal(back.resY, 5);
    assert.equal(back.nodata, -1);
    assert.deepEqual(Array.from(back.bands[0]), [1, 2, 3, 4, 5, 6]);
  });

  it("writes and reads back a multi-band raster with correct interleaving", async () => {
    const raster = makeRaster(
      [
        [1, 2, 3, 4],
        [10, 20, 30, 40],
      ],
      2,
      2,
    );
    const back = await readRasterData(writeRasterBands(raster));
    assert.equal(back.bands.length, 2);
    assert.deepEqual(Array.from(back.bands[0]), [1, 2, 3, 4]);
    assert.deepEqual(Array.from(back.bands[1]), [10, 20, 30, 40]);
  });

  it("runs a tool end-to-end via the dispatcher and yields renderable bytes", async () => {
    const raster = makeRaster([[0, 1, 2, 0, 1, 2, 0, 1, 2]], 3, 3);
    const { bytes, messages } = runRasterToolClient("slope", raster, {
      units: "percent",
      z_factor: 1,
    });
    assert.ok(messages.length >= 2);
    const back = await readRasterData(bytes);
    assert.equal(back.width, 3);
    assert.equal(back.height, 3);
    // Verify semantic content, not just shape: the encoded slope carries the
    // terrain NoData and the interior pixel has a real (>0) slope.
    assert.equal(back.nodata, TERRAIN_NODATA);
    assert.ok(back.bands[0][4] > 0);
  });
});
