import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, sign } from "node:crypto";
import { resolve } from "node:path";
import { build } from "esbuild";
import { Miniflare } from "miniflare";

// Synthetic assertions generated outside workerd; the runtime must verify real cryptography.
const fields = {
  auth_date: String(Math.floor(Date.now() / 1000)),
  user: JSON.stringify({ id: 12345, first_name: "Test" }),
};
const canonical = Object.keys(fields)
  .sort()
  .map((key) => `${key}=${fields[key]}`)
  .join("\n");
const token = "123456:test_fixture_only";
const secret = createHmac("sha256", "WebAppData").update(token).digest();
const hmac = createHmac("sha256", secret).update(canonical).digest("hex");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const hex = publicKey
  .export({ type: "spki", format: "der" })
  .subarray(-32)
  .toString("hex");
const signature = sign(
  null,
  Buffer.from(`123456:WebAppData\n${canonical}`),
  privateKey,
).toString("base64url");
const hmacData = new URLSearchParams({ ...fields, hash: hmac }).toString();
const edData = new URLSearchParams({ ...fields, signature }).toString();
const bundled = await build({
  stdin: {
    contents: `
      import { TelegramAuthServer } from './dist/server.js';
      import { z } from 'zod';
      export default { async fetch() {
        const used = new Set();
        const auth = await TelegramAuthServer.create({
          secrets: { jweSecret: 'k'.repeat(32) }, namespace: 'worker-test',
          initDataConfig: { botToken: ${JSON.stringify(token)}, validation: 'either', ed25519PublicKey: ${JSON.stringify(hex)}, singleUse: true, maxAuthDateAgeMs: 60000 },
          replayStore: { async consume(key, expiry) { if (used.has(key) || Date.now() >= expiry) return false; used.add(key); return true; } },
          accessTokenConfig: { ttlMs: 60000, payloadSchema: z.object({ userId: z.string() }) },
          refreshTokenConfig: { ttlMs: 60000, payloadSchema: z.object({ userId: z.string() }), idField: 'userId', skipTokenGroupVerification: true }
        });
        const one = await auth.verifyInitData(${JSON.stringify(edData)});
        const replay = await auth.verifyInitData(${JSON.stringify(hmacData)});
        const hmacAuth = await TelegramAuthServer.create({
          secrets: { jweSecret: 'k'.repeat(32) }, initDataConfig: { botToken: ${JSON.stringify(token)} },
          accessTokenConfig: { ttlMs: 60000 }, refreshTokenConfig: { ttlMs: 60000, payloadSchema: z.object({ userId: z.string() }), idField: 'userId', skipTokenGroupVerification: true }
        });
        const hmacResult = await hmacAuth.verifyInitData(${JSON.stringify(hmacData)});
        const access = await auth.genAccessToken({ userId: 'test-user' });
        const refresh = await auth.genRefreshToken({ userId: 'test-user' });
        return Response.json({ ed25519: one.valid && one.method === 'ed25519', hmac: hmacResult.valid && hmacResult.method === 'hmac', replay: !replay.valid && replay.reason === 'replayed', access: (await auth.verifyAccessToken(access.accessToken)).payload, refresh: (await auth.verifyRefreshToken(refresh.refreshToken)).payload });
      } };
    `,
    resolveDir: resolve(import.meta.dirname, ".."),
    sourcefile: "worker-smoke.ts",
  },
  bundle: true,
  platform: "neutral",
  format: "esm",
  conditions: ["workerd", "import"],
  external: ["node:*"],
  write: false,
});
const worker = new Miniflare({
  modules: true,
  script: bundled.outputFiles[0].text,
  // Compatibility date supported by the workerd bundled with the locked stable Miniflare.
  compatibilityDate: "2026-08-06",
  compatibilityFlags: ["nodejs_compat"],
});
try {
  const response = await worker.dispatchFetch("https://test.example");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ed25519: true,
    hmac: true,
    replay: true,
    access: { userId: "test-user" },
    refresh: { userId: "test-user" },
  });
  console.log(
    "Workers runtime: real HMAC/Ed25519 verification, canonical replay protection, and JWE round trips passed.",
  );
} finally {
  await worker.dispose();
}
