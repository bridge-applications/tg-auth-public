import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
await mkdir(join(root, ".package-check"), { recursive: true });
const consumer = await mkdtemp(join(root, ".package-check/consumer-"));
try {
  const [packed] = JSON.parse(
    execFileSync(
      "npm",
      [
        "pack",
        "--ignore-scripts",
        "--json",
        "--cache",
        join(consumer, ".npm-cache"),
        "--pack-destination",
        consumer,
      ],
      { cwd: root, encoding: "utf8" },
    ),
  );
  for (const required of [
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "docs/migration.md",
    "dist/client.js",
    "dist/server.js",
    "dist/schemas.js",
  ])
    assert(
      packed.files.some((file) => file.path === required),
      `Missing packed file: ${required}`,
    );
  for (const file of packed.files) {
    assert(
      !/\.env|\.DS_Store|GeoLite|repomix|archive\/|_temp|tests\/|node_modules\//.test(
        file.path,
      ),
      `Unexpected packed file: ${file.path}`,
    );
  }
  const packageDir = join(
    consumer,
    "node_modules/@bridge-applications/tg-auth",
  );
  await mkdir(packageDir, { recursive: true });
  execFileSync("tar", [
    "-xzf",
    join(consumer, packed.filename),
    "--strip-components=1",
    "-C",
    packageDir,
  ]);
  await writeFile(
    join(consumer, "package.json"),
    JSON.stringify({ type: "module" }),
  );
  await writeFile(
    join(consumer, "smoke.mjs"),
    `
    import assert from 'node:assert/strict';
    import { z } from 'zod';
    import { TelegramAuthServer } from '@bridge-applications/tg-auth/server';
    import { TelegramAuthClient } from '@bridge-applications/tg-auth/client';
    import { ApiStatus } from '@bridge-applications/tg-auth/schemas';
    import * as root from '@bridge-applications/tg-auth';
    assert.equal(root.TelegramAuthServer, TelegramAuthServer);
    assert.equal(ApiStatus.SUCCESS, 'SUCCESS');
    TelegramAuthClient.init({ baseUrl: 'https://app.example', telegram: { initData: '' } });
    const auth = await TelegramAuthServer.create({ secrets: { jweSecret: 'k'.repeat(32) }, initDataConfig: { botId: 123456, validation: 'ed25519' }, accessTokenConfig: { ttlMs: 1000 }, refreshTokenConfig: { ttlMs: 1000, payloadSchema: z.object({ userId: z.string() }), idField: 'userId', skipTokenGroupVerification: true } });
    const { accessToken } = await auth.genAccessToken();
    assert.equal((await auth.verifyAccessToken(accessToken)).payload, null);
  `,
  );
  execFileSync(process.execPath, [join(consumer, "smoke.mjs")], {
    cwd: consumer,
    stdio: "inherit",
  });
  await writeFile(
    join(consumer, "consumer.ts"),
    `
    import { z } from 'zod';
    import { TelegramAuthServer } from '@bridge-applications/tg-auth/server';
    import { TelegramAuthClient, type TelegramWebAppAdapter } from '@bridge-applications/tg-auth/client';
    const adapter: TelegramWebAppAdapter = { initData: 'signed-data' };
    TelegramAuthClient.init({ baseUrl: 'https://app.example', telegram: adapter });
    const auth = await TelegramAuthServer.create({ secrets: { jweSecret: 'k'.repeat(32) }, initDataConfig: { botId: 123456, validation: 'ed25519' }, accessTokenConfig: { ttlMs: 1000, payloadSchema: z.object({ userId: z.string() }) }, refreshTokenConfig: { ttlMs: 1000, payloadSchema: z.object({ userId: z.string() }), idField: 'userId', skipTokenGroupVerification: true } });
    const verified = await auth.verifyAccessToken('test');
    const userId: string | undefined = verified.payload?.userId;
    void userId;
    // @ts-expect-error Output types must not erase schema validation.
    const invalid: number = verified.payload?.userId;
    void invalid;
  `,
  );
  for (const [module, resolution] of [
    ["NodeNext", "NodeNext"],
    ["ESNext", "Bundler"],
  ]) {
    execFileSync(
      process.execPath,
      [
        join(root, "node_modules/typescript/bin/tsc"),
        "--noEmit",
        "--strict",
        "--skipLibCheck",
        "--target",
        "ES2022",
        "--module",
        module,
        "--moduleResolution",
        resolution,
        join(consumer, "consumer.ts"),
      ],
      { cwd: consumer, stdio: "inherit" },
    );
  }
  await writeFile(
    join(consumer, "browser.mjs"),
    `export { TelegramAuthClient } from '@bridge-applications/tg-auth/client';`,
  );
  const bundled = await build({
    entryPoints: [join(consumer, "browser.mjs")],
    bundle: true,
    platform: "browser",
    format: "esm",
    write: false,
    metafile: true,
  });
  const inputs = Object.keys(bundled.metafile.inputs);
  assert(
    !inputs.some((file) =>
      /logic\/server|@upstash|\bjose\b|@worldcoin|\bviem\b/.test(file),
    ),
    "Browser entry contains server dependencies",
  );
  assert(
    (await readFile(join(packageDir, "package.json"), "utf8")).includes(
      "github.com/bridge-applications/tg-auth-public",
    ),
  );
  console.log(
    `Packed ESM imports, NodeNext/Bundler types, and browser isolation passed (${packed.files.length} published files).`,
  );
} finally {
  await rm(consumer, { recursive: true, force: true });
}
