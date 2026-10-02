import { z } from "zod";
import {
  ApiAuthAppSessionReqSchema,
  ApiAuthAppSessionResSchema,
  ApiAuthAccessTokenResSchema,
  ApiAuthSignOutReqSchema,
  ApiAuthSignOutResSchema,
  ApiAuthClearCookiesResSchema,
} from "../../schemas.js";
import { callBackend } from "./helpers/callBackend.js";
import type { EndpointSchema, HttpMethod } from "./helpers/callBackend.js";

const paths = {
  appSession: "/api/auth/app-session",
  accessToken: "/api/auth/access-token",
  signOut: "/api/auth/sign-out",
  clearCookies: "/api/auth/clear-cookies",
} as const;
type Endpoint = keyof typeof paths;
const defaults: Record<Endpoint, EndpointSchema> = {
  appSession: {
    req: ApiAuthAppSessionReqSchema,
    res: ApiAuthAppSessionResSchema,
  },
  accessToken: { req: null, res: ApiAuthAccessTokenResSchema },
  signOut: { req: ApiAuthSignOutReqSchema, res: ApiAuthSignOutResSchema },
  clearCookies: { req: null, res: ApiAuthClearCookiesResSchema },
};
const accessFields = z.object({
  accessToken: z.string().min(1),
  accessTokenExpiresAt: z.union([
    z.number().int().nonnegative(),
    z.iso.datetime({ offset: true }).transform((value) => Date.parse(value)),
  ]),
});
const authFields = accessFields.extend({
  refreshTokenExpiresAt: z.union([
    z.number().int().nonnegative(),
    z.iso.datetime({ offset: true }).transform((value) => Date.parse(value)),
  ]),
});
type AccessFields = z.infer<typeof accessFields>;
type AuthFields = z.infer<typeof authFields>;
export type TokenStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;
export interface TelegramWebAppAdapter {
  initData?: string;
}
export type TelegramInitDataProvider = () => string | Promise<string>;
export interface TelegramAuthClientConfigInput {
  baseUrl: string;
  telegram?: TelegramWebAppAdapter;
  initDataProvider?: TelegramInitDataProvider;
  clientVersion?: string;
  urlPaths?: Partial<Record<Endpoint, string>>;
  customSchemas?: Partial<Record<Endpoint, Partial<EndpointSchema> | null>>;
  /** Memory-only by default. Opt in to browser storage only after assessing XSS exposure. */
  storage?: TokenStorage | null;
  storageKey?: string;
  requestTimeoutMs?: number;
  debug?: boolean;
}

/** One application per browser realm. The singleton is never shared with server verification. */
export class TelegramAuthClient {
  private static instance: TelegramAuthClient | null = null;
  private readonly urlPaths: Record<Endpoint, string>;
  private readonly schemas: Record<Endpoint, EndpointSchema>;
  private tokens: Partial<AuthFields> = {};
  private generation = 0;
  private pendingClosures = 0;
  private refreshPromise?: Promise<z.infer<typeof ApiAuthAccessTokenResSchema>>;
  private providerPromise?: Promise<string>;
  private readonly storageKey: string;

  private constructor(private readonly config: TelegramAuthClientConfigInput) {
    const url = new URL(config.baseUrl);
    if (
      !["https:", "http:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      throw new Error(
        "baseUrl must be an HTTP(S) URL without credentials, a query or a fragment",
      );
    if (
      config.initDataProvider !== undefined &&
      typeof config.initDataProvider !== "function"
    )
      throw new Error("initDataProvider must be a function");
    if (config.clientVersion !== undefined && !config.clientVersion.trim())
      throw new Error("clientVersion must not be empty");
    const timeout = config.requestTimeoutMs ?? 15_000;
    if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 120_000)
      throw new Error("requestTimeoutMs must be between 1 and 120000");
    this.urlPaths = { ...paths, ...config.urlPaths };
    this.schemas = { ...defaults };
    for (const endpoint of Object.keys(paths) as Endpoint[]) {
      const override = config.customSchemas?.[endpoint];
      const schema = { ...defaults[endpoint], ...override };
      if (
        typeof schema.res?.safeParse !== "function" ||
        (schema.req !== null && typeof schema.req?.safeParse !== "function")
      )
        throw new Error("Endpoint schemas must be Zod schemas");
      if (!/^\/(?!\/)[^?#]*$/.test(this.urlPaths[endpoint]))
        throw new Error("Endpoint paths must begin with /");
      this.schemas[endpoint] = schema;
    }
    this.storageKey = config.storageKey ?? "telegramAuth.tokens";
    this.restore();
  }

  static init(config: TelegramAuthClientConfigInput): TelegramAuthClient {
    const next = new TelegramAuthClient({
      ...config,
      baseUrl: config.baseUrl.replace(/\/+$/, ""),
    });
    if (this.instance) this.instance.generation++;
    this.instance = next;
    return next;
  }
  static isInitialized(): boolean {
    return this.instance !== null;
  }
  static reset(): void {
    if (this.instance) this.instance.generation++;
    this.instance = null;
  }
  private static get(): TelegramAuthClient {
    if (!this.instance)
      throw new Error(
        "TelegramAuthClient not initialized. Call TelegramAuthClient.init() first.",
      );
    return this.instance;
  }
  static get isAuthenticated(): boolean {
    const { tokens } = this.get();
    return (
      !!tokens.accessToken && (tokens.accessTokenExpiresAt ?? 0) > Date.now()
    );
  }
  static get expectedToBeAuthenticated(): boolean {
    return (this.get().tokens.refreshTokenExpiresAt ?? 0) > Date.now();
  }
  static get hasInitDataProvider(): boolean {
    return typeof this.get().config.initDataProvider === "function";
  }
  private assertCurrent(generation: number): void {
    if (TelegramAuthClient.instance !== this || generation !== this.generation)
      throw new Error("Authentication operation superseded");
    if (this.pendingClosures > 0)
      throw new Error("Session sign-out is in progress");
  }
  private call<T>(
    endpoint: Endpoint,
    method: HttpMethod,
    data?: unknown,
    headers: Record<string, string> = {},
    schemas = this.schemas[endpoint],
  ): Promise<T> {
    return callBackend<T>(
      this.config.baseUrl,
      this.urlPaths[endpoint],
      method,
      schemas,
      data,
      headers,
      this.config.debug,
      this.config.requestTimeoutMs,
    );
  }
  private persist(): void {
    try {
      this.config.storage?.setItem(
        this.storageKey,
        JSON.stringify(this.tokens),
      );
    } catch {
      /* Storage may be unavailable in embedded browsers. Memory remains authoritative. */
    }
  }
  private clear(): void {
    this.generation++;
    this.tokens = {};
    this.refreshPromise = undefined;
    this.providerPromise = undefined;
    try {
      this.config.storage?.removeItem(this.storageKey);
    } catch {
      /* Logout must clear memory even if storage fails. */
    }
  }
  private restore(): void {
    try {
      const raw = this.config.storage?.getItem(this.storageKey);
      if (!raw) return;
      const parsed = authFields.partial().safeParse(JSON.parse(raw));
      if (!parsed.success) throw new Error("Invalid cache");
      const value = parsed.data;
      if (value.accessToken && (value.accessTokenExpiresAt ?? 0) > Date.now())
        this.tokens = {
          accessToken: value.accessToken,
          accessTokenExpiresAt: value.accessTokenExpiresAt,
        };
      if ((value.refreshTokenExpiresAt ?? 0) > Date.now())
        this.tokens.refreshTokenExpiresAt = value.refreshTokenExpiresAt;
      this.persist();
    } catch {
      this.clear();
    }
  }

  static getInitData(explicit?: string): string {
    const client = this.get();
    client.assertCurrent(client.generation);
    const app =
      client.config.telegram ??
      (
        globalThis as typeof globalThis & {
          Telegram?: { WebApp?: TelegramWebAppAdapter };
        }
      ).Telegram?.WebApp;
    return explicit?.trim() || app?.initData?.trim() || "";
  }
  static async resolveInitData(explicit?: string): Promise<string> {
    const client = this.get();
    const generation = client.generation;
    client.assertCurrent(generation);
    const immediate = this.getInitData(explicit);
    if (immediate) return immediate;
    if (!client.config.initDataProvider) return "";
    if (!client.providerPromise)
      client.providerPromise = Promise.resolve()
        .then(() => client.config.initDataProvider!())
        .then((value) => {
          if (typeof value !== "string")
            throw new Error("Init-data provider must return a string");
          return value.trim();
        })
        .catch(() => {
          throw new Error("Init-data provider failed");
        });
    const pending = client.providerPromise;
    try {
      const value = await pending;
      client.assertCurrent(generation);
      return value;
    } finally {
      if (client.providerPromise === pending)
        client.providerPromise = undefined;
    }
  }
  static commitAuth(fields: AuthFields): void {
    const client = this.get();
    client.assertCurrent(client.generation);
    const parsed = authFields.parse(fields);
    if (
      parsed.accessTokenExpiresAt <= Date.now() ||
      parsed.refreshTokenExpiresAt <= Date.now()
    )
      throw new Error("Cannot commit expired credentials");
    client.tokens = parsed;
    client.persist();
  }
  static commitAccess(fields: AccessFields): void {
    const client = this.get();
    client.assertCurrent(client.generation);
    const parsed = accessFields.parse(fields);
    if (parsed.accessTokenExpiresAt <= Date.now())
      throw new Error("Cannot commit expired credentials");
    client.tokens = { ...client.tokens, ...parsed };
    client.persist();
  }

  static async getAppSession<
    TReq extends z.ZodType = typeof ApiAuthAppSessionReqSchema,
    TRes extends z.ZodType = typeof ApiAuthAppSessionResSchema,
  >(
    payload: z.input<TReq> = {} as z.input<TReq>,
    reqSchema?: TReq,
    resSchema?: TRes,
    headers: Record<string, string> = {},
  ): Promise<z.output<TRes>> {
    const client = this.get();
    const generation = client.generation;
    client.assertCurrent(generation);
    if (!payload || typeof payload !== "object" || Array.isArray(payload))
      throw new Error("App-session payload must be an object");
    const input = { ...payload } as Record<string, unknown>;
    if (input.clientVersion === undefined && client.config.clientVersion)
      input.clientVersion = client.config.clientVersion;
    if (input.telegramInitData === undefined) {
      const proof = await this.resolveInitData();
      if (proof) input.telegramInitData = proof;
    }
    client.assertCurrent(generation);
    const response = await client.call<z.output<TRes>>(
      "appSession",
      "POST",
      input,
      headers,
      {
        req: reqSchema ?? client.schemas.appSession.req,
        res: resSchema ?? client.schemas.appSession.res,
      },
    );
    client.assertCurrent(generation);
    const fields = accessFields.safeParse(response);
    if (fields.success) this.commitAccess(fields.data);
    const refresh = authFields.shape.refreshTokenExpiresAt.safeParse(
      Reflect.get(Object(response), "refreshTokenExpiresAt"),
    );
    if (refresh.success && refresh.data > Date.now()) {
      client.tokens.refreshTokenExpiresAt = refresh.data;
      client.persist();
    }
    return response;
  }

  static async getAccessToken<
    TRes extends z.ZodType = typeof ApiAuthAccessTokenResSchema,
  >(
    resSchema?: TRes,
    headers: Record<string, string> = {},
    request?: { payload: unknown; schema: z.ZodType },
  ): Promise<z.output<TRes>> {
    const client = this.get();
    const generation = client.generation;
    client.assertCurrent(generation);
    const response = await client.call<z.output<TRes>>(
      "accessToken",
      "POST",
      request?.payload,
      headers,
      {
        req: request?.schema ?? client.schemas.accessToken.req,
        res: resSchema ?? client.schemas.accessToken.res,
      },
    );
    client.assertCurrent(generation);
    const fields = accessFields.safeParse(response);
    if (fields.success) this.commitAccess(fields.data);
    return response;
  }
  static async getAccessTokenSilently(): Promise<AccessFields> {
    const client = this.get();
    client.assertCurrent(client.generation);
    if (
      client.tokens.accessToken &&
      (client.tokens.accessTokenExpiresAt ?? 0) > Date.now()
    )
      return accessFields.parse(client.tokens);
    delete client.tokens.accessToken;
    delete client.tokens.accessTokenExpiresAt;
    client.persist();
    if (client.refreshPromise) return client.refreshPromise;
    const pending = this.getAccessToken();
    client.refreshPromise = pending;
    try {
      return await pending;
    } finally {
      if (client.refreshPromise === pending) client.refreshPromise = undefined;
    }
  }
  static async signOut(
    options: z.input<typeof ApiAuthSignOutReqSchema> = { signAllOut: true },
  ): Promise<z.infer<typeof ApiAuthSignOutResSchema>> {
    const client = this.get();
    client.clear();
    client.pendingClosures++;
    try {
      return await client.call("signOut", "POST", options);
    } finally {
      client.pendingClosures--;
    }
  }
  static async clearCookies(): Promise<
    z.infer<typeof ApiAuthClearCookiesResSchema>
  > {
    const client = this.get();
    client.clear();
    client.pendingClosures++;
    try {
      return await client.call("clearCookies", "POST");
    } finally {
      client.pendingClosures--;
    }
  }
}
