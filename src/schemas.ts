import { z } from "zod";
import { ApiBaseResSchema } from "./schemas/api/ApiBaseResSchema.js";
export * from "./schemas/api/ApiBaseResSchema.js";
export { ApiAuthSignOutReqSchema } from "./schemas/api/endpoints/ApiAuthSignOut/ApiAuthSignOutReqSchema.js";
export { ApiAuthSignOutResSchema } from "./schemas/api/endpoints/ApiAuthSignOut/ApiAuthSignOutResSchema.js";
export { ApiAuthClearCookiesResSchema } from "./schemas/api/endpoints/ApiAuthClearCookies/ApiAuthClearCookiesResSchema.js";

const expiry = z.union([
  z.number().int().nonnegative(),
  z.iso.datetime({ offset: true }).transform((value) => Date.parse(value)),
]);
export const ApiAuthAppSessionReqSchema = z
  .object({
    clientVersion: z.string().optional(),
    telegramInitData: z.string().max(16384).optional(),
  })
  .passthrough();
export const ApiAuthAccessTokenResSchema = ApiBaseResSchema.extend({
  accessToken: z.string().min(1),
  accessTokenExpiresAt: expiry,
});
export const ApiAuthAppSessionResSchema = ApiAuthAccessTokenResSchema.extend({
  refreshTokenExpiresAt: expiry,
});
