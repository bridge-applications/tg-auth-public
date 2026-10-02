// ApiAuthSignOutReqSchema.ts

import { z } from "zod";

export const ApiAuthSignOutReqSchema = z.object({
  signAllOut: z.boolean(),
  // └──IF TRUE, ALL DEVICES WILL BE SIGNED OUT
});
