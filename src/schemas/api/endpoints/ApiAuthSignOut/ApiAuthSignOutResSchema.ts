// ApiAuthSignOutResSchema.ts

import { z } from "zod";
import { ApiBaseResSchema } from "../../ApiBaseResSchema.js";

export const ApiAuthSignOutResSchema = ApiBaseResSchema.extend({
  success: z.boolean(),
  // └──TRUE IF SIGNED OUT SUCCESSFULLY
});
