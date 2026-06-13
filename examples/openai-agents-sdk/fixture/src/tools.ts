import { Agent, tool } from "@openai/agents";
import { z } from "zod";

const inventory = {
  widget: 7,
  adapter: 3,
  cable: 11,
} as const;

const itemSchema = z.object({
  item: z.enum(["widget", "adapter", "cable"]),
});

export const getInventoryCount = tool({
  name: "get_inventory_count",
  description: "Return a safe inventory count from static data.",
  parameters: itemSchema,
  execute: ({ item }: z.infer<typeof itemSchema>) => inventory[item],
});

export const supportAgent = new Agent({
  name: "support-agent",
  instructions: "Answer inventory questions using the available tool.",
  tools: [getInventoryCount],
});
