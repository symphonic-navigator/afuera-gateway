import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";

const app = Fastify();
await app.register(rateLimit, { global: true, max: 1000, timeWindow: "1 minute" });
app.get("/strict", { config: { rateLimit: { max: 2, timeWindow: "1 minute" } } }, async () => ({ ok: true }));
const codes = [];
for (let i = 0; i < 4; i++) codes.push((await app.inject({ url: "/strict" })).statusCode);
console.log("await-register:", codes);

const app2 = Fastify();
void app2.register(rateLimit, { global: true, max: 1000, timeWindow: "1 minute" });
app2.get("/strict", { config: { rateLimit: { max: 2, timeWindow: "1 minute" } } }, async () => ({ ok: true }));
const codes2 = [];
for (let i = 0; i < 4; i++) codes2.push((await app2.inject({ url: "/strict" })).statusCode);
console.log("void-register:", codes2);
