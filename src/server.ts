import { openDatabase } from "./db.ts";
import { createApp } from "./app.ts";

const db = await openDatabase();
const { app } = await createApp({ db });
const host = process.env.HOST ?? "0.0.0.0";
const port = Number(process.env.PORT ?? 8080);
await app.listen({ host, port });
app.log.info({ event: "SERVER_LISTENING", host, port });

const shutdown = async () => {
  await app.close();
  await db.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
