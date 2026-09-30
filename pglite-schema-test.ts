import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";

const schema = await readFile("./schema.sql", "utf8");

const db = new PGlite("./data/pglite-schema-test");

await db.exec(schema);

console.log("SCHEMA_OK");

await db.close();
