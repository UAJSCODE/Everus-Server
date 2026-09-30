import { PGlite } from "@electric-sql/pglite";

const db = new PGlite("./data/pglite-test");

await db.exec("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY);");

console.log("PGLITE_OK");

await db.close();
