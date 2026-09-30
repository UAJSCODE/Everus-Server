import { mkdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import { Pool } from "pg";

export type Database = {
  query: (sql: string, params?: unknown[]) => Promise<{ rows: any[] }>;
  exec: (sql: string) => Promise<unknown>;
  close: () => Promise<unknown>;
};

export async function openDatabase(dataPath = process.env.DATABASE_PATH ?? "./data/everus-pglite"): Promise<Database> {
  const schema = await readFile(fileURLToPath(new URL("../schema.sql", import.meta.url)), "utf8");
  if (process.env.DATABASE_URL) {
    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    await pool.query(schema);
    return {
      query: (sql, params) => pool.query(sql, params as unknown[]),
      exec: (sql) => pool.query(sql),
      close: () => pool.end(),
    };
  }
  await mkdir(dataPath, { recursive: true });
  const db = new PGlite(dataPath);
  await db.exec(schema);
  return {
    query: (sql, params) => db.query(sql, params),
    exec: (sql) => db.exec(sql),
    close: () => db.close(),
  };
}
