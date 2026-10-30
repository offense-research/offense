// Exposes the small node:sqlite surface used by Purple over a SQLite-backed
// Durable Object. Calls are synchronous, as in DatabaseSync.
export class DurableSqlite {
  constructor(storage) {
    this.storage = storage;
    this.sql = storage.sql;
  }

  transactionSync(action) {
    return this.storage.transactionSync(action);
  }

  prepare(query) {
    const sql = this.sql;
    return {
      get(...values) {
        return sql.exec(query, ...values).toArray()[0];
      },
      all(...values) {
        return sql.exec(query, ...values).toArray();
      },
      run(...values) {
        const cursor = sql.exec(query, ...values);
        // Cloudflare's cursor rowsWritten counts storage work, including index
        // rows. SQLite changes() matches DatabaseSync's statement changes.
        cursor.toArray();
        const changes = sql.exec('SELECT changes() AS count').one().count;
        const lastInsertRowid = sql.exec('SELECT last_insert_rowid() AS id').one().id;
        return { changes, lastInsertRowid };
      }
    };
  }

  exec(query) {
    // Durable Object SQL disallows BEGIN/COMMIT. Consecutive synchronous
    // storage operations are atomic in a single input event.
    if (/^(?:BEGIN(?: IMMEDIATE)?|COMMIT|ROLLBACK)\s*;?$/i.test(query.trim())) return;
    this.sql.exec(query).toArray();
  }
}
