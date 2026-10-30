export function transactionSync(db, action) {
  if (typeof db.transactionSync === 'function') return db.transactionSync(action);
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = action();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}
