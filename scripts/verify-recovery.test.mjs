import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateRecoveryTarget, verifyRecovery, readRecoveryInput } from "./verify-recovery.mjs";

test("restored database verification must use a separate direct PostgreSQL endpoint", () => {
  const recovered = "postgresql://reader:other@recovery.db.example/recovered";
  assert.equal(validateRecoveryTarget(recovered, "postgresql://owner:private@prod.db.example/caiae"), recovered);
  for (const url of [
    "postgresql://owner:other@prod.db.example/caiae",
    "postgresql://owner:other@prod.db.example:5432/caiae",
  ]) {
    const source = url.includes(":5432") ?
      "postgresql://owner:secret@prod.db.example:5432/caiae" :
      "postgresql://owner:secret@prod.db.example/caiae";
    assert.throws(() => validateRecoveryTarget(url, source), /must not be the production/);
  }
  assert.throws(() => validateRecoveryTarget("postgresql://user:secret@host-pooler.example/db"), /non-pooled/);
  assert.throws(() => validateRecoveryTarget("https://example.com/db"), /PostgreSQL database/);
  assert.throws(() => validateRecoveryTarget(undefined), /RECOVERY_DATABASE_URL/);
});

test("equivalent source endpoints cannot hide behind ports, case, encoding, pooler or loopback aliases", () => {
  for (const [recovery, source] of [
    ["postgres://reader:x@prod.example:5432/db", "postgresql://owner:y@prod.example/db"],
    ["postgres://reader:x@PROD.EXAMPLE./db", "postgres://owner:y@prod.example/db"],
    ["postgres://reader:x@prod.example/%64b", "postgres://owner:y@prod.example/db"],
    ["postgres://reader:x@ep-123.region.neon.tech/db", "postgres://owner:y@ep-123-pooler.region.neon.tech/db"],
    ["postgres://reader:x@127.0.0.1/db", "postgres://owner:y@localhost:5432/db"],
    ["postgres://reader:x@[::1]/db", "postgres://owner:y@localhost/db"],
  ]) assert.throws(() => validateRecoveryTarget(recovery, source), /must not be the production/);
});

test("rejects parser ambiguity and driver destination overrides without echoing credentials", () => {
  for (const raw of [
    "postgres://reader:DO-NOT-LOG@recovery.example/db?host=prod.example",
    "postgres://reader:x@recovery.example/db?hostaddr=127.0.0.1",
    "postgres://reader:x@recovery.example/db?port=5433",
    "postgres://reader:x@recovery.example/db?database=prod",
    "postgres://reader:x@recovery.example/db?options=-csearch_path=other",
    "postgres://reader:x@recovery.example/db?sslmode=require&sslmode=disable",
    "postgres://reader:x@RECOVERY-POOLER.example/db",
    "postgres://reader:x@recovery.example/db#fragment",
    "postgres://reader:x@recovery.example/%ZZ",
    "postgres://reader:x@recovery.example/db/name",
    "postgres://reader:x@recovery.example/%00db",
    " postgres://reader:x@recovery.example/db",
    "postgres://reader:x@recovery.example\\db",
  ]) assert.throws(() => validateRecoveryTarget(raw), error => {
    assert.equal(error.message.includes("DO-NOT-LOG"), false);
    return true;
  });
  assert.throws(() => validateRecoveryTarget("postgres://r:x@recovery.example/db", "https://prod.example/db"));
  const target = "postgres://r:x@recovery.example/db?sslmode=require&application_name=recovery";
  assert.equal(validateRecoveryTarget(target, "postgres://r:y@prod.example/db"), target);
});

function transactionFixture({ signature = true, mode = "on", schema = true,
  anchored = { valid: true, checkedChains: 1 }, collectError = false, counts,
  failQuery, failRollback = false, failConnect = false } = {}) {
  const calls = [];
  let connected = 0;
  let released = [];
  const client = {
    query: async sql => {
      calls.push(sql);
      if ((failQuery && sql.startsWith(failQuery)) || (failRollback && sql === "ROLLBACK")) {
        throw new Error("private-provider-error postgresql://secret:DO-NOT-LOG@host/db");
      }
      if (sql.includes("current_setting")) return { rows: [{ isolation: "repeatable read", read_only: mode }] };
      if (sql.includes("schema_migrations")) return { rows: [{ current: schema }] };
      if (sql.includes("count(*)")) return { rows: [counts ?? { organizations: 2, resources: 3, audit_events: 4 }] };
      return { rows: [] };
    },
    release: discard => { released.push(discard); },
  };
  const database = {
    LATEST_SCHEMA_VERSION: "0014_worker_activity",
    verifyAuditCheckpointSignature: () => signature,
    verifyAuditCheckpointAgainstDatabaseWithClient: async received => {
      assert.equal(received, client); calls.push("ANCHOR"); return anchored;
    },
    collectAuditCheckpointWithClient: async received => {
      assert.equal(received, client); calls.push("ALL_CHAINS");
      if (collectError) throw new Error("private-provider-error");
      return { chainHeads: [{}] };
    },
  };
  const pool = { query: () => { throw new Error("pool.query is forbidden inside recovery verification"); },
    connect: async () => { connected++; if (failConnect) throw new Error("DO-NOT-LOG"); return client; } };
  return { pool, database, calls, get connected() { return connected; }, get released() { return released; } };
}
const checkpoint = { checkpoint: { chainHeads: [{}] } };

test("transaction wiring fixture uses one verified read-only snapshot and emits only explicit counts", async () => {
  const fixture = transactionFixture({ counts: { organizations: 2, resources: 3, audit_events: 4, secret: "DO-NOT-LOG" } });
  const report = await verifyRecovery(fixture.pool, checkpoint, "synthetic-public-key", { database: fixture.database });
  assert.equal(fixture.connected, 1);
  assert.deepEqual(fixture.released, [false]);
  assert.equal(fixture.calls[0], "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  assert.equal(fixture.calls.at(-1), "COMMIT");
  assert.equal(fixture.calls.filter(sql => sql.startsWith("BEGIN")).length, 1);
  assert.equal(fixture.calls.filter(sql => sql === "COMMIT").length, 1);
  assert.ok(fixture.calls.indexOf("ANCHOR") < fixture.calls.indexOf("ALL_CHAINS"));
  assert.ok(fixture.calls.some(sql => sql.includes("statement_timeout")));
  assert.deepEqual(report, { schemaVersion: "0014_worker_activity", anchoredChainsVerified: 1,
    allRestoredChainsVerified: 1, organizations: 2, resources: 3, audit_events: 4,
    snapshotIsolation: "repeatable read", readOnly: true });
});

test("invalid/empty external anchors fail before connecting", async () => {
  for (const supplied of [null, {}, { checkpoint: { chainHeads: [] } }]) {
    const fixture = transactionFixture();
    await assert.rejects(verifyRecovery(fixture.pool, supplied, "key", { database: fixture.database }));
    assert.equal(fixture.connected, 0);
  }
  const fixture = transactionFixture({ signature: false });
  await assert.rejects(verifyRecovery(fixture.pool, checkpoint, "key", { database: fixture.database }), /signature/);
  assert.equal(fixture.connected, 0);
});

for (const [name, options] of [
  ["read/write transaction", { mode: "off" }], ["schema mismatch", { schema: false }],
  ["bad anchor", { anchored: { valid: false, checkedChains: 0 } }],
  ["partial anchor", { anchored: { valid: true, checkedChains: 0 } }],
  ["chain scan failure", { collectError: true }],
  ["invalid counts", { counts: { organizations: 1, resources: -1, audit_events: 3 } }],
  ["query failure", { failQuery: "SELECT EXISTS" }],
  ["commit failure", { failQuery: "COMMIT" }],
]) test("recovery " + name + " rolls back and never emits a report", async () => {
  const fixture = transactionFixture(options);
  await assert.rejects(verifyRecovery(fixture.pool, checkpoint, "key", { database: fixture.database }), error => {
    assert.equal(error.message.includes("private-provider-error"), false);
    assert.equal(error.message.includes("DO-NOT-LOG"), false);
    assert.equal(error.cause, undefined);
    return true;
  });
  assert.equal(fixture.calls.at(-1), "ROLLBACK");
  assert.deepEqual(fixture.released, [false]);
});

test("failed rollback discards the client and connection errors remain secret-free", async () => {
  const fixture = transactionFixture({ collectError: true, failRollback: true });
  await assert.rejects(verifyRecovery(fixture.pool, checkpoint, "key", { database: fixture.database }));
  assert.deepEqual(fixture.released, [true]);
  const failed = transactionFixture({ failConnect: true });
  await assert.rejects(verifyRecovery(failed.pool, checkpoint, "key", { database: failed.database }), /snapshot verification failed/);
  assert.deepEqual(failed.released, []);
});

test("external input files are regular, byte-bounded, UTF8 and do not leak paths", async t => {
  const directory = await mkdtemp(join(tmpdir(), "caiae-recovery-fixture-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, "synthetic-checkpoint.json");
  await writeFile(file, "{}");
  assert.equal(await readRecoveryInput(file, 2), "{}");
  await assert.rejects(readRecoveryInput(file, 1), /bounded UTF-8/);
  await writeFile(file, new Uint8Array([0xff]));
  await assert.rejects(readRecoveryInput(file, 5), /bounded UTF-8/);
  await assert.rejects(readRecoveryInput(directory, 5), /bounded UTF-8/);
  await assert.rejects(readRecoveryInput(join(directory, "DO-NOT-LOG"), 5), error => {
    assert.equal(error.message.includes("DO-NOT-LOG"), false); return true;
  });
  await assert.rejects(readRecoveryInput(file, Infinity), /byte limit/);
});

