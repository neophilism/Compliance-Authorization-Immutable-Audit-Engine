import assert from "node:assert/strict";
import test from "node:test";
import { validateRecoveryTarget } from "./verify-recovery.mjs";

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
