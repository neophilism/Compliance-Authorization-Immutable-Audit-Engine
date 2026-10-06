"use client";

import { FormEvent, useState } from "react";

export default function Home() {
  const [organizationId, setOrganizationId] =
    useState("");

  function submit(event: FormEvent) {
    event.preventDefault();
    const value = organizationId.trim();
    if (!value) return;
    window.location.href =
      `/admin?organizationId=${encodeURIComponent(value)}`;
  }

  return (
    <main className="landing">
      <section className="landing-card">
        <div className="landing-copy">
          <div className="eyebrow">
            Civic Technology Infrastructure
          </div>
          <h1>
            Compliance operations, in one console.
          </h1>
          <p>
            The reference administration interface for declarative
            compliance checks, authorization decisions, evidence,
            statutory clocks, findings, remediation, certifications,
            reporting, and tamper-evident audit history.
          </p>
          <p>
            This UI is deliberately policy-neutral. Bill- or
            program-specific behavior remains in downstream rules,
            schemas, and configuration.
          </p>
        </div>

        <form
          className="landing-enter"
          onSubmit={submit}
        >
          <h2>Open an organization</h2>
          <p>
            Enter the organization UUID used by the engine. The
            console reads and mutates state exclusively through the
            Fastify API.
          </p>
          <input
            className="control"
            aria-label="Organization ID"
            placeholder="Organization UUID"
            value={organizationId}
            onChange={(event) =>
              setOrganizationId(event.target.value)
            }
          />
          <button
            className="button"
            type="submit"
            disabled={!organizationId.trim()}
          >
            Open administration console
          </button>
        </form>
      </section>
    </main>
  );
}
