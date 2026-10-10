# First production organization and operator

The CAIAE engine requires an organization and an active user principal before an operator bearer credential can be securely bootstrapped. The demonstration seed command is not suitable for production provisioning.

After deploying the schema using a direct Neon database URL in a one-shot migration, run the guarded provisioning script in a trusted terminal, not a publicly accessible web process.

Required private environment values:

    DATABASE_URL_UNPOOLED=postgresql://...
    CAIAE_BOOTSTRAP_CONFIRM=CREATE_PRODUCTION_TENANT
    CAIAE_BOOTSTRAP_ORG_SLUG=compliance-office
    CAIAE_BOOTSTRAP_ORG_NAME=Compliance Office
    CAIAE_BOOTSTRAP_OPERATOR_NAME=Primary Administrator

Then run:

    npm install
    npm run build
    node scripts/bootstrap-tenant.mjs

The script creates an active organization and active operator principal with a stable internal marker. Re-running it against the same organization is idempotent and does not create another principal. It does **not** grant a role, create a credential or print secrets. An existing inactive org/principal or duplicate marked principals requires manual administrative review.

After provisioning, start the API with a long random CAIAE_BOOTSTRAP_SECRET. Use the authenticated /v1/security/bootstrap endpoint with the newly returned organizationId and principalId, supplying the secret in X-CAIAE-Bootstrap-Secret. Save the returned caiau_ operator credential in a secure password manager: it is shown only once. Remove CAIAE_BOOTSTRAP_SECRET from the API environment after bootstrap, rotate it if exposed, and confirm GET /v1/security/me with the credential succeeds.

Never print the bootstrap secret, bearer credential or database URL to CI logs, issue comments or public chat. Never run this script against the wrong Neon branch or Render workspace. Only production administrators should perform the setup.
