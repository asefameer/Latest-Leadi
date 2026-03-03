# App B Azure Setup (Isolated)

This repository is App B only. It must remain operationally isolated from Infinity.

## Deployment Workflow

- Workflow file: `.github/workflows/azure-deploy-app-b.yml`
- Triggered on pushes to App B code paths and manual dispatch.
- Deploys a single Azure Web App package from `server/`.
- Frontend build output (`dist/`) is copied into `server/public/` and served by Express.

## Required Azure Resources (App B)

Use App-B-specific resources and names:

- Azure Web App: `leadi-portal-app-prod-001`
- Resource group: `rg-portal-app-prod` (can be moved to a dedicated RG later)
- Optional custom domain: App B domain only

> Important: Do not share App B credentials, auth secrets, or data stores with Infinity.

## Required GitHub Secrets (App B repo)

Configure these in **Settings > Secrets and variables > Actions**:

- `N8N_WEBHOOK_URL` (required for chatbot API)
- `VITE_CHATBOT_BACKEND_URL` (frontend API base URL)
  - Recommended value for same-host deployment:
    - `https://leadi-portal-app-prod-001.azurewebsites.net`
- `CORS_ORIGIN` (optional, for stricter CORS)

## OIDC / Azure Login

Workflow uses OIDC with these env values:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`

If these differ for App B, update values in workflow env block.

## First Deployment Checklist

1. Ensure Web App `leadi-portal-app-prod-001` exists.
2. Ensure OIDC federated credential is configured for this GitHub repo.
3. Add required GitHub secrets listed above.
4. Push to `main` or run workflow manually.
5. Verify:
   - `https://leadi-portal-app-prod-001.azurewebsites.net/`
   - `https://leadi-portal-app-prod-001.azurewebsites.net/health`

## Isolation Guardrails

- Keep App B CI/CD in this repo only.
- Keep App B domain and SSL separate from Infinity.
- Keep App B telemetry/logging separated where possible.
- Never copy Infinity secrets into this repository.
