# MailTrace AI frontend

The Next.js SOC workspace uses authenticated same-origin `/api` requests to the FastAPI backend. See the [project README](../README.md) for local setup, administrator provisioning, model training, integration configuration, and Docker deployment.

Run `npm ci` and `BACKEND_URL=http://127.0.0.1:8000 npm run dev` from this directory after starting the backend.

Pages and layouts use the Next.js App Router in `src/app/`. Shared views are in `src/components/`, the HTTP client in `src/services/api.ts`, the polling hook in `src/hooks/useLoad.ts`, and shared user types in `src/types/user.ts`. The `@/` alias resolves to `src/`. Public assets stay in `public/` as required by Next.js.

Run `npm test`, `npm run lint`, and `npm run build -- --webpack` for regression checks. Delete the generated `.next/` cache once when switching from the old root `app/` route layout to this `src/` layout.
