# Dashboard Workflow Architecture

Date: 2026-10-01
Stage: 13 — Dashboard, Metrics & Security Overview

## 1. Core Workflow
- The dashboard is located at `/dashboard` and requires standard `RouteGuard` authentication.
- It consumes `metricsService.getMetrics()` to render 4 primary backend-authoritative counts: `sbom_count`, `proof_count`, `verification_count`, and `certificate_count`.

## 2. API Contract Restraint
- Only the 4 supported metrics are rendered.
- **Vulnerability Snapshot Metrics**, **Policy Status Metrics**, and **Recent Activity Feed** were completely intentionally excluded as they are absent from the `DashboardMetrics` API contract.
- The UI avoids inventing a "Security Score", risk levels, or other derived analytics.

## 3. Query & Cache Architecture
- The page leverages standard React Query fetching and error states matching the established error mapping. 
- State is tied purely to the active token session, deliberately avoiding `?owner_id` URL selectors for multi-tenant hopping.

## 4. UI Layout
- Utilizes the 4-card grid header layout from Shadcn templates.
- Includes a direct Quick Actions navigation hub leveraging Next `Link` components to natively established routes.
