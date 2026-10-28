# Stage 13 Acceptance Criteria

Date: 2026-10-01
Stage: 13 — Dashboard, Metrics & Security Overview

## Criteria

1. **Dashboard Route**: `/dashboard` acts as the verified authenticated landing zone.
2. **Metrics Fetching**: `metricsService.getMetrics()` successfully maps UI state to `DashboardMetrics` array interface.
3. **Intentional Boundary Discrepancies Handled**: `Vulnerabilities`, `Policies`, and `Recent Activity` missing from the endpoint are intentionally NOT derived or simulated locally to preserve strict backend compliance.
4. **Card UI**: 4 specific shadcn metrics cards represent the total lifecycle steps available.
5. **Loading Resiliency**: UI skeleton prevents visual glitches and "0" flickering while metrics load.
6. **No Arbitrary Analytics**: The application strictly refuses to generate or derive abstract risk assessments, scores, or claims.
7. **Role Visibility**: User token defines contextual authority naturally.
8. **Navigation Hub**: 4 static "Quick Actions" logically dispatch users deeper into the app.
