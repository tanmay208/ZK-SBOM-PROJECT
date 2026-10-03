# Stage 3 Product Acceptance Criteria

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## Acceptance Criteria

Stage 3 is considered complete ONLY if all of the following are true:

1. **Actors Documented:** `unauthenticated`, `vendor`, `admin`, `auditor` capabilities and restrictions are explicitly mapped.
2. **Capabilities Documented:** Every frontend capability is traced to a supported backend API. Unsupported features are explicitly marked.
3. **Route Inventory:** Exhaustive list of all pages, URLs, and states.
4. **Route Access:** A definitive matrix dictates exactly who can access what, and how the frontend reacts to 401/403.
5. **User Journeys:** Core operational flows (login to certificate viewing) are documented step-by-step.
6. **Action/API Map:** Every UI action has a defined HTTP method and endpoint.
7. **States Documented:** Loading, empty, success, and complex domain states (e.g., `assembling_witness`, `public_input_mismatch`) have defined UX behavior.
8. **Crypto Workflow Contract:** The rules for proof generation, verification, and certificates explicitly forbid client-side trust assumptions.
9. **Admin/Auditor Workflows:** Role-specific boundaries are documented without inventing new backend capabilities.
10. **Data Visibility:** Strict categorization of data into private, owner-only, role-restricted, and public tiers.
11. **Security UX Constraints:** The 16 core security UX rules are frozen.
12. **Responsive Requirements:** Behavioral UI changes for mobile/tablet are defined.
13. **Edge Cases:** API failure modes (400, 401, 403, 404, 413, 422) are mapped to UI behavior.
14. **No Source Code Modified:** The frontend and backend codebase remains completely untouched.
15. **No Hallucinations:** No APIs, database tables (e.g., audit logs), or tenant structures were invented.

If any of these criteria fail, the Stage 3 completion matrix cannot be marked as PASS.
