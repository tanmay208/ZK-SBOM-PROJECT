# Design State Specification

Date: 2026-10-01
Stage: 4 — Design System, Visual Language & UI Semantics Freeze

## 1. Global UI States
- **Loading:** Used during initial API fetches. 
  - *Visuals:* Gray skeleton loaders matching the shape of the expected content, or a centered circular spinner.
- **Empty:** Used when a list/table has zero records.
  - *Visuals:* A subtle, non-distracting illustration or icon, accompanied by muted text (e.g., "No records found") and a primary call-to-action if applicable.
- **Processing (Submitting):** Used when a form POST is in flight.
  - *Visuals:* The submit button becomes disabled and shows an inline spinner. Other form inputs become `disabled`.

## 2. Proof Job States (`/proofs`)
- **`pending`**:
  - *Badge:* `--color-warning` (Amber). Text: "Pending".
  - *Layout:* Proof artifact area shows a loading state.
- **`assembling_witness`**:
  - *Badge:* `--color-info` (Blue). Text: "Generating".
  - *Layout:* Proof artifact area shows a loading state.
- **`completed`**:
  - *Badge:* `--color-success` (Green). Text: "Completed".
  - *Layout:* Proof artifact area reveals the base64 string in a monospace block.
- **`failed`**:
  - *Badge:* `--color-danger` (Red). Text: "Failed".
  - *Layout:* Proof artifact area is replaced by a danger alert containing the sanitized error.
- **`execution_blocked`**:
  - *Badge:* `--color-danger` (Red). Text: "Blocked".
  - *Layout:* System unavailable alert.

## 3. Verification Result States (`/verify`)
- **`verified`**:
  - *Visuals:* Large `--color-success` (Green) panel. Prominent checkmark icon. Text: "Cryptographic verification succeeded."
- **`invalid`**:
  - *Visuals:* Large `--color-danger` (Red) panel. X-mark icon. Text: "Verification failed: cryptographic proof is invalid."
- **`authoritative_record_mismatch`**:
  - *Visuals:* Large `--color-danger` (Red) panel. Text: "Verification failed: submitted roots do not match active system records."
- **`public_input_mismatch`**:
  - *Visuals:* Large `--color-danger` (Red) panel. Text: "Verification failed: proof does not match the provided public inputs."
- **`unavailable`**:
  - *Visuals:* Large `--color-warning` (Amber) panel. Text: "Verification service currently unavailable."

## 4. Vulnerability Snapshot States (`/admin/vulnerabilities`)
- **`pending`**:
  - *Badge:* `--color-warning` (Amber). Text: "Pending Approval".
- **`approved`**:
  - *Badge:* `--color-success` (Green). Text: "Approved".
- **`revoked`**:
  - *Badge:* `--color-danger` (Red). Text: "Revoked".

## 5. Security Policy States (`/admin/policies`)
- **`active=true`**:
  - *Badge:* `--color-success` (Green). Text: "Active".
- **`active=false`**:
  - *Badge:* `--color-text-muted` (Gray). Text: "Inactive".

## 6. Access States
- **`unauthorized` (401)**:
  - *Visuals:* Immediate redirect to `/login`. No UI state rendered in the main app.
- **`forbidden` (403)**:
  - *Visuals:* Centered card. Icon: Lock/Shield. Text: "Access Denied. You do not have permission to view this resource."
- **`not found` (404)**:
  - *Visuals:* Centered card. Icon: Magnifying glass/Broken document. Text: "Page Not Found."
