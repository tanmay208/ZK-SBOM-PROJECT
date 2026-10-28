# Responsive Behavior Requirements

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## 1. Scope
Defines the functional layout and behavioral adjustments across device breakpoints (Desktop, Tablet, Mobile). This does not prescribe CSS visual design.

## 2. Navigation Collapse
- **Desktop:** Main navigation renders as a persistent side drawer or top bar with full labels.
- **Tablet:** Side drawer collapses to icons, or top bar remains visible.
- **Mobile:** Navigation collapses into a hamburger menu. User profile and logout controls move inside the collapsed menu.

## 3. Data Tables (SBOMs, Proofs, Snapshots, Policies)
- **Desktop:** Full tabular layout. All columns visible.
- **Tablet:** Less critical columns (e.g., descriptions, precise timestamps) are hidden or truncated.
- **Mobile:** Tabular layout converts to a list of cards, where each row becomes a vertically stacked card containing the primary identifier (e.g., Name/ID) and primary status badge.

## 4. Cryptographic Artifact Display
- **Hashes & Roots (128-char hex):** 
  - **All breakpoints:** Must use `text-overflow: ellipsis` or a middle-truncation strategy (e.g., `0x1234...abcd`).
  - **Interaction:** Must include a one-click "Copy to Clipboard" button because manually highlighting a wrapped 128-character hex string on mobile is error-prone.
- **Proof Artifact (Base64 block):**
  - **Desktop:** Scrollable `<pre>` or `<code>` block with fixed max height.
  - **Mobile:** Collapsed by default with a "Show Proof Data" toggle, plus a primary "Copy Proof" button.

## 5. Forms (Upload, Generate, Ingest)
- **Desktop:** Multi-column layout permitted (e.g., SBOM details left, file dropzone right).
- **Mobile:** Strictly single-column, full-width stacked inputs. Touch targets for dropdowns (Snapshot/Policy selection) must be large enough for finger interaction.

## 6. Status Indicators (Badges)
- **All breakpoints:** Status indicators (Pending, Approved, Verified, Invalid) must rely on text labels, not solely on color or icons, to ensure accessibility and clarity on smaller screens.

## 7. Destructive Confirmations
- **All breakpoints:** Modals for Approve/Revoke must trap focus and disable background scrolling. On mobile, modals should take up the full screen width to prevent misclicks.
