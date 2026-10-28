# Design System & Visual Language

Date: 2026-10-01
Stage: 4 — Design System, Visual Language & UI Semantics Freeze

## 1. Design Philosophy
The Zero-Knowledge SBOM Vulnerability Verification Platform must communicate **security, cryptographic integrity, trust, privacy, and technical precision**. The visual language is restrained, enterprise-focused, and data-dense.

**Anti-Goals:**
- No "hacker" aesthetics (e.g., green-on-black terminals, glowing neon, binary rain).
- No cryptocurrency trading aesthetics (e.g., flashy charts, gamified numbers).
- No generic SaaS softness (e.g., excessive border radii, drop shadows, oversized playful fonts).

## 2. Visual Personality
- **Tone:** Professional, precise, factual, calm.
- **Surface Philosophy:** Flat, strictly delineated surfaces. Elevation is used sparingly for modals and floating menus.
- **Border/Radius Philosophy:** Sharp or minimal radius (e.g., 2px - 4px) to communicate structure and rigor.
- **Iconography:** Functional, geometric outline icons. Used strictly for utility (e.g., copy, external link, status).
- **Illustration:** None. The platform relies on data, tables, and typography, not decorative illustrations.

## 3. Color Semantics
Colors must be defined semantically, not by arbitrary component names.

- `--color-bg`: Page background.
- `--color-surface`: Card/table background.
- `--color-elevated-surface`: Modals and dropdowns.
- `--color-border-subtle`: Dividers and table rows.
- `--color-border-strong`: Active inputs, emphasized structural boundaries.
- `--color-text-primary`: Primary reading text.
- `--color-text-secondary`: Labels, metadata, table headers.
- `--color-text-muted`: Disabled states, timestamps.
- `--color-primary`: Primary interactive elements (buttons, active tabs).
- `--color-success`: Cryptographic success (`verified`), approved states. (Must be accessible green).
- `--color-warning`: Impeding or inactive states (`pending`, `inactive`). (Accessible amber/yellow).
- `--color-danger`: Cryptographic failures (`invalid`), revoked states, destructive actions. (Accessible red).
- `--color-info`: Informational states, active processing (`assembling_witness`). (Accessible blue).
- `--color-focus`: Focus rings for keyboard accessibility.

**Accessibility Constraint:** Color must never be the only carrier of meaning. Status indicators must include a text label or distinguishable icon.

## 4. Typography
- **Primary Font Family:** A highly legible, grotesque sans-serif (e.g., Inter, Roboto).
- **Monospace Font:** A clear, tabular monospace font (e.g., JetBrains Mono, Fira Code) strictly reserved for cryptographic hashes, UUIDs, roots, and code blocks.
- **Hierarchy:**
  - `H1`: Page titles. Semantic `<h1>`.
  - `H2`: Section headers (e.g., inside a card). Semantic `<h2>`.
  - `H3`: Sub-section headers. Semantic `<h3>`.
  - `Body`: Standard data table content and paragraphs.
  - `Small`: Metadata, helper text.
  - `Label`: Form labels, uppercase table headers (tracked out).
  - `Code`: Hash/UUID display.

## 5. Spacing & Layout
- **Scale:** An 8px linear scale (4px, 8px, 16px, 24px, 32px, 48px, 64px).
- **Max Width:** Constrained max-width for forms and reading content (e.g., 1200px) to prevent overly long line lengths. Full width for complex data tables.
- **Gutters:** 24px desktop, 16px tablet/mobile.

## 6. Component Semantics
- **App Shell:** Persistent top/side navigation and main content area.
- **Card:** Structural container for grouped information (e.g., form sections).
- **Metric Card:** Small numeric summary card for dashboard counts.
- **Data Table:** Primary list presentation. Includes pagination.
- **Badge:** Inline status indicator. Must include text.
- **Button:** Primary, secondary, danger, and ghost variants.
- **Copy-to-Clipboard Control:** Icon button with a tooltip ("Copied!") used adjacent to all hashes.
- **Hash Display:** Monospace block with `text-overflow: ellipsis` or middle-truncation, accompanied by a copy button.
- **Proof Artifact Viewer:** Scrollable `<pre>` area with a fixed height and a primary "Copy" action. Never renders actual witness data.

## 7. Security-Sensitive Components
- **Verification Result Panel:** The most critical UI component.
  - **VERIFIED:** Distinct, highly visible success banner. Clear typography indicating cryptographic success.
  - **INVALID / MISMATCH / UNAVAILABLE:** Distinct failure banner. Must not visually blend with the success state.
- **Destructive Confirmations (Modals):** Must require explicit user confirmation (clicking a "Revoke" button) before submitting the API call. Focus must be trapped within the modal.

## 8. Motion
- **Philosophy:** Restrained. Used only for state transitions (e.g., expanding a drawer, opening a modal) or loading indicators (spinner).
- **Prohibited:** No continuous decorative animations, pulsing backgrounds, or flashy "verifying" movie-style sequences.
- **Reduced Motion:** Must respect `prefers-reduced-motion` media queries by disabling non-essential transitions.

## 9. Accessibility
- **Keyboard:** All interactive elements must be reachable via `Tab` with a visible `--color-focus` ring.
- **Semantic HTML:** Use proper `<nav>`, `<main>`, `<table>`, `<form>`, `<label>` tags.
- **Contrast:** All text and critical UI boundaries must meet WCAG 2.1 AA contrast requirements.
- **Screen Readers:** Badges and icons must have `aria-label` or visually hidden text when meaning is not explicitly written.

## 10. Microcopy Principles
- **Tone:** Factual and precise.
- **Avoid:** "100% secure", "Unhackable", "Safe".
- **Use:** "Cryptographic verification succeeded", "Verification failed: public input mismatch".
- **Errors:** Display the sanitized `error_message` from the API. Never expose internal paths or stack traces.
