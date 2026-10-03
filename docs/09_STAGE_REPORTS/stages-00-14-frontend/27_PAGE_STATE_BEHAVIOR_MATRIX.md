# Page State Behavior Matrix

Date: 2026-10-01
Stage: 3 — Complete Product Requirements, Page Inventory & User Flow Freeze

## Core Form States (Apply to Login, Register, Upload, Generate, Ingest, Create Policy)
| State | Trigger | Behavior |
|---|---|---|
| **INITIAL** | Page load | Form is blank or prefilled with default selections. Submit button is enabled. |
| **PROCESSING** | User clicks submit | Submit button disabled. Loading spinner. Inputs disabled. |
| **SUCCESS** | API returns 2xx | Form clears or redirects. Toast notification shown. |
| **FAILED (422)** | Validation error | Specific fields highlighted with error text from `detail` array. |
| **FAILED (400/409)**| Domain error | Global error banner above form. |

## Data List States (Apply to SBOMs, Proofs, Certificates, Policies, Snapshots)
| State | Trigger | Behavior |
|---|---|---|
| **LOADING** | Fetching API | Skeleton loader or spinner. |
| **EMPTY** | API returns `[]` | Empty state illustration/text (e.g., "No proofs generated yet"). Primary call-to-action button (e.g., "Generate Proof"). |
| **SUCCESS** | API returns `[...]`| Table renders with pagination controls. |
| **FAILED** | API error (500/network) | Error state indicating fetch failure with a "Retry" button. |

## Proof Job Specific States (`/proofs/[id]`)
| Status Enum | Meaning | Frontend Behavior |
|---|---|---|
| `pending` | Queued in backend | "Waiting to start". Spinner. No proof artifact available. Poll every 5s. |
| `assembling_witness`| Backend working | "Generating proof...". Spinner. Poll every 5s. |
| `completed` | Success | "Completed". Display proof artifact in copyable block. Stop polling. |
| `failed` | Prover crashed | "Failed". Display sanitized `error_message`. Stop polling. |
| `execution_blocked` | Env not ready | "Environment Unavailable". Suggest contacting admin. Stop polling. |

## Verification Request States (`/verify`)
| Result Enum | Meaning | Frontend Behavior |
|---|---|---|
| `verified` | Success | "Verification Successful". Display Certificate UUID and link to view. |
| `invalid` | Math failed | "Proof Invalid". Red warning. |
| `authoritative_record_mismatch`| Root mismatch | "Record Mismatch". Explain that the submitted roots do not match active approved system records. |
| `public_input_mismatch`| Proof input mismatch| "Public Input Mismatch". Explain the proof artifact was generated for different roots. |
| `unavailable` | Verifier blocked | "Verifier Unavailable". |

## Vulnerability Snapshot States
| Status Enum | Meaning | Frontend Behavior |
|---|---|---|
| `processing` | Ingesting | (Rarely seen due to sync ingest, but handle as Pending). |
| `pending` | Awaiting admin | Display "Pending Approval". (Admin sees Approve/Revoke buttons). |
| `approved` | Active | Display green "Approved" badge. Usable in dropdowns for Proof Generation. |
| `revoked` | Invalidated | Display red "Revoked" badge. NOT usable for new proof generations. |

## Policy States
| Active Field | Meaning | Frontend Behavior |
|---|---|---|
| `active=true` | Current policy | Display green "Active" badge. Usable in dropdowns. |
| `active=false`| Legacy policy | Display gray "Inactive" badge. Read-only history. |
