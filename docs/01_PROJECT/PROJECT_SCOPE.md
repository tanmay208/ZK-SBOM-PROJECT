# Project Scope

## Problem

SBOMs can reveal dependency and product composition when shared for supply-chain assurance. The project explores whether a supplier can produce a checkable policy-compliance proof against committed SBOM and vulnerability data without handing the verifier the original component inventory.

## Objective

Implement an end-to-end prototype that connects SBOM intake and commitments, vulnerability snapshot and policy records, zero-knowledge proof generation and verification, persisted verification results, and certificate validation.

## In scope through Stage 22

- Backend APIs and persistence for SBOMs, vulnerability snapshots, policies, proof jobs, verification requests, and certificates.
- Noir circuit/proof workflows and configured artifact profiles.
- A web frontend for vendor, verifier, certificate, and administrator interactions.
- Security, integration, and runtime validation recorded in stage reports.

## Out of scope / deferred

Production hosting, external HTTPS/TLS termination, public ingress, origin isolation, firewall/network policy, production secrets/database provisioning, and external reachability remain Stage 23 work. This is not a claim that these controls are deployed.

## Claim boundary

The implementation addresses the statement encoded by its circuits, selected data commitments, and policy inputs. It does not prove vulnerability-database completeness or freshness, SBOM completeness, general software safety, or absence of unmodeled vulnerabilities. Research novelty has not been established by the repository evidence.
