# Development Rules

1. Authoritative architecture documents must not be silently changed.
2. ZKP public inputs cannot change without explicit architecture review.
3. Private data must never cross the buyer boundary.
4. Raw SBOM must never be returned by buyer verification APIs.
5. Cryptographic implementation requires deterministic test vectors.
6. Python and Noir must produce interoperable cryptographic values.
7. Every service requires API tests.
8. Cryptographic components require negative tests.
9. SQL Server remains the single database instance.
10. No Kubernetes.
11. No blockchain.
12. No Redis.
13. No second ZKP framework.
14. No unnecessary infrastructure.
15. No scope expansion without explicit review.
16. Day 45 is feature freeze.
17. No claim of universal software security.
18. Proof claims must remain limited to the committed SBOM, policy, and vulnerability snapshot.
19. No sensitive data in logs.
20. No sensitive data in buyer-facing API responses.
