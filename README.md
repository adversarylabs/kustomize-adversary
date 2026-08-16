# Kustomize adversary

The Kustomize adversary reviews Kustomize source configuration before it is
rendered or deployed. Its goal is to find high-confidence security,
supply-chain, and reliability problems introduced by bases, generators,
transformers, and overlays.

## Scope

The adversary scans Kustomization files named `Kustomization`,
`kustomization.yaml`, or `kustomization.yml`, together with YAML patch files in
the repository. It focuses on risks that are specific to the Kustomize
composition layer, including mutable inputs, unsafe generator data, risky
overlay patches, and configuration that makes deployments non-reproducible or
stale.

Findings are deterministic and include file and line evidence. The complete
detector inventory is in [CHECKS.md](CHECKS.md).

## Boundaries

This adversary evaluates authored Kustomize configuration, not the fully
rendered Kubernetes resources. Security policy for rendered workloads, RBAC,
and raw manifests belongs to the `kubernetes` adversary. Helm chart analysis
belongs to `helm`, and generic secrets outside Kustomize generators belong to
`security/secrets`.
