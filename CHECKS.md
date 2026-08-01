# Checks — what kustomize detects

This file is the **public audit list** of detectors for the **kustomize** adversary. High-confidence defects in `kustomization.yaml` and overlay structure with file:line evidence. Rendered-manifest security (privileged pods, RBAC, images in raw YAML) is owned by `kubernetes` — this adversary covers what only the kustomize layer can see: generators, remote bases, and overlay patches.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `kustomization.yaml` / `kustomization.yml` / `Kustomization`, generator definitions, patch files referenced by kustomizations, and overlay directory structure.

**Precision stance:** Secrets in generators fire hard. Remote bases fire on mutability, not existence. Patch findings fire only on privilege *introduced by* a patch (the base is the kubernetes adversary's job). Overlay naming (`prod`, `production`) may inform severity but never suppression.

Public grounding: kustomize documentation (secretGenerator, remote targets, generatorOptions), Flux/Argo GitOps practices, and the SOPS/SealedSecrets ecosystem as the correct contrast for secret handling.

---

## Critical

### `kustomize.literal-secret`

| | |
| --- | --- |
| **What** | `secretGenerator` embeds secret material in committed files |
| **Why** | `literals:` with real values, or `files:`/`envs:` pointing at committed plaintext credential files, is a committed secret — base64 in the rendered Secret changes nothing |
| **Looks for** | `secretGenerator` with `literals:` whose values are non-placeholder (entropy/length gate); `files:`/`envs:` referencing committed files whose content is credential-shaped |
| **Stays quiet when** | Values are `${VAR}` placeholders or obvious dummies (`changeme` — downgrade to low, not silent, in prod-named overlays); referenced files are gitignored or SOPS-encrypted; SealedSecrets/external-secrets used instead |
| **Public examples** | kustomize secretGenerator docs; SOPS + kustomize integrations as the correct pattern |
| **Remediation** | Use SOPS-encrypted sources, SealedSecrets, or External Secrets Operator — never plaintext generator inputs |

---

## High

### `kustomize.mutable-remote`

| | |
| --- | --- |
| **What** | Remote base/resource tracked by branch or unpinned ref |
| **Why** | `resources: github.com/org/repo//base?ref=main` means whoever controls that branch controls what you `kubectl apply` — the kustomize equivalent of an unpinned GitHub Action |
| **Looks for** | Remote URLs in `resources:`/`bases:`/`components:` with `ref=main|master|HEAD`, no `ref=` at all, or plain `http://` URLs |
| **Stays quiet when** | `ref=` is a full commit SHA (tags downgrade to low — they're mutable but conventionally respected); local relative paths |
| **Public examples** | kustomize remote targets docs; GitOps supply-chain guidance on pinning |
| **Remediation** | Pin remote resources to immutable commit SHAs; vendor bases you don't control |

### `kustomize.configmap-secret-shaped`

| | |
| --- | --- |
| **What** | `configMapGenerator` carrying credential-shaped literals |
| **Why** | Same data, wrong object: ConfigMaps have broader read access and no secret handling — parity with `kubernetes.secret-in-configmap` at the generator layer |
| **Looks for** | `configMapGenerator` literals/files with keys matching `password|token|secret|credential` and non-placeholder values (entropy gate) |
| **Stays quiet when** | Templated/placeholder values; config words that merely contain the keyword with low-entropy values (`keyspace`, `token_ttl`) |
| **Public examples** | Kubernetes docs: ConfigMaps “do not provide secrecy” |
| **Remediation** | Move to `secretGenerator` with an encrypted source, or an external secret manager |

### `kustomize.patch-privilege-escalation`

| | |
| --- | --- |
| **What** | Overlay patch *introduces* privilege the base doesn't have |
| **Why** | Patches are where privilege sneaks past review — the base looks clean, the prod overlay quietly adds `privileged: true` or a hostPath. Raw-manifest scanners that skip patch files miss this entirely |
| **Looks for** | Patch files (strategic-merge or JSON6902) setting `privileged: true`, `hostNetwork/hostPID/hostIPC: true`, `hostPath` volumes, or adding `SYS_ADMIN`-class capabilities |
| **Stays quiet when** | Patches only tune resources/replicas/labels; privilege exists identically in the base (kubernetes adversary owns it there — cross-reference, don't double-report) |
| **Public examples** | GitOps overlay-drift reviews; kustomize patch docs |
| **Remediation** | Keep privilege visible in the base where it's reviewed, or better, remove it; overlays should tune scale and config, not security posture |

---

## Medium

### `kustomize.latest-image`

| | |
| --- | --- |
| **What** | `images:` transformer sets `newTag: latest` or drops to an untagged reference |
| **Why** | The images transformer is the deploy-time pin point in kustomize — floating it makes every apply a different deploy |
| **Looks for** | `images:` entries with `newTag: latest`, no `newTag`/`digest` on overridden images in prod-named overlays |
| **Stays quiet when** | `digest:` used, or any explicit version `newTag` (recommend digests, don't flag versioned tags); dev overlays with versioned base images |
| **Public examples** | kustomize images transformer docs; same class as `kubernetes.mutable-image` |
| **Remediation** | Use `digest:` overrides for deployed images; version tags at minimum |

### `kustomize.name-suffix-hash-disabled`

| | |
| --- | --- |
| **What** | `generatorOptions: disableNameSuffixHash: true` on config/secret generators |
| **Why** | The suffix hash is what makes config changes trigger rollouts. Disabling it means editing a ConfigMap no longer restarts consumers — pods run stale config until something else restarts them, a classic "we deployed the fix but nothing changed" incident |
| **Looks for** | `generatorOptions.disableNameSuffixHash: true` (global or per-generator) |
| **Stays quiet when** | Hash suffix enabled (default); disabled for objects referenced by tools that can't track hashed names **and** a rollout-restart mechanism is visible (annotation-based reloader) |
| **Public examples** | kustomize generatorOptions docs; stale-config incident writeups |
| **Remediation** | Keep the suffix hash; if a fixed name is required, pair it with a config-reloader |

---

## Low

### `kustomize.namespace-default`

| | |
| --- | --- |
| **What** | Kustomization explicitly targets the `default` namespace |
| **Why** | Deploying real workloads into `default` defeats namespace-scoped RBAC/quotas/policies; almost always unintentional in overlays |
| **Looks for** | `namespace: default` in kustomization files, weighted up in prod-named overlays |
| **Stays quiet when** | Dedicated namespaces set; toy/example directories |
| **Public examples** | Kubernetes multi-tenancy guidance |
| **Remediation** | Create and target a dedicated namespace per app/environment |

---

## Out of scope (owned elsewhere)

| Concern | Owner |
| --- | --- |
| Raw manifest security (privileged pods, RBAC, images in resources) | `kubernetes` |
| Helm charts (including kustomize `helmCharts:` chart content) | `helm` |
| Generic secret literals outside generators | `security/secrets` |
| Flux/Argo application CRs | `kubernetes` (until a GitOps adversary exists) |
