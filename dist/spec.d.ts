import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "kustomize";
    readonly displayName: "Kustomize";
    readonly description: "Reviews Kustomize overlays for mutable resources, image tags, and literal secrets.";
    readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml", "**/*.yaml", "**/*.yml"];
    readonly rules: [{
        readonly id: "kustomize.literal-secret";
        readonly title: "Secret generator embeds a credential literal";
        readonly summary: "Secret generator embeds a credential literal";
        readonly category: "secrets";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "secretGenerator literals and committed credential files become secrets in git history.";
        readonly impact: "Committed credentials for apps and infrastructure are recoverable from the repo.";
        readonly recommendation: "Use SOPS-encrypted sources, SealedSecrets, or External Secrets Operator.";
        readonly complexity: "small";
        readonly tags: ["secrets", "literal-secret"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml"];
            readonly pattern: {
                readonly pattern: "secretGenerator:[\\s\\S]{0,260}literals:[\\s\\S]{0,160}(?:password|token|secret|api[_-]?key|credential)\\s*=\\s*(?!\\$\\{)(?!changeme)(?!example)[^\\s#]+";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kustomize.mutable-remote";
        readonly title: "Remote resource tracks a mutable branch";
        readonly summary: "Remote resource tracks a mutable branch";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Remote bases pinned to main/master/HEAD let whoever controls the branch control what you apply.";
        readonly impact: "Supply-chain substitution of entire base manifests without an overlay change.";
        readonly recommendation: "Pin remote resources to immutable commit SHAs; vendor bases you do not control.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-remote"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml"];
            readonly pattern: {
                readonly pattern: "(?:github\\.com|https?://)[^\\s]+(?:\\?ref=(?:main|master|HEAD)|#(?:main|master|HEAD)\\b)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kustomize.configmap-secret-shaped";
        readonly title: "ConfigMap generator carries credential-shaped data";
        readonly summary: "ConfigMap generator carries credential-shaped data";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "ConfigMaps are not secret objects — broader read access and no secret handling.";
        readonly impact: "Credentials exposed to any subject that can read ConfigMaps in the namespace.";
        readonly recommendation: "Move credentials to secretGenerator with an encrypted source or external secret manager.";
        readonly complexity: "small";
        readonly tags: ["secrets", "configmap"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml"];
            readonly pattern: {
                readonly pattern: "configMapGenerator:[\\s\\S]{0,260}literals:[\\s\\S]{0,160}(?:password|token|secret|api[_-]?key|credential)\\s*=\\s*(?!\\$\\{)(?!changeme)(?!example)[^\\s#]+";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kustomize.patch-privilege-escalation";
        readonly title: "Overlay patch introduces elevated privilege";
        readonly summary: "Overlay patch introduces elevated privilege";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Patches can quietly add privileged mode, host namespaces, hostPath, or dangerous capabilities.";
        readonly impact: "Production overlays become host-compromising while the base still looks clean.";
        readonly recommendation: "Keep privilege visible in the base for review, or remove it; overlays should not raise security posture.";
        readonly complexity: "small";
        readonly tags: ["security", "patch", "privilege"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.yaml", "**/*.yml"];
            readonly pattern: {
                readonly pattern: "(?:privileged:\\s*true|hostNetwork:\\s*true|hostPID:\\s*true|hostIPC:\\s*true|hostPath:|capabilit(?:y|ies):[\\s\\S]{0,80}(?:add|SYS_ADMIN))";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kustomize.latest-image";
        readonly title: "Image override uses a mutable tag";
        readonly summary: "Image override uses a mutable tag";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "The images transformer is the deploy-time pin — floating tags make every apply a different deploy.";
        readonly impact: "Non-reproducible production images and tag-move supply-chain risk.";
        readonly recommendation: "Use digest overrides for deployed images; version tags at minimum.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "latest-image"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml"];
            readonly pattern: {
                readonly pattern: "newTag:\\s*(?:latest|main|edge)\\b";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kustomize.name-suffix-hash-disabled";
        readonly title: "Generator name-suffix hash is disabled";
        readonly summary: "Generator name-suffix hash is disabled";
        readonly category: "reliability";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "The suffix hash is what makes ConfigMap/Secret changes trigger rollouts.";
        readonly impact: "Pods keep stale config after generator edits until something else restarts them.";
        readonly recommendation: "Keep the suffix hash; pair fixed names with a config-reloader if required.";
        readonly complexity: "small";
        readonly tags: ["reliability", "generator"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml"];
            readonly pattern: {
                readonly pattern: "disableNameSuffixHash:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "kustomize.namespace-default";
        readonly title: "Kustomization targets the default namespace";
        readonly summary: "Kustomization targets the default namespace";
        readonly category: "hygiene";
        readonly severity: "low";
        readonly confidence: "high";
        readonly whyItMatters: "Deploying real workloads into default defeats namespace-scoped RBAC, quotas, and policies.";
        readonly impact: "Shared-namespace blast radius and policy gaps for production apps.";
        readonly recommendation: "Create and target a dedicated namespace per app/environment.";
        readonly complexity: "trivial";
        readonly tags: ["hygiene", "namespace"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml"];
            readonly pattern: {
                readonly pattern: "^namespace:\\s*default\\s*$";
                readonly flags: "im";
            };
            readonly requires: [];
        };
    }];
};
export {};
