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
    readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml"];
    readonly rules: [{
        readonly id: "kustomize.mutable-remote";
        readonly title: "Remote resource tracks a mutable branch";
        readonly summary: "Remote resource tracks a mutable branch";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Remote resource tracks a mutable branch weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Pin remote resources to immutable commits.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-remote"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml"];
            readonly pattern: {
                readonly pattern: "github\\.com[^\\s]+\\?ref=(?:main|master|HEAD)";
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
        readonly whyItMatters: "Image override uses a mutable tag weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Use digest overrides for deployed images.";
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
        readonly id: "kustomize.literal-secret";
        readonly title: "Secret generator embeds a credential literal";
        readonly summary: "Secret generator embeds a credential literal";
        readonly category: "secrets";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Secret generator embeds a credential literal weakens an important secrets boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Use an encrypted or external secret source.";
        readonly complexity: "small";
        readonly tags: ["secrets", "literal-secret"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["kustomization.yml", "kustomization.yaml", "**/kustomization.yml", "**/kustomization.yaml"];
            readonly pattern: {
                readonly pattern: "secretGenerator:[\\s\\S]{0,260}literals:[\\s\\S]{0,120}(?:password|token|secret)\\s*=";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
