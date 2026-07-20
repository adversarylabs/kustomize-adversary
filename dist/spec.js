export const spec = {
    "id": "kustomize",
    "displayName": "Kustomize",
    "description": "Reviews Kustomize overlays for mutable resources, image tags, and literal secrets.",
    "files": [
        "kustomization.yml",
        "kustomization.yaml",
        "**/kustomization.yml",
        "**/kustomization.yaml"
    ],
    "rules": [
        {
            "id": "kustomize.mutable-remote",
            "title": "Remote resource tracks a mutable branch",
            "summary": "Remote resource tracks a mutable branch",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Remote resource tracks a mutable branch weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Pin remote resources to immutable commits.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "mutable-remote"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "kustomization.yml",
                    "kustomization.yaml",
                    "**/kustomization.yml",
                    "**/kustomization.yaml"
                ],
                "pattern": {
                    "pattern": "github\\.com[^\\s]+\\?ref=(?:main|master|HEAD)",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "kustomize.latest-image",
            "title": "Image override uses a mutable tag",
            "summary": "Image override uses a mutable tag",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Image override uses a mutable tag weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Use digest overrides for deployed images.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "latest-image"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "kustomization.yml",
                    "kustomization.yaml",
                    "**/kustomization.yml",
                    "**/kustomization.yaml"
                ],
                "pattern": {
                    "pattern": "newTag:\\s*(?:latest|main|edge)\\b",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "kustomize.literal-secret",
            "title": "Secret generator embeds a credential literal",
            "summary": "Secret generator embeds a credential literal",
            "category": "secrets",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Secret generator embeds a credential literal weakens an important secrets boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Use an encrypted or external secret source.",
            "complexity": "small",
            "tags": [
                "secrets",
                "literal-secret"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "kustomization.yml",
                    "kustomization.yaml",
                    "**/kustomization.yml",
                    "**/kustomization.yaml"
                ],
                "pattern": {
                    "pattern": "secretGenerator:[\\s\\S]{0,260}literals:[\\s\\S]{0,120}(?:password|token|secret)\\s*=",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};
