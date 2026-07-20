# Kustomize adversary

Reviews Kustomize overlays for mutable resources, image tags, and literal secrets.

## Checks

- **Remote resource tracks a mutable branch:** Pin remote resources to immutable commits.
- **Image override uses a mutable tag:** Use digest overrides for deployed images.
- **Secret generator embeds a credential literal:** Use an encrypted or external secret source.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```
