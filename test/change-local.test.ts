import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated Kustomization edit does not surface a legacy mutable tag", async () => {
  const repo = await repositoryWithLegacyKustomization();
  await writeFile(join(repo, "kustomization.yaml"), kustomization("new diagnostic"));

  const result = await changedReview(repo, ["kustomization.yaml"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "kustomize.latest-image"),
    false,
  );
});

test("an added Kustomization remains fully eligible", async () => {
  const repo = await repositoryWithLegacyKustomization();
  await writeFile(join(repo, "Kustomization"), kustomization("added file"));

  const result = await changedReview(repo, ["Kustomization"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "kustomize.latest-image"),
    true,
  );
});

test("an unchanged first occurrence does not hide a later changed occurrence", async () => {
  const repo = await repositoryWithLegacyKustomization();
  await writeFile(join(repo, "kustomization.yaml"), twoImages("1.2.3"));
  await execute("git", ["add", "kustomization.yaml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "two image fixture"], { cwd: repo });
  await writeFile(join(repo, "kustomization.yaml"), twoImages("latest"));

  const result = await changedReview(repo, ["kustomization.yaml"], true);
  const observation = result.rawObservations?.find(
    (item) => item.ruleId === "kustomize.latest-image",
  );
  assert.equal(observation?.location?.line, 8);
  assert.equal(observation?.location?.snippet, "newTag: latest");
});

test("a changed line inside a multi-line semantic match anchors the finding", async () => {
  const repo = await repositoryWithLegacyKustomization();
  await writeFile(join(repo, "patch.yaml"), jsonPatch("/metadata/name"));
  await execute("git", ["add", "patch.yaml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "patch fixture"], { cwd: repo });
  await writeFile(join(repo, "patch.yaml"), jsonPatch("/apiVersion"));

  const result = await changedReview(repo, ["patch.yaml"], true);
  const observation = result.rawObservations?.find(
    (item) => item.ruleId === "kustomize.api-version-json-patch",
  );
  assert.equal(observation?.location?.line, 7);
  assert.equal(observation?.location?.snippet, "path: /apiVersion");
});

test("an unrelated line inside a broad secret match does not revive a legacy finding", async () => {
  const original = secretGenerator("old diagnostic");
  const repo = await repositoryWithLegacyKustomization();
  await writeFile(join(repo, "kustomization.yaml"), original);
  await execute("git", ["add", "kustomization.yaml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "secret fixture"], { cwd: repo });
  await writeFile(join(repo, "kustomization.yaml"), secretGenerator("new diagnostic"));

  const result = await changedReview(repo, ["kustomization.yaml"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "kustomize.literal-secret"),
    false,
  );
});

async function repositoryWithLegacyKustomization(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "kustomize-change-local-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await writeFile(join(repo, "kustomization.yaml"), kustomization("old diagnostic"));
  await execute("git", ["add", "kustomization.yaml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

function kustomization(diagnostic: string): string {
  return `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
images:
  - name: example/app
    newTag: latest
labels:
  - pairs:
      diagnostic: ${JSON.stringify(diagnostic)}
`;
}

function twoImages(workerTag: string): string {
  return `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
images:
  - name: example/app
    newTag: latest
  - name: example/worker
    digest: sha256:deadbeef
    newTag: ${workerTag}
`;
}

function jsonPatch(path: string): string {
  return `apiVersion: builtin
kind: PatchTransformer
metadata:
  name: version
patch: |-
  - op: replace
    path: ${path}
    value: apps/v1
`;
}

function secretGenerator(diagnostic: string): string {
  return `secretGenerator:
  - name: credentials
    annotations:
      diagnostic: ${JSON.stringify(diagnostic)}
    literals:
      - password=super-secret-value
`;
}

async function changedReview(
  repoPath: string,
  changedFiles: string[],
  includeRawObservations = false,
) {
  return createApp().run({
    includeRawObservations,
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}
