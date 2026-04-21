import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const releaseMode = (process.env.NOTRUS_RELEASE_MODE ?? "local").trim().toLowerCase();
const approvalsPath = path.resolve(
  process.env.NOTRUS_RELEASE_APPROVALS_PATH ?? path.join(rootDir, "config", "release", "approvals.json")
);

function fail(message) {
  throw new Error(message);
}

function isNonEmptyString(value, maxLength = 300) {
  return typeof value === "string" && value.trim().length > 0 && value.trim().length <= maxLength;
}

function normalizeApprovals(payload) {
  if (!payload || typeof payload !== "object") {
    return [];
  }

  if (!Array.isArray(payload.approvals)) {
    return [];
  }

  return payload.approvals
    .map((entry) => {
      if (!entry || typeof entry !== "object") {
        return null;
      }
      const reviewer = isNonEmptyString(entry.reviewer, 120) ? entry.reviewer.trim().toLowerCase() : null;
      const approvedAt = isNonEmptyString(entry.approvedAt, 60) ? entry.approvedAt.trim() : null;
      const role = isNonEmptyString(entry.role, 120) ? entry.role.trim() : null;
      if (!reviewer || !approvedAt) {
        return null;
      }
      return {
        approvedAt,
        reviewer,
        role,
      };
    })
    .filter(Boolean);
}

async function currentHeadCommit() {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: rootDir });
  return stdout.trim();
}

async function main() {
  if (releaseMode !== "production") {
    console.log(
      JSON.stringify(
        {
          mode: releaseMode,
          ok: true,
          skipped: true,
          reason: "Release governance verification is only required in production mode.",
        },
        null,
        2
      )
    );
    return;
  }

  let raw = "";
  try {
    raw = await fs.readFile(approvalsPath, "utf8");
  } catch {
    fail(
      `Production releases require a governance approval file at ${approvalsPath}. Set NOTRUS_RELEASE_APPROVALS_PATH if needed.`
    );
  }

  let payload = null;
  try {
    payload = JSON.parse(raw);
  } catch {
    fail(`Release governance file is not valid JSON: ${approvalsPath}`);
  }

  const approvals = normalizeApprovals(payload);
  const uniqueReviewers = [...new Set(approvals.map((entry) => entry.reviewer))];
  if (uniqueReviewers.length < 2) {
    fail("Production releases require at least two unique human approvals.");
  }

  const releaseId = isNonEmptyString(payload.releaseId, 120) ? payload.releaseId.trim() : null;
  if (!releaseId) {
    fail("Production releases require a non-empty releaseId in the governance approval file.");
  }

  const commit = isNonEmptyString(payload.commit, 120) ? payload.commit.trim() : null;
  if (commit) {
    const head = await currentHeadCommit();
    if (head !== commit) {
      fail(`Governance approvals target commit ${commit}, but HEAD is ${head}.`);
    }
  }

  const initiatedBy = isNonEmptyString(payload.initiatedBy, 120) ? payload.initiatedBy.trim().toLowerCase() : null;
  if (initiatedBy && uniqueReviewers.length > 0 && uniqueReviewers.every((reviewer) => reviewer === initiatedBy)) {
    fail("At least one release reviewer must be distinct from initiatedBy.");
  }

  console.log(
    JSON.stringify(
      {
        approvals: approvals.length,
        initiatedBy: initiatedBy ?? null,
        mode: releaseMode,
        ok: true,
        releaseId,
        reviewers: uniqueReviewers,
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
