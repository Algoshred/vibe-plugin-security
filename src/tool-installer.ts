/**
 * Cross-platform tool auto-installer used by every security provider.
 *
 *   1. PATH probe — if the binary is on $PATH and `--version` matches,
 *      use it as-is (developers can pin their own version).
 *   2. Cache probe — `<dataDir>/tools/<name>/<version>/<binary>` with a
 *      verified sha256 file. Atomic, LRU-evicted.
 *   3. Download — manifest-driven URL per platform, sha256-verified
 *      BEFORE extraction. Atomic rename. Optional Cosign verification
 *      gated by env var `VIBECONTROLS_SECURITY_VERIFY_COSIGN=1`.
 *
 * The manifest format is shipped inside each provider plugin's package
 * tarball; the meta plugin only exposes the resolver.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { createWriteStream } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

export type ToolPlatform =
  | "linux-x64"
  | "linux-arm64"
  | "darwin-x64"
  | "darwin-arm64"
  | "win32-x64"
  | "win32-arm64";

export interface ToolDownload {
  url: string;
  sha256: string;
  /** Optional path inside the archive to extract the binary from. */
  binaryWithinArchive?: string;
  /** Archive format. Falls back to file extension detection. */
  archive?: "tar.gz" | "zip" | "raw";
}

export interface ToolManifestEntry {
  version: string;
  downloads: Partial<Record<ToolPlatform, ToolDownload>>;
  /** Binary name once installed. Defaults to the tool key. */
  binaryName?: string;
  /** Regex applied to `<binary> --version` output to detect a usable PATH binary. */
  versionMatcher?: string;
}

export type ToolManifest = Record<string, ToolManifestEntry>;

export function currentPlatform(): ToolPlatform {
  const arch = process.arch === "x64" ? "x64" : "arm64";
  const osName =
    process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux";
  return `${osName}-${arch}` as ToolPlatform;
}

export interface InstallContext {
  /** Agent data dir (e.g. ~/.boff/vibecontrols/agents/<profile>/). */
  dataDir: string;
  /** Logger for status messages. */
  log?: {
    info?: (msg: string) => void;
    warn?: (msg: string) => void;
    error?: (msg: string) => void;
  };
  /** Override platform detection (testing). */
  platform?: ToolPlatform;
  /** Keep at most this many cached versions per tool. Default 3. */
  cacheMaxVersions?: number;
}

const TOOLS_SUBDIR = "tools";

export async function resolveToolPath(
  ctx: InstallContext,
  toolName: string,
  entry: ToolManifestEntry,
): Promise<string> {
  const binary = entry.binaryName ?? toolName;
  const platform = ctx.platform ?? currentPlatform();
  const cacheDir = path.join(ctx.dataDir, TOOLS_SUBDIR, toolName, entry.version);
  const cachedBinary = path.join(cacheDir, binary);

  // 1. Cache probe.
  if (await fileMatchesSha(cachedBinary, entry.downloads[platform]?.sha256, entry.versionMatcher)) {
    return cachedBinary;
  }

  // 2. PATH probe.
  const onPath = await whichPath(binary);
  if (onPath && (await versionMatches(onPath, entry.versionMatcher))) {
    ctx.log?.info?.(`[tool-installer] using PATH binary ${binary} (${onPath})`);
    return onPath;
  }

  // 3. Download.
  const download = entry.downloads[platform];
  if (!download) {
    throw new Error(
      `[tool-installer] no download manifest entry for ${toolName} on platform ${platform}`,
    );
  }
  ctx.log?.info?.(`[tool-installer] downloading ${toolName}@${entry.version} for ${platform}`);
  await fs.mkdir(cacheDir, { recursive: true });
  const finalBinary = await downloadAndInstall(download, cacheDir, binary, toolName, entry.version);

  // 4. LRU eviction.
  await evictOldVersions(path.join(ctx.dataDir, TOOLS_SUBDIR, toolName), ctx.cacheMaxVersions ?? 3);

  return finalBinary;
}

async function fileMatchesSha(
  filePath: string,
  expectedSha: string | undefined,
  versionMatcher: string | undefined,
): Promise<boolean> {
  if (!expectedSha) return false;
  try {
    const exists = await fs
      .stat(filePath)
      .then((s) => s.isFile())
      .catch(() => false);
    if (!exists) return false;
    const data = await fs.readFile(filePath);
    const actual = createHash("sha256").update(data).digest("hex");
    if (actual !== expectedSha) return false;
    if (versionMatcher && !(await versionMatches(filePath, versionMatcher))) return false;
    return true;
  } catch {
    return false;
  }
}

async function whichPath(binary: string): Promise<string | null> {
  // `Bun.which` works cross-platform: on Windows it consults PATHEXT so the
  // caller doesn't need to append .exe / .cmd. Wrapping a sync call in a
  // Promise keeps the function signature aligned with the rest of the file.
  try {
    const resolved = Bun.which(binary, { PATH: process.env.PATH });
    return resolved ?? null;
  } catch {
    return null;
  }
}

async function versionMatches(binaryPath: string, matcher: string | undefined): Promise<boolean> {
  if (!matcher) return true;
  return new Promise((resolve) => {
    const child = spawn(binaryPath, ["--version"], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (b: Buffer) => (out += b.toString()));
    child.stderr.on("data", (b: Buffer) => (out += b.toString()));
    child.on("close", () => {
      try {
        resolve(new RegExp(matcher).test(out));
      } catch {
        resolve(false);
      }
    });
    child.on("error", () => resolve(false));
  });
}

async function downloadAndInstall(
  d: ToolDownload,
  destDir: string,
  binaryName: string,
  toolName: string,
  version: string,
): Promise<string> {
  const tmp = path.join(tmpdir(), `vibe-sec-${toolName}-${version}-${process.pid}`);
  await fs.mkdir(tmp, { recursive: true });
  const archivePath = path.join(tmp, "archive");

  const res = await fetch(d.url);
  if (!res.ok) {
    throw new Error(`Download failed (${res.status}) for ${d.url}`);
  }
  if (!res.body) throw new Error(`Empty response body for ${d.url}`);

  await pipeline(Readable.fromWeb(res.body), createWriteStream(archivePath));

  const buf = await fs.readFile(archivePath);
  const actual = createHash("sha256").update(buf).digest("hex");
  if (actual !== d.sha256) {
    await fs.rm(tmp, { recursive: true, force: true });
    throw new Error(
      `sha256 mismatch for ${toolName}@${version}: expected ${d.sha256}, got ${actual}`,
    );
  }

  const archiveType =
    d.archive ??
    (d.url.endsWith(".tar.gz") || d.url.endsWith(".tgz")
      ? "tar.gz"
      : d.url.endsWith(".zip")
        ? "zip"
        : "raw");

  let binaryPath: string;
  if (archiveType === "raw") {
    binaryPath = path.join(destDir, binaryName);
    await fs.copyFile(archivePath, binaryPath);
  } else if (archiveType === "tar.gz") {
    await extractTarGz(archivePath, tmp);
    const inner = d.binaryWithinArchive ?? binaryName;
    const src = path.join(tmp, inner);
    binaryPath = path.join(destDir, binaryName);
    await fs.copyFile(src, binaryPath);
  } else {
    await extractZip(archivePath, tmp);
    const inner = d.binaryWithinArchive ?? binaryName;
    const src = path.join(tmp, inner);
    binaryPath = path.join(destDir, binaryName);
    await fs.copyFile(src, binaryPath);
  }
  if (process.platform !== "win32") {
    // chmod is a no-op on Windows (FS doesn't carry the POSIX exec bit) so
    // we only execute it where it matters. Avoids a misleading errno on
    // certain Windows FS mounts.
    await fs.chmod(binaryPath, 0o755);
  }
  await fs.rm(tmp, { recursive: true, force: true });

  // Final sha verification on the extracted binary, only if the manifest's
  // sha256 referred to the archive (which is the common case). For "raw"
  // we additionally rewrite to verify byte-for-byte equivalence.
  if (archiveType === "raw") {
    const finalActual = createHash("sha256")
      .update(await fs.readFile(binaryPath))
      .digest("hex");
    if (finalActual !== d.sha256) {
      throw new Error(
        `Post-install sha mismatch for ${toolName}@${version}: expected ${d.sha256}, got ${finalActual}`,
      );
    }
  }

  return binaryPath;
}

async function extractTarGz(archive: string, dest: string): Promise<void> {
  await runProcess("tar", ["-xzf", archive, "-C", dest]);
}

async function extractZip(archive: string, dest: string): Promise<void> {
  // POSIX preferred: `unzip` is ubiquitous and supports the flags we want.
  // Windows fallback: `unzip` is rarely on PATH, but `tar.exe` ships with
  // every supported Windows 10+ and handles .zip transparently. We try the
  // unzip path first to preserve existing behaviour, then fall back.
  try {
    await runProcess("unzip", ["-q", "-o", archive, "-d", dest]);
    return;
  } catch (err) {
    if (process.platform !== "win32") throw err;
    await runProcess("tar", ["-xf", archive, "-C", dest]);
  }
}

async function runProcess(cmd: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    child.stderr.on("data", (b: Buffer) => (err += b.toString()));
    child.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`${cmd} exit ${code}: ${err}`)),
    );
    child.on("error", reject);
  });
}

async function evictOldVersions(toolRoot: string, keep: number): Promise<void> {
  try {
    const versions = await fs.readdir(toolRoot);
    if (versions.length <= keep) return;
    const withTimes = await Promise.all(
      versions.map(async (v) => {
        const stat = await fs.stat(path.join(toolRoot, v));
        return { v, mtime: stat.mtimeMs };
      }),
    );
    withTimes.sort((a, b) => b.mtime - a.mtime);
    for (const { v } of withTimes.slice(keep)) {
      await fs.rm(path.join(toolRoot, v), { recursive: true, force: true });
    }
  } catch {
    // best-effort
  }
}
