import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const MAX_ANDROID_UPLOAD_BYTES = 100 * 1024 * 1024;

const MAX_STDOUT_BYTES = 3 * 1024 * 1024;
const MAX_STDERR_BYTES = 16 * 1024;
const COMMAND_TIMEOUT_MS = 150_000;
const OPERATION_NAMES = [
  "inspect_android_package",
  "search_android_classes",
  "inspect_android_class",
  "inspect_android_method",
  "trace_android_references",
] as const;

export type AndroidAnalysisOperation = (typeof OPERATION_NAMES)[number];

export type AndroidAnalysisInput = {
  operation: AndroidAnalysisOperation;
  apkPath: string;
  query?: string;
  className?: string;
  methodName?: string;
  overloadIndex?: number;
};

export class ReaAnalysisError extends Error {
  constructor(
    message: string,
    readonly statusCode: number,
  ) {
    super(message);
    this.name = "ReaAnalysisError";
  }
}

const reaRoot = findReaRoot();

function findReaRoot(): string {
  const projectRoots = [
    process.cwd(),
    resolve(process.cwd(), "../.."),
    resolve(dirname(fileURLToPath(import.meta.url)), "../../.."),
  ];

  for (const projectRoot of projectRoots) {
    const candidate = resolve(projectRoot, "rea");
    if (existsSync(join(candidate, "scripts", "rea.mjs"))) return candidate;
  }

  return resolve(process.cwd(), "rea");
}

export async function getReaRuntimeVersion(): Promise<string> {
  try {
    const packageJson = JSON.parse(
      await readFile(join(reaRoot, "package.json"), "utf8"),
    ) as { version?: unknown };
    return typeof packageJson.version === "string"
      ? packageJson.version
      : "unknown";
  } catch {
    throw new ReaAnalysisError(
      "The REA source package is not available to the API service.",
      503,
    );
  }
}

export async function assertReaAndroidRuntimeReady(): Promise<void> {
  const runtimeFiles = [
    "scripts/rea.mjs",
    "dist/cli-runtime/cli.js",
    "dist/cli-runtime/cliOutput.js",
    "dist/cli-runtime/cliResultOutput.js",
  ];

  for (const runtimeFile of runtimeFiles) {
    if (!existsSync(join(reaRoot, runtimeFile))) {
      throw new ReaAnalysisError(
        "REA’s compiled CLI runtime is missing. Build the REA package before analyzing APKs.",
        503,
      );
    }
  }

  const jadxPath = process.env.REA_JADX_MCP_JAR;
  if (!jadxPath || !isAbsolute(jadxPath)) {
    throw new ReaAnalysisError(
      "The pinned JADX runtime is not configured. Set REA_JADX_MCP_JAR to the verified JADX 0.7.1 JAR.",
      503,
    );
  }

  try {
    const jadxInfo = await stat(jadxPath);
    if (!jadxInfo.isFile()) throw new Error("JADX path is not a file");
  } catch {
    throw new ReaAnalysisError(
      "The configured JADX JAR could not be found by the REA service.",
      503,
    );
  }
}

export async function runReaAndroidCommand(
  input: AndroidAnalysisInput,
  signal: AbortSignal,
): Promise<unknown> {
  const cliPath = join(reaRoot, "scripts", "rea.mjs");
  const args = [...buildCommandArgs(input), "--json"];
  const output = await runCliProcess(cliPath, args, input.apkPath, signal);

  try {
    return JSON.parse(output) as unknown;
  } catch {
    throw new ReaAnalysisError(
      "REA completed without returning valid JSON output.",
      502,
    );
  }
}

function buildCommandArgs(input: AndroidAnalysisInput): string[] {
  switch (input.operation) {
    case "inspect_android_package":
      return ["inspect-android-package", input.apkPath];
    case "search_android_classes":
      return ["search-android-classes", input.apkPath, input.query ?? ""];
    case "inspect_android_class":
      return ["inspect-android-class", input.apkPath, input.className ?? ""];
    case "inspect_android_method":
      return [
        "inspect-android-method",
        input.apkPath,
        input.className ?? "",
        input.methodName ?? "",
        ...(input.overloadIndex === undefined
          ? []
          : ["--overload-index", String(input.overloadIndex)]),
      ];
    case "trace_android_references":
      return [
        "trace-android-references",
        input.apkPath,
        input.className ?? "",
        ...(input.methodName === undefined
          ? []
          : ["--method-name", input.methodName]),
        ...(input.overloadIndex === undefined
          ? []
          : ["--overload-index", String(input.overloadIndex)]),
      ];
  }
}

function reaEnvironment(): NodeJS.ProcessEnv {
  const allowedKeys = [
    "HOME",
    "PATH",
    "TMPDIR",
    "TEMP",
    "JAVA_HOME",
    "REA_JADX_MCP_JAR",
    "REA_JADX_OPERATION_TIMEOUT_MS",
    "REA_JADX_HEAP_MIB",
    "REA_JADX_ACTIVE_PROCESSOR_COUNT",
  ];
  const environment: NodeJS.ProcessEnv = { NODE_ENV: "production" };

  for (const key of allowedKeys) {
    const value = process.env[key];
    if (value !== undefined) environment[key] = value;
  }

  return environment;
}

function runCliProcess(
  cliPath: string,
  args: string[],
  apkPath: string,
  signal: AbortSignal,
): Promise<string> {
  return new Promise((resolveOutput, rejectOutput) => {
    if (signal.aborted) {
      rejectOutput(new ReaAnalysisError("Analysis cancelled.", 499));
      return;
    }

    const child = spawn(process.execPath, [cliPath, ...args], {
      cwd: reaRoot,
      env: reaEnvironment(),
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let outputLimitExceeded = false;
    let timedOut = false;
    let settled = false;
    let killTimer: NodeJS.Timeout | undefined;

    const stopChild = () => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      killTimer ??= setTimeout(() => child.kill("SIGKILL"), 3_000);
      killTimer.unref();
    };

    const timeout = setTimeout(() => {
      timedOut = true;
      stopChild();
    }, COMMAND_TIMEOUT_MS);
    timeout.unref();

    const removeAbortListener = () => signal.removeEventListener("abort", stopChild);
    const cleanup = () => {
      clearTimeout(timeout);
      if (killTimer) clearTimeout(killTimer);
      removeAbortListener();
    };
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      rejectOutput(error);
    };

    signal.addEventListener("abort", stopChild, { once: true });

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_STDOUT_BYTES) {
        outputLimitExceeded = true;
        stopChild();
      } else {
        stdout.push(chunk);
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (stderrBytes >= MAX_STDERR_BYTES) return;
      const remaining = MAX_STDERR_BYTES - stderrBytes;
      const captured = chunk.subarray(0, remaining);
      stderr.push(captured);
      stderrBytes += captured.length;
    });

    child.once("error", (cause) => {
      fail(
        new ReaAnalysisError(
          `Could not start REA: ${cause.message}`,
          503,
        ),
      );
    });
    child.once("close", (code) => {
      if (settled) return;
      settled = true;
      cleanup();

      if (signal.aborted) {
        rejectOutput(new ReaAnalysisError("Analysis cancelled.", 499));
        return;
      }
      if (timedOut) {
        rejectOutput(
          new ReaAnalysisError("REA analysis exceeded its time limit.", 504),
        );
        return;
      }
      if (outputLimitExceeded) {
        rejectOutput(
          new ReaAnalysisError(
            "REA returned more output than this service accepts.",
            502,
          ),
        );
        return;
      }
      if (code !== 0) {
        const details = Buffer.concat(stderr)
          .toString("utf8")
          .trim()
          .replaceAll(apkPath, "[temporary APK]");
        rejectOutput(
          new ReaAnalysisError(
            details
              ? `REA analysis failed: ${details.slice(0, 1_200)}`
              : `REA analysis failed with exit code ${String(code)}.`,
            502,
          ),
        );
        return;
      }

      resolveOutput(Buffer.concat(stdout).toString("utf8").trim());
    });
  });
}
