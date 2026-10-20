import { createWriteStream } from "node:fs";
import { open, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Router, type IRouter } from "express";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { AndroidAnalysisResponse } from "@workspace/api-zod";
import { logger } from "../lib/logger";
import {
  assertReaAndroidRuntimeReady,
  getReaRuntimeVersion,
  MAX_ANDROID_UPLOAD_BYTES,
  ReaAnalysisError,
  runReaAndroidCommand,
  type AndroidAnalysisOperation,
} from "../lib/reaAndroidCli";

const router: IRouter = Router();

const allowedOperations = new Set<AndroidAnalysisOperation>([
  "inspect_android_package",
  "search_android_classes",
  "inspect_android_class",
  "inspect_android_method",
  "trace_android_references",
]);
const allowedContentTypes = new Set([
  "application/vnd.android.package-archive",
  "application/octet-stream",
]);

let analysisInProgress = false;

class UploadTooLargeError extends Error {
  constructor() {
    super("The APK exceeds the 100 MB upload limit.");
    this.name = "UploadTooLargeError";
  }
}

router.post("/analysis/android", async (req, res): Promise<void> => {
  let temporaryDirectory: string | undefined;
  let acquiredAnalysisSlot = false;
  const abortController = new AbortController();

  const abortOnDisconnect = () => abortController.abort();
  req.once("aborted", abortOnDisconnect);
  res.once("close", () => {
    if (!res.writableEnded) abortController.abort();
  });

  try {
    const operationValue = readString(req.query.operation);
    if (
      operationValue === undefined ||
      !allowedOperations.has(operationValue as AndroidAnalysisOperation)
    ) {
      res.status(400).json({ message: "Choose a supported REA Android operation." });
      return;
    }

    const operation = operationValue as AndroidAnalysisOperation;
    const commandInput = parseCommandInput(req.query, operation);
    if (typeof commandInput === "string") {
      res.status(400).json({ message: commandInput });
      return;
    }

    const fileName = parseUploadFileName(req.get("x-rea-filename"));
    if (!fileName) {
      res.status(400).json({ message: "Provide a valid APK filename." });
      return;
    }

    const contentType = req
      .get("content-type")
      ?.split(";")[0]
      ?.trim()
      .toLowerCase();
    if (!contentType || !allowedContentTypes.has(contentType)) {
      res.status(415).json({ message: "Only raw APK uploads are accepted." });
      return;
    }

    const contentLength = Number(req.get("content-length"));
    if (Number.isFinite(contentLength) && contentLength > MAX_ANDROID_UPLOAD_BYTES) {
      res.status(413).json({ message: "The APK exceeds the 100 MB upload limit." });
      return;
    }

    await assertReaAndroidRuntimeReady();
    const engineVersion = await getReaRuntimeVersion();

    if (analysisInProgress) {
      res.status(429).json({ message: "Another REA analysis is already running." });
      return;
    }
    analysisInProgress = true;
    acquiredAnalysisSlot = true;

    temporaryDirectory = await mkdtemp(join(tmpdir(), "rea-apk-"));
    const apkPath = join(temporaryDirectory, "input.apk");
    let uploadedBytes = 0;
    await pipeline(
      req,
      new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          uploadedBytes += chunk.length;
          if (uploadedBytes > MAX_ANDROID_UPLOAD_BYTES) {
            callback(new UploadTooLargeError());
            return;
          }
          callback(null, chunk);
        },
      }),
      createWriteStream(apkPath, { flags: "wx", mode: 0o600 }),
    );

    const fileInfo = await stat(apkPath);
    if (fileInfo.size === 0) {
      res.status(422).json({ message: "The uploaded APK is empty." });
      return;
    }

    if (fileInfo.size > MAX_ANDROID_UPLOAD_BYTES) {
      res.status(413).json({ message: "The APK exceeds the 100 MB upload limit." });
      return;
    }

    const apkFile = await open(apkPath, "r");
    const signature = Buffer.alloc(4);
    const { bytesRead } = await apkFile.read(signature, 0, signature.length, 0);
    await apkFile.close();
    const zipHeader =
      signature[0] === 0x50 &&
      signature[1] === 0x4b &&
      ((signature[2] === 0x03 && signature[3] === 0x04) ||
        (signature[2] === 0x05 && signature[3] === 0x06) ||
        (signature[2] === 0x07 && signature[3] === 0x08));
    if (
      bytesRead < 4 ||
      !zipHeader
    ) {
      res.status(422).json({ message: "The uploaded file is not a ZIP-based APK." });
      return;
    }

    const result = await runReaAndroidCommand(
      { ...commandInput, operation, apkPath },
      abortController.signal,
    );
    const response = AndroidAnalysisResponse.parse({
      operation,
      fileName,
      sizeBytes: fileInfo.size,
      analyzedAt: new Date().toISOString(),
      engineVersion,
      result,
    });
    res.status(200).json(response);
  } catch (cause) {
    if (req.aborted || res.destroyed || abortController.signal.aborted) return;
    if (cause instanceof UploadTooLargeError) {
      res.status(413).json({ message: cause.message });
      return;
    }
    if (cause instanceof ReaAnalysisError) {
      res.status(cause.statusCode).json({ message: cause.message });
      return;
    }

    logger.error({ err: cause }, "REA Android analysis request failed");
    res.status(500).json({ message: "The REA analysis request could not be completed." });
  } finally {
    req.off("aborted", abortOnDisconnect);
    if (temporaryDirectory) {
      await rm(temporaryDirectory, { recursive: true, force: true }).catch((cause) =>
        logger.error({ err: cause }, "Could not remove temporary APK directory"),
      );
    }
    if (acquiredAnalysisSlot) analysisInProgress = false;
  }
});

function readString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function parseCommandInput(
  query: Record<string, unknown>,
  operation: AndroidAnalysisOperation,
):
  | {
      query?: string;
      className?: string;
      methodName?: string;
      overloadIndex?: number;
    }
  | string {
  const searchQuery = readString(query.query);
  const className = readString(query.className);
  const methodName = readString(query.methodName);
  const rawOverloadIndex = readString(query.overloadIndex);
  const invalidText = (value: string | undefined, maxLength: number) =>
    value !== undefined &&
    (value.length === 0 ||
      value.length > maxLength ||
      value.startsWith("-") ||
      /[\u0000-\u001f\u007f]/u.test(value));

  if (invalidText(searchQuery, 256)) return "Enter a valid class-name search.";
  if (invalidText(className, 512)) return "Enter a valid fully qualified class name.";
  if (invalidText(methodName, 256)) return "Enter a valid method name.";

  const overloadIndex =
    rawOverloadIndex === undefined ? undefined : Number(rawOverloadIndex);
  if (
    overloadIndex !== undefined &&
    (!Number.isInteger(overloadIndex) || overloadIndex < 0 || overloadIndex > 1_000_000)
  ) {
    return "Overload index must be a non-negative whole number.";
  }

  switch (operation) {
    case "inspect_android_package":
      if (searchQuery || className || methodName || overloadIndex !== undefined) {
        return "This operation does not take class or method parameters.";
      }
      return {};
    case "search_android_classes":
      if (!searchQuery) return "Enter a class-name search.";
      if (className || methodName || overloadIndex !== undefined) {
        return "Class and method parameters are not used by this operation.";
      }
      return { query: searchQuery };
    case "inspect_android_class":
      if (!className) return "Enter a fully qualified class name.";
      if (searchQuery || methodName || overloadIndex !== undefined) {
        return "Search and method parameters are not used by this operation.";
      }
      return { className };
    case "inspect_android_method":
      if (!className || !methodName) {
        return "Enter both the class name and method name.";
      }
      if (searchQuery) return "Search text is not used by this operation.";
      return { className, methodName, overloadIndex };
    case "trace_android_references":
      if (!className) return "Enter a fully qualified class name.";
      if (searchQuery) return "Search text is not used by this operation.";
      if (overloadIndex !== undefined && !methodName) {
        return "A method name is required when specifying an overload index.";
      }
      return {
        className,
        ...(methodName ? { methodName } : {}),
        ...(overloadIndex === undefined ? {} : { overloadIndex }),
      };
  }
}

function parseUploadFileName(header: string | undefined): string | undefined {
  if (!header || header.length > 768) return undefined;

  let decoded: string;
  try {
    decoded = decodeURIComponent(header);
  } catch {
    return undefined;
  }

  if (
    decoded.length === 0 ||
    decoded.length > 255 ||
    /[\\/\u0000-\u001f\u007f]/u.test(decoded) ||
    !decoded.toLowerCase().endsWith(".apk")
  ) {
    return undefined;
  }

  return decoded;
}

export default router;
