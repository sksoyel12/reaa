import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export type ExtractedString = {
  value: string;
  offset: number;
};

export type AnalysisReport = {
  fileName: string;
  sizeBytes: number;
  mimeType: string;
  sha256: string;
  fileType: string;
  signatureDescription: string;
  entropy: number;
  strings: ExtractedString[];
  totalStringCount: number;
  stringsTruncated: boolean;
  analyzedAt: string;
};

export type AnalysisProgress = {
  bytesRead: number;
  totalBytes: number;
  percent: number;
};

export type AnalysisOptions = {
  signal?: AbortSignal;
  onProgress?: (progress: AnalysisProgress) => void;
};

export const MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024;
const CHUNK_SIZE_BYTES = 4 * 1024 * 1024;
const MIN_STRING_LENGTH = 4;
const MAX_EXTRACTED_STRINGS = 1_000;
const MAX_STRING_LENGTH = 2_000;

type Signature = {
  fileType: string;
  description: string;
};

function matches(bytes: Uint8Array, expected: number[], offset = 0): boolean {
  return expected.every((byte, index) => bytes[offset + index] === byte);
}

function identifySignature(bytes: Uint8Array, fileName: string): Signature {
  if (matches(bytes, [0x7f, 0x45, 0x4c, 0x46])) {
    return { fileType: "Executable", description: "ELF binary" };
  }

  if (matches(bytes, [0x4d, 0x5a])) {
    const peOffset =
      bytes.length >= 0x40
        ? bytes[0x3c]! |
          (bytes[0x3d]! << 8) |
          (bytes[0x3e]! << 16) |
          (bytes[0x3f]! << 24)
        : -1;

    if (peOffset >= 0 && peOffset + 4 <= bytes.length && matches(bytes, [0x50, 0x45, 0, 0], peOffset)) {
      return { fileType: "Executable", description: "Windows PE executable" };
    }

    return { fileType: "Executable", description: "DOS MZ executable header" };
  }

  if (
    matches(bytes, [0xfe, 0xed, 0xfa, 0xce]) ||
    matches(bytes, [0xce, 0xfa, 0xed, 0xfe]) ||
    matches(bytes, [0xfe, 0xed, 0xfa, 0xcf]) ||
    matches(bytes, [0xcf, 0xfa, 0xed, 0xfe])
  ) {
    return { fileType: "Executable", description: "Mach-O binary" };
  }

  if (matches(bytes, [0xca, 0xfe, 0xba, 0xbe])) {
    return {
      fileType: "Executable",
      description: "Java class or Mach-O universal binary signature",
    };
  }

  if (matches(bytes, [0x50, 0x4b, 0x03, 0x04]) || matches(bytes, [0x50, 0x4b, 0x05, 0x06]) || matches(bytes, [0x50, 0x4b, 0x07, 0x08])) {
    if (fileName.toLowerCase().endsWith(".apk")) {
      return {
        fileType: "Android package",
        description: "ZIP-based APK signature (contents are not unpacked)",
      };
    }

    return {
      fileType: "Archive",
      description: "ZIP archive signature (format may be APK, JAR, DOCX, or another ZIP-based file)",
    };
  }

  if (matches(bytes, [0x1f, 0x8b])) {
    return { fileType: "Archive", description: "GZIP compressed data" };
  }

  if (matches(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) {
    return { fileType: "Archive", description: "RAR archive" };
  }

  if (matches(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) {
    return { fileType: "Archive", description: "7-Zip archive" };
  }

  if (matches(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) {
    return { fileType: "Document", description: "PDF document" };
  }

  if (matches(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return { fileType: "Image", description: "PNG image" };
  }

  if (matches(bytes, [0xff, 0xd8, 0xff])) {
    return { fileType: "Image", description: "JPEG image" };
  }

  if (matches(bytes, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) || matches(bytes, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61])) {
    return { fileType: "Image", description: "GIF image" };
  }

  if (matches(bytes, [0x52, 0x49, 0x46, 0x46]) && matches(bytes, [0x57, 0x45, 0x42, 0x50], 8)) {
    return { fileType: "Image", description: "WebP image" };
  }

  if (matches(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) {
    return { fileType: "Document", description: "OLE compound document (legacy Office or another OLE file)" };
  }

  if (matches(bytes, [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0])) {
    return { fileType: "Database", description: "SQLite database" };
  }

  if (matches(bytes, [0, 0x61, 0x73, 0x6d])) {
    return { fileType: "Executable", description: "WebAssembly module" };
  }

  if (bytes.length >= 8 && matches(bytes, [0x66, 0x74, 0x79, 0x70], 4)) {
    return { fileType: "Media", description: "ISO base media container (for example MP4 or HEIF)" };
  }

  if (looksLikeText(bytes)) {
    return { fileType: "Text", description: "Mostly printable text (content sniff)" };
  }

  return { fileType: "Unknown", description: "No supported signature recognized" };
}

function looksLikeText(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return false;

  const sampleLength = Math.min(bytes.length, 4_096);
  let printableOrWhitespace = 0;

  for (let index = 0; index < sampleLength; index += 1) {
    const byte = bytes[index]!;
    if (
      byte === 0x09 ||
      byte === 0x0a ||
      byte === 0x0d ||
      (byte >= 0x20 && byte <= 0x7e) ||
      byte >= 0x80
    ) {
      printableOrWhitespace += 1;
    }
  }

  return printableOrWhitespace / sampleLength >= 0.85;
}

function calculateEntropy(counts: Uint32Array, byteLength: number): number {
  if (byteLength === 0) return 0;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / byteLength;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    const error = new Error("Analysis cancelled.");
    error.name = "AbortError";
    throw error;
  }
}

function yieldToBrowser(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

export async function analyzeFile(file: File, options: AnalysisOptions = {}): Promise<AnalysisReport> {
  if (file.size > MAX_FILE_SIZE_BYTES) {
    throw new Error("This version supports files up to 500 MB. Choose a smaller file to continue.");
  }

  const { signal, onProgress } = options;
  const headerBytes = new Uint8Array(Math.min(file.size, 64));
  const byteCounts = new Uint32Array(256);
  const hasher = sha256.create();
  const strings: ExtractedString[] = [];
  let bytesRead = 0;
  let runStart = -1;
  let runLength = 0;
  let runPreview = "";
  let totalStringCount = 0;
  let stringsTruncated = false;

  const saveRun = () => {
    if (runLength >= MIN_STRING_LENGTH) {
      totalStringCount += 1;
      if (strings.length < MAX_EXTRACTED_STRINGS) {
        strings.push({ value: runPreview, offset: runStart });
      } else {
        stringsTruncated = true;
      }
    }
    runStart = -1;
    runLength = 0;
    runPreview = "";
  };

  onProgress?.({ bytesRead: 0, totalBytes: file.size, percent: file.size === 0 ? 100 : 0 });

  for (let offset = 0; offset < file.size; offset += CHUNK_SIZE_BYTES) {
    throwIfAborted(signal);
    const chunkEnd = Math.min(offset + CHUNK_SIZE_BYTES, file.size);
    const chunk = new Uint8Array(await file.slice(offset, chunkEnd).arrayBuffer());

    if (offset < headerBytes.length) {
      headerBytes.set(chunk.subarray(0, headerBytes.length - offset), offset);
    }

    hasher.update(chunk);
    for (let index = 0; index < chunk.length; index += 1) {
      const byte = chunk[index]!;
      byteCounts[byte] += 1;

      if (byte >= 0x20 && byte <= 0x7e) {
        if (runStart === -1) runStart = offset + index;
        runLength += 1;
        if (runPreview.length < MAX_STRING_LENGTH) {
          runPreview += String.fromCharCode(byte);
        } else {
          stringsTruncated = true;
        }
      } else {
        saveRun();
      }
    }

    bytesRead += chunk.length;
    onProgress?.({
      bytesRead,
      totalBytes: file.size,
      percent: file.size === 0 ? 100 : (bytesRead / file.size) * 100,
    });
    await yieldToBrowser();
  }

  throwIfAborted(signal);
  saveRun();

  const signature = identifySignature(headerBytes, file.name);

  return {
    fileName: file.name,
    sizeBytes: file.size,
    mimeType: file.type || "application/octet-stream",
    sha256: bytesToHex(hasher.digest()),
    fileType: signature.fileType,
    signatureDescription: signature.description,
    entropy: calculateEntropy(byteCounts, file.size),
    strings,
    totalStringCount,
    stringsTruncated,
    analyzedAt: new Date().toISOString(),
  };
}
