import { createHash } from "node:crypto";

import { PDFDocument, PDFName } from "pdf-lib";

import type { EnvelopePageRecord } from "../schemas/envelope.ts";
import { MAX_PDF_PAGES, MAX_UPLOAD_SIZE_BYTES } from "../types/domain.ts";
import { getDisplayedPageGeometry } from "./pdf-page-geometry.ts";

const PDF_MAGIC_HEADER = "%PDF-";

const PDF_IMPORT_ERROR_MESSAGES = {
  encrypted_pdf:
    "This PDF is password-protected or encrypted. Please upload an unlocked PDF.",
  invalid_type: "Only PDF files are supported. Please upload a valid PDF.",
  too_large: "This file exceeds the 20 MB limit.",
  too_many_pages: `This PDF has more than ${String(MAX_PDF_PAGES)} pages. Split it into smaller documents.`,
  unreadable_pdf: "We couldn't read this PDF. Please upload a valid file.",
  unsupported_variant:
    "This PDF uses an unsupported format. Please export it as a standard PDF.",
  upload_failed: "Upload failed. Please try again.",
} as const;

export const pdfImportFailureCodes = [
  "encrypted_pdf",
  "invalid_type",
  "too_large",
  "too_many_pages",
  "unreadable_pdf",
  "unsupported_variant",
  "upload_failed",
] as const;

export type PdfImportFailureCode = (typeof pdfImportFailureCodes)[number];

export type PdfImportError = {
  code: PdfImportFailureCode;
  message: string;
};

export type ImportedPdfPage = Pick<
  EnvelopePageRecord,
  "heightPt" | "pageNumber" | "widthPt"
>;

export type ImportedPdfDocument = {
  /**
   * The document to store: pdf-lib's own rewrite of the upload, not the
   * upload. See normalizeForStorage.
   */
  body: Uint8Array;
  encrypted: boolean;
  filename: string;
  pageCount: number;
  pages: ImportedPdfPage[];
  pureXfa: boolean;
  sizeBytes: number;
  sourceHash: string;
};

type ImportPdfDocumentInput = {
  body: Uint8Array;
  contentType?: string | null;
  filename: string;
  maxSizeBytes?: number;
};

export class DocumentImportError extends Error {
  code: PdfImportFailureCode;

  constructor(
    code: PdfImportFailureCode,
    message = getPdfImportErrorMessage(code),
  ) {
    super(message);
    this.code = code;
    this.name = "DocumentImportError";
  }
}

export const DEFAULT_DOCUMENT_IMPORT_LIMITS = {
  maxSizeBytes: MAX_UPLOAD_SIZE_BYTES,
};

export function getPdfImportErrorMessage(code: PdfImportFailureCode): string {
  return PDF_IMPORT_ERROR_MESSAGES[code];
}

function assertImportRequest(input: {
  contentType?: string | null;
  filename: string;
  maxSizeBytes: number;
  sizeBytes: number;
}): void {
  if (!input.filename.toLowerCase().endsWith(".pdf")) {
    throw new DocumentImportError("invalid_type");
  }

  const normalizedContentType = input.contentType?.trim().toLowerCase() ?? "";

  if (
    normalizedContentType.length > 0 &&
    normalizedContentType !== "application/pdf"
  ) {
    throw new DocumentImportError("invalid_type");
  }

  if (input.sizeBytes > input.maxSizeBytes) {
    throw new DocumentImportError("too_large");
  }
}

function isPasswordException(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const normalizedMessage = error.message.trim().toLowerCase();

  return (
    error.name === "PasswordException" ||
    normalizedMessage.includes("password") ||
    normalizedMessage.includes("encrypted")
  );
}

function looksLikePdf(body: Uint8Array): boolean {
  if (body.length < PDF_MAGIC_HEADER.length) {
    return false;
  }

  const header = new TextDecoder("latin1").decode(
    body.subarray(0, PDF_MAGIC_HEADER.length),
  );

  return header === PDF_MAGIC_HEADER;
}

function maybeContainsXfa(body: Uint8Array): boolean {
  const prefix = new TextDecoder("latin1").decode(
    body.subarray(0, Math.min(body.length, 512 * 1024)),
  );

  return prefix.includes("/XFA");
}

function maybeContainsEncrypt(body: Uint8Array): boolean {
  const prefix = new TextDecoder("latin1").decode(
    body.subarray(0, Math.min(body.length, 512 * 1024)),
  );

  return prefix.includes("/Encrypt");
}

/**
 * Rewrites an upload into the file that is stored as the envelope's source.
 *
 * A signer is shown the source with pdf.js, and the signed copy is made by
 * pdf-lib reading the same file. The two do not read every PDF alike: an
 * object defined twice is one thing to pdf.js, which follows the
 * cross-reference table, and another to pdf-lib, which keeps the last
 * definition in the file; a form field is drawn from its value by pdf.js and
 * from its stored appearance when pdf-lib flattens it. A file made to be
 * read both ways would show a signer one document and seal another.
 *
 * So the upload is read once by pdf-lib, its form is flattened the way the
 * signed copy flattens it, and what pdf-lib writes back is the source: one
 * definition of each object, one cross-reference table, nothing after the
 * end. That file is what is stored, hashed, shown and sealed.
 */
async function normalizeForStorage(body: Uint8Array): Promise<Uint8Array> {
  const document = await PDFDocument.load(body, {
    ignoreEncryption: false,
    updateMetadata: false,
  });

  if (document.getPageCount() > MAX_PDF_PAGES) {
    throw new DocumentImportError("too_many_pages");
  }

  if (document.catalog.has(PDFName.of("AcroForm"))) {
    try {
      document.getForm().flatten();
    } catch {
      // A form pdf-lib cannot flatten stays as it is, as it does when the
      // signed copy is made. The stored file is still pdf-lib's rewrite.
    }
  }

  return document.save({ useObjectStreams: false });
}

async function parsePdfDocument(
  body: Uint8Array,
): Promise<{ pages: ImportedPdfPage[]; pureXfa: boolean }> {
  const document = await PDFDocument.load(body, {
    ignoreEncryption: false,
    updateMetadata: false,
  });

  if (document.getPageCount() > MAX_PDF_PAGES) {
    throw new DocumentImportError("too_many_pages");
  }

  // The size of each page as a reader shows it: the CropBox, with width and
  // height swapped on a page rotated a quarter turn. The field overlay is
  // laid out to this size, so it has to match what the browser draws.
  const pages = document.getPages().map((page, index) => {
    const { heightPt, widthPt } = getDisplayedPageGeometry(page);

    return { heightPt, pageNumber: index + 1, widthPt };
  });

  return {
    pages,
    pureXfa: false,
  };
}

function hashDocument(body: Uint8Array): string {
  return createHash("sha256").update(body).digest("hex");
}

export async function importPdfDocument({
  body,
  contentType,
  filename,
  maxSizeBytes = DEFAULT_DOCUMENT_IMPORT_LIMITS.maxSizeBytes,
}: ImportPdfDocumentInput): Promise<ImportedPdfDocument> {
  const normalizedFilename = filename.trim() || "document.pdf";
  const uploadSizeBytes = body.length;

  assertImportRequest({
    contentType,
    filename: normalizedFilename,
    maxSizeBytes,
    sizeBytes: uploadSizeBytes,
  });

  if (!looksLikePdf(body)) {
    throw new DocumentImportError("invalid_type");
  }

  const containsEncrypt = maybeContainsEncrypt(body);
  const containsXfa = maybeContainsXfa(body);

  if (containsEncrypt) {
    throw new DocumentImportError("encrypted_pdf");
  }

  try {
    if (containsXfa) {
      throw new DocumentImportError("unsupported_variant");
    }

    const storedBody = await normalizeForStorage(body.slice());

    // The rewrite can come out larger than the upload.
    if (storedBody.length > maxSizeBytes) {
      throw new DocumentImportError("too_large");
    }

    // Page sizes are read from the stored file, the one the browser draws.
    const { pages, pureXfa } = await parsePdfDocument(storedBody.slice());

    if (pureXfa) {
      throw new DocumentImportError("unsupported_variant");
    }

    return {
      body: storedBody,
      encrypted: false,
      filename: normalizedFilename,
      pageCount: pages.length,
      pages,
      pureXfa,
      sizeBytes: storedBody.length,
      sourceHash: hashDocument(storedBody),
    };
  } catch (error) {
    if (error instanceof DocumentImportError) {
      throw error;
    }

    if (isPasswordException(error) || containsXfa) {
      if (isPasswordException(error)) {
        throw new DocumentImportError("encrypted_pdf");
      }

      throw new DocumentImportError("unsupported_variant");
    }

    throw new DocumentImportError("unreadable_pdf");
  }
}
