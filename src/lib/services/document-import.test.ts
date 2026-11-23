import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { PDFDocument } from "pdf-lib";

import { MAX_PDF_PAGES } from "../types/domain.ts";
import { DocumentImportError, importPdfDocument } from "./document-import.ts";
import { prepareRevisionZero } from "./pdf-revision.ts";

async function pdfWithPages(count: number): Promise<Uint8Array> {
  const document = await PDFDocument.create();

  for (let page = 0; page < count; page += 1) {
    document.addPage([612, 792]);
  }

  return document.save();
}

test("a PDF with more pages than the limit is refused, one at the limit is taken", async () => {
  await assert.rejects(
    importPdfDocument({
      body: await pdfWithPages(MAX_PDF_PAGES + 1),
      contentType: "application/pdf",
      filename: "many.pdf",
    }),
    (error: unknown) =>
      error instanceof DocumentImportError && error.code === "too_many_pages",
  );

  const imported = await importPdfDocument({
    body: await pdfWithPages(MAX_PDF_PAGES),
    contentType: "application/pdf",
    filename: "long.pdf",
  });

  assert.equal(imported.pageCount, MAX_PDF_PAGES);
});

// A signer is shown the stored source with pdf.js, and the sealed copy is
// made by pdf-lib reading that same file. The two do not read every PDF the
// same way, so the stored source has to be a file both read alike: the
// import hands back pdf-lib's own rewrite of the upload, and that is what
// gets stored, hashed, shown and sealed.

function handBuiltPdf(objects: string[]): string {
  let pdf = "%PDF-1.7\n";
  const offsets: number[] = [];

  objects.forEach((body, index) => {
    offsets.push(pdf.length);
    pdf += `${String(index + 1)} 0 obj\n${body}\nendobj\n`;
  });

  const xref = pdf.length;

  pdf += `xref\n0 ${String(objects.length + 1)}\n0000000000 65535 f \n`;

  for (const offset of offsets) {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  }

  return `${pdf}trailer\n<< /Size ${String(objects.length + 1)} /Root 1 0 R >>\nstartxref\n${String(xref)}\n%%EOF\n`;
}

function streamObject(dictionary: string, data: string): string {
  return `<< ${dictionary} /Length ${String(data.length)} >>\nstream\n${data}\nendstream`;
}

const HELVETICA = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

/** A second definition of the page's content, after the end of the file. */
function pdfWithShadowObject(): Uint8Array {
  const base = handBuiltPdf([
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    streamObject("", "BT /F1 24 Tf 72 700 Td (PAY 1000) Tj ET"),
    HELVETICA,
  ]);
  const shadow = `4 0 obj\n${streamObject("", "BT /F1 24 Tf 72 700 Td (PAY 100000) Tj ET")}\nendobj\n`;

  return Uint8Array.from(Buffer.from(base + shadow, "latin1"));
}

/** A form field whose value and stored appearance say different things. */
function pdfWithStaleFieldAppearance(): Uint8Array {
  return Uint8Array.from(
    Buffer.from(
      handBuiltPdf([
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] /NeedAppearances true /DA (/Helv 12 Tf 0 g) /DR << /Font << /Helv 5 0 R >> >> >> >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> /Annots [6 0 R] >>",
        streamObject("", "BT /F1 24 Tf 72 700 Td (Amount due:) Tj ET"),
        HELVETICA,
        "<< /Type /Annot /Subtype /Widget /FT /Tx /T (amount) /V (PAY 1000) /DA (/Helv 12 Tf 0 g) /Rect [72 650 372 680] /F 4 /P 3 0 R /AP << /N 7 0 R >> >>",
        streamObject(
          "/Type /XObject /Subtype /Form /BBox [0 0 300 30] /Resources << /Font << /Helv 5 0 R >> >>",
          "BT /Helv 12 Tf 2 10 Td (PAY 100000) Tj ET",
        ),
      ]),
      "latin1",
    ),
  );
}

/** The text pdf.js paints on the first page, form fields included. */
async function paintedText(pdfBytes: Uint8Array): Promise<string> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const document = await pdfjs.getDocument({
    data: new Uint8Array(pdfBytes),
    useSystemFonts: false,
    verbosity: 0,
  }).promise;
  const page = await document.getPage(1);
  const operators = await page.getOperatorList();
  const parts: string[] = [];

  operators.fnArray.forEach((operator: number, index: number) => {
    if (operator !== pdfjs.OPS.showText) {
      return;
    }

    const glyphs = operators.argsArray[index][0] as unknown[];

    parts.push(
      glyphs
        .map((glyph) =>
          typeof glyph === "object" && glyph !== null && "unicode" in glyph
            ? String(glyph.unicode)
            : "",
        )
        .join(""),
    );
  });

  await document.destroy();

  return parts.join(" | ");
}

for (const [name, build] of [
  [
    "a second definition of an object after the end of the file",
    pdfWithShadowObject,
  ],
  [
    "a form field whose appearance differs from its value",
    pdfWithStaleFieldAppearance,
  ],
] as const) {
  test(`the stored source reads the same in pdf.js and pdf-lib: ${name}`, async () => {
    const imported = await importPdfDocument({
      body: build(),
      contentType: "application/pdf",
      filename: "contract.pdf",
    });
    const shownToSigner = await paintedText(imported.body);
    const sealed = await prepareRevisionZero(imported.body);

    assert.equal(await paintedText(sealed), shownToSigner);
    assert.equal(imported.sizeBytes, imported.body.length);
    assert.equal(
      imported.sourceHash,
      createHash("sha256").update(imported.body).digest("hex"),
    );
  });
}
