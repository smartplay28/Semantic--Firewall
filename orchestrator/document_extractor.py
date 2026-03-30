import csv
import io
from pathlib import Path


class DocumentExtractionError(Exception):
    pass


class DocumentExtractor:
    def __init__(self, max_chars: int = 100_000):
        self.max_chars = max_chars

    def extract_text(self, filename: str, content: bytes) -> dict:
        suffix = Path(filename).suffix.lower()
        if suffix in {".txt", ".md", ".log"}:
            text = self._decode_text(content)
        elif suffix == ".csv":
            text = self._extract_csv(content)
        elif suffix == ".pdf":
            text = self._extract_pdf(content)
        elif suffix in {".png", ".jpg", ".jpeg"}:
            text = self._extract_image_ocr(content)
        else:
            raise DocumentExtractionError(f"Unsupported file type: {suffix or 'unknown'}")

        quality = self._assess_quality(suffix, text)
        return {
            "filename": filename,
            "extension": suffix,
            "text": text[: self.max_chars],
            "truncated": len(text) > self.max_chars,
            "char_count": min(len(text), self.max_chars),
            "extraction_mode": self._extraction_mode_for_suffix(suffix),
            "extraction_quality": quality,
            "warnings": self._warnings_for_extract(suffix, text, quality),
        }

    def _extraction_mode_for_suffix(self, suffix: str) -> str:
        if suffix in {".txt", ".md", ".log"}:
            return "native_text"
        if suffix == ".csv":
            return "structured_csv"
        if suffix == ".pdf":
            return "pdf_text"
        if suffix in {".png", ".jpg", ".jpeg"}:
            return "ocr_image"
        return "unknown"

    def _quality_for_suffix(self, suffix: str) -> str:
        if suffix in {".txt", ".md", ".log", ".csv"}:
            return "high"
        if suffix == ".pdf":
            return "medium"
        if suffix in {".png", ".jpg", ".jpeg"}:
            return "medium"
        return "low"

    def _warnings_for_extract(self, suffix: str, text: str, quality: str) -> list[str]:
        warnings = []
        stripped = text.strip()
        if len(stripped) < 20:
            warnings.append("Very little text was extracted from the document.")
        if quality == "low":
            warnings.append("Extraction quality looks low. Review the extracted text before trusting the scan result.")
        if suffix in {".png", ".jpg", ".jpeg"}:
            warnings.append("OCR-based extraction can be noisier than native text extraction.")
        if suffix == ".pdf":
            warnings.append("PDF extraction quality depends on the source document structure.")
        return warnings

    def _decode_text(self, content: bytes) -> str:
        for encoding in ("utf-8", "utf-16", "latin-1"):
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                continue
        raise DocumentExtractionError("Could not decode text document.")

    def _extract_csv(self, content: bytes) -> str:
        decoded = self._decode_text(content)
        reader = csv.reader(io.StringIO(decoded))
        rows = []
        for row in reader:
            cleaned = [cell.strip() for cell in row if cell.strip()]
            if cleaned:
                rows.append(" | ".join(cleaned))
        return "\n".join(rows)

    def _extract_pdf(self, content: bytes) -> str:
        pdf_reader = None
        errors = []
        try:
            from pypdf import PdfReader  # type: ignore

            pdf_reader = PdfReader(io.BytesIO(content))
        except Exception as exc:
            errors.append(str(exc))
        if pdf_reader is None:
            try:
                from PyPDF2 import PdfReader  # type: ignore

                pdf_reader = PdfReader(io.BytesIO(content))
            except Exception as exc:
                errors.append(str(exc))
        if pdf_reader is None:
            raise DocumentExtractionError(
                "PDF extraction requires pypdf or PyPDF2 to be installed."
            )

        pages = []
        for page in pdf_reader.pages:
            extracted = page.extract_text() or ""
            if extracted.strip():
                pages.append(extracted)
        text = "\n\n".join(pages).strip()
        if not text:
            raise DocumentExtractionError("No extractable text found in PDF document.")
        return text

    def _extract_image_ocr(self, content: bytes) -> str:
        image_module = None
        errors = []
        try:
            from PIL import Image  # type: ignore

            image_module = Image
        except Exception as exc:
            errors.append(str(exc))
        if image_module is None:
            raise DocumentExtractionError(
                "Image OCR requires Pillow and pytesseract to be installed."
            )

        try:
            import pytesseract  # type: ignore
        except Exception as exc:
            errors.append(str(exc))
            raise DocumentExtractionError(
                "Image OCR requires Pillow and pytesseract to be installed."
            ) from exc

        try:
            image = image_module.open(io.BytesIO(content))
            processed = image.convert("L")
            try:
                from PIL import ImageOps  # type: ignore

                processed = ImageOps.autocontrast(processed)
            except Exception:
                pass
            processed = processed.point(lambda pixel: 255 if pixel > 160 else 0)
            text = pytesseract.image_to_string(processed).strip()
        except Exception as exc:
            raise DocumentExtractionError(f"Image OCR failed: {exc}") from exc

        if not text:
            raise DocumentExtractionError("No extractable text found in image document.")
        return text

    def _assess_quality(self, suffix: str, text: str) -> str:
        base_quality = self._quality_for_suffix(suffix)
        stripped = text.strip()
        if not stripped:
            return "low"
        weird_ratio = sum(1 for char in stripped if not (char.isalnum() or char.isspace() or char in ".,:;!?-_/@#()[]'\"")) / max(len(stripped), 1)
        short_text = len(stripped) < 30
        many_singletons = len([token for token in stripped.split() if len(token) == 1]) > max(5, len(stripped.split()) // 2)

        if suffix in {".png", ".jpg", ".jpeg"}:
            if weird_ratio > 0.2 or many_singletons or short_text:
                return "low"
            if weird_ratio > 0.08:
                return "medium"
            return "high"

        if suffix == ".pdf":
            if weird_ratio > 0.15 or short_text:
                return "low"
            if weird_ratio > 0.06:
                return "medium"
            return max(base_quality, "medium", key=lambda item: {"low": 0, "medium": 1, "high": 2}[item])

        return base_quality
