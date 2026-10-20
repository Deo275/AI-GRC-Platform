"""Pure-Python Professional PDF Report Generator for AI-GRC Platform.

Generates Adobe PDF 1.4 compliant documents with zero binary or external dependencies.
Features:
- Professional executive design with typography, colors, and layout.
- Self-contained metrics cards, tables with dynamic column sizing, alternating row colors,
  and clean cell padding.
- Multi-page page breaks with running headers, running footers, page numbering (Page X of Y),
  and standard compliance disclaimers.
- Clear separation between Authoritative GRC records and AI Advisory insights.
- Enforces MAX_REPORT_ROWS ceiling and handles empty datasets gracefully.
"""

from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
import re

MAX_REPORT_ROWS = 10000

STANDARD_DISCLAIMER = (
    "DISCLAIMER: This report is generated automatically by the AI-GRC Platform for internal "
    "risk management, vulnerability prioritization, and compliance tracking purposes. It does "
    "not constitute formal legal counsel, regulatory certification, or guarantee of third-party audit attestation."
)


def _escape_pdf_text(text: Any) -> str:
    """Escapes special characters in text for PDF string literals: \\, (, )."""
    if text is None:
        return ""
    s = str(text)
    # Replace non-ascii or non-printable chars safely with ASCII equivalents or space
    s = s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    clean_chars = []
    for char in s:
        code = ord(char)
        if 32 <= code <= 126 or code in (9, 10, 13):
            clean_chars.append(char)
        elif char == "•":
            clean_chars.append("*")
        elif char in ("–", "—"):
            clean_chars.append("-")
        elif char in ("'", "'"):
            clean_chars.append("'")
        elif char in ('"', '"'):
            clean_chars.append('"')
        else:
            clean_chars.append(" ")
    return "".join(clean_chars)


class PDFCanvas:
    """A lightweight stream-based PDF 1.4 page and document builder."""

    def __init__(self, page_width: float = 612.0, page_height: float = 792.0):
        self.width = page_width
        self.height = page_height
        self.pages: List[str] = []
        self.current_stream: List[str] = []

    def start_new_page(self):
        if self.current_stream:
            self.pages.append("\n".join(self.current_stream))
            self.current_stream = []

    def set_color_fill(self, r: float, g: float, b: float):
        self.current_stream.append(f"{r:.3f} {g:.3f} {b:.3f} rg")

    def set_color_stroke(self, r: float, g: float, b: float):
        self.current_stream.append(f"{r:.3f} {g:.3f} {b:.3f} RG")

    def draw_rect(self, x: float, y: float, w: float, h: float, fill: bool = True, stroke: bool = False):
        op = "B" if (fill and stroke) else ("f" if fill else "s")
        self.current_stream.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re {op}")

    def draw_line(self, x1: float, y1: float, x2: float, y2: float, line_width: float = 1.0):
        self.current_stream.append(f"{line_width:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def draw_text(self, text: str, x: float, y: float, font: str = "F1", size: float = 10.0):
        escaped = _escape_pdf_text(text)
        self.current_stream.append(
            f"BT /{font} {size:.1f} Tf {x:.2f} {y:.2f} Td ({escaped}) Tj ET"
        )

    def finish_document(self) -> bytes:
        if self.current_stream:
            self.pages.append("\n".join(self.current_stream))
            self.current_stream = []

        total_pages = len(self.pages)
        if total_pages == 0:
            self.pages.append("")
            total_pages = 1

        # We will build indirect objects:
        # 1: Catalog
        # 2: Pages
        # 3, 4: Font F1 (Helvetica), Font F2 (Helvetica-Bold)
        # 5: Font F3 (Helvetica-Oblique)
        # For each page i (0-indexed):
        #   page_obj_num = 6 + i * 2
        #   stream_obj_num = 6 + i * 2 + 1
        objects: Dict[int, str] = {}

        page_refs = [f"{6 + i * 2} 0 R" for i in range(total_pages)]
        objects[1] = "<< /Type /Catalog /Pages 2 0 R >>"
        objects[2] = f"<< /Type /Pages /Kids [{ ' '.join(page_refs) }] /Count {total_pages} >>"
        objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        objects[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
        objects[5] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique >>"

        for i, page_content in enumerate(self.pages):
            page_obj_num = 6 + i * 2
            stream_obj_num = 6 + i * 2 + 1

            # Replace any {TOTAL_PAGES} placeholder
            page_content = page_content.replace("{TOTAL_PAGES}", str(total_pages))
            content_bytes = page_content.encode("latin-1", errors="replace")
            stream_length = len(content_bytes)

            objects[page_obj_num] = (
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {self.width:.2f} {self.height:.2f}] "
                f"/Contents {stream_obj_num} 0 R "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> >>"
            )
            objects[stream_obj_num] = f"<< /Length {stream_length} >>\nstream\n{page_content}\nendstream"

        # Assemble PDF byte stream
        out = bytearray()
        out.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets: Dict[int, int] = {}
        for obj_num in sorted(objects.keys()):
            offsets[obj_num] = len(out)
            body = f"{obj_num} 0 obj\n{objects[obj_num]}\nendobj\n"
            out.extend(body.encode("latin-1", errors="replace"))

        xref_offset = len(out)
        max_obj = max(objects.keys())
        out.extend(f"xref\n0 {max_obj + 1}\n".encode("latin-1"))
        out.extend(b"0000000000 65535 f \n")
        for i in range(1, max_obj + 1):
            offset = offsets.get(i, 0)
            out.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))

        trailer = (
            f"trailer\n"
            f"<< /Size {max_obj + 1}\n"
            f"/Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        )
        out.extend(trailer.encode("latin-1"))
        return bytes(out)


def build_pdf_report(
    title: str,
    subtitle: str,
    summary_cards: List[Dict[str, Any]],
    table_headers: List[str],
    table_rows: List[List[Any]],
    ai_advisories: Optional[List[Dict[str, Any]]] = None,
    generated_by: str = "system",
    generated_at: Optional[datetime] = None,
    disclaimer: str = STANDARD_DISCLAIMER,
) -> bytes:
    """Builds a formatted, multi-page PDF report conforming to PDF 1.4."""
    if len(table_rows) > MAX_REPORT_ROWS:
        raise ValueError(
            f"Report '{title}' query returned {len(table_rows)} rows, exceeding the maximum "
            f"supported export limit of {MAX_REPORT_ROWS} rows. Please apply query filters."
        )

    page_width = 612.0
    page_height = 792.0
    margin_x = 36.0
    margin_bottom = 45.0
    usable_width = page_width - (2 * margin_x)

    canvas = PDFCanvas(page_width, page_height)
    ts_str = (generated_at or datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S UTC")

    current_page = 1

    def draw_footer(page_num: int):
        # Footer dividing line
        canvas.set_color_stroke(0.80, 0.84, 0.88)
        canvas.draw_line(margin_x, margin_bottom + 14, page_width - margin_x, margin_bottom + 14, 0.5)

        # Footer disclaimer
        canvas.set_color_fill(0.50, 0.55, 0.60)
        canvas.draw_text(
            "AI-GRC Platform | Authoritative Governance & Risk Architecture",
            margin_x,
            margin_bottom + 2,
            font="F1",
            size=7.5,
        )

        # Page numbering placeholder
        page_str = f"Page {page_num} of {{TOTAL_PAGES}}"
        canvas.draw_text(
            page_str,
            page_width - margin_x - 65,
            margin_bottom + 2,
            font="F2",
            size=7.5,
        )

    def draw_running_header():
        canvas.set_color_fill(0.08, 0.12, 0.20)
        canvas.draw_text(
            f"AI-GRC PLATFORM: {_escape_pdf_text(title)} (Continued)",
            margin_x,
            page_height - 30,
            font="F2",
            size=8.5,
        )
        canvas.set_color_stroke(0.85, 0.88, 0.92)
        canvas.draw_line(margin_x, page_height - 35, page_width - margin_x, page_height - 35, 0.5)

    # -------------------------------------------------------------------------
    # PAGE 1: COVER & HEADER
    # -------------------------------------------------------------------------
    cursor_y = page_height - 36.0

    # Top Accent Banner
    canvas.set_color_fill(0.06, 0.13, 0.28)  # Deep Navy #0f2147
    canvas.draw_rect(margin_x, cursor_y - 50, usable_width, 50, fill=True)

    # Header Top Tag
    canvas.set_color_fill(0.24, 0.60, 0.98)  # Azure Accent
    canvas.draw_text("CYBERSECURITY GOVERNANCE, RISK & COMPLIANCE PLATFORM", margin_x + 14, cursor_y - 18, font="F2", size=8.0)

    # Report Title
    canvas.set_color_fill(1.0, 1.0, 1.0)
    canvas.draw_text(title, margin_x + 14, cursor_y - 38, font="F2", size=15.0)

    cursor_y -= 65

    # Subtitle & Metadata Line
    canvas.set_color_fill(0.25, 0.30, 0.38)
    canvas.draw_text(subtitle, margin_x, cursor_y, font="F1", size=9.0)
    cursor_y -= 14

    metadata_line = f"Generated: {ts_str}   |   Export Operator: {generated_by}   |   Classification: Internal GRC Artifact"
    canvas.set_color_fill(0.40, 0.45, 0.52)
    canvas.draw_text(metadata_line, margin_x, cursor_y, font="F3", size=8.0)
    cursor_y -= 18

    # -------------------------------------------------------------------------
    # SUMMARY KPI CARDS
    # -------------------------------------------------------------------------
    if summary_cards:
        cards_per_row = min(len(summary_cards), 4)
        if cards_per_row > 0:
            card_width = (usable_width - (cards_per_row - 1) * 8.0) / cards_per_row
            card_height = 42.0

            row_y = cursor_y - card_height
            for idx, card in enumerate(summary_cards[:4]):
                cx = margin_x + idx * (card_width + 8.0)
                # Background card
                canvas.set_color_fill(0.96, 0.97, 0.99)
                canvas.draw_rect(cx, row_y, card_width, card_height, fill=True)
                canvas.set_color_stroke(0.85, 0.89, 0.93)
                canvas.draw_rect(cx, row_y, card_width, card_height, fill=False, stroke=True)

                # Card Top Border highlight
                color_type = card.get("color", "accent")
                if color_type == "danger":
                    canvas.set_color_fill(0.90, 0.22, 0.27)
                elif color_type == "warning":
                    canvas.set_color_fill(0.95, 0.60, 0.15)
                elif color_type == "success":
                    canvas.set_color_fill(0.13, 0.65, 0.45)
                else:
                    canvas.set_color_fill(0.20, 0.45, 0.85)
                canvas.draw_rect(cx, row_y + card_height - 3, card_width, 3, fill=True)

                # Label
                canvas.set_color_fill(0.35, 0.40, 0.48)
                lbl = str(card.get("label", ""))[:22]
                canvas.draw_text(lbl, cx + 8, row_y + card_height - 15, font="F2", size=7.5)

                # Big Value
                canvas.set_color_fill(0.08, 0.12, 0.20)
                val = str(card.get("value", ""))
                canvas.draw_text(val, cx + 8, row_y + 10, font="F2", size=13.0)

            cursor_y = row_y - 18

    # -------------------------------------------------------------------------
    # AUTHORITATIVE DATA TABLE
    # -------------------------------------------------------------------------
    num_cols = len(table_headers)
    if num_cols > 0:
        # Calculate column widths
        col_widths: List[float] = []
        base_w = usable_width / num_cols
        for h in table_headers:
            col_widths.append(base_w)

        row_height = 20.0
        header_height = 22.0

        def draw_table_header(y_pos: float):
            canvas.set_color_fill(0.12, 0.17, 0.26)  # Dark header
            canvas.draw_rect(margin_x, y_pos - header_height, usable_width, header_height, fill=True)
            canvas.set_color_fill(1.0, 1.0, 1.0)

            cur_x = margin_x
            for c_idx, h_text in enumerate(table_headers):
                w = col_widths[c_idx]
                display_h = str(h_text)[:18]
                canvas.draw_text(display_h, cur_x + 5, y_pos - header_height + 6, font="F2", size=8.0)
                cur_x += w
            return y_pos - header_height

        cursor_y = draw_table_header(cursor_y)

        # Check for empty rows
        if not table_rows:
            canvas.set_color_fill(0.98, 0.98, 0.99)
            canvas.draw_rect(margin_x, cursor_y - 25, usable_width, 25, fill=True)
            canvas.set_color_stroke(0.88, 0.90, 0.94)
            canvas.draw_rect(margin_x, cursor_y - 25, usable_width, 25, fill=False, stroke=True)
            canvas.set_color_fill(0.45, 0.50, 0.58)
            canvas.draw_text("No records found matching current report criteria.", margin_x + 15, cursor_y - 16, font="F3", size=8.5)
            cursor_y -= 35
        else:
            for r_idx, row in enumerate(table_rows):
                # Page break check
                if cursor_y - row_height < margin_bottom + 25:
                    draw_footer(current_page)
                    canvas.start_new_page()
                    current_page += 1
                    draw_running_header()
                    cursor_y = page_height - 50
                    cursor_y = draw_table_header(cursor_y)

                # Alternating row background
                if r_idx % 2 == 0:
                    canvas.set_color_fill(0.98, 0.98, 0.99)
                else:
                    canvas.set_color_fill(1.0, 1.0, 1.0)
                canvas.draw_rect(margin_x, cursor_y - row_height, usable_width, row_height, fill=True)

                # Bottom row border
                canvas.set_color_stroke(0.89, 0.91, 0.94)
                canvas.draw_line(margin_x, cursor_y - row_height, page_width - margin_x, cursor_y - row_height, 0.5)

                # Row cells text
                cur_x = margin_x
                canvas.set_color_fill(0.15, 0.18, 0.25)
                for c_idx, cell_val in enumerate(row):
                    if c_idx >= len(col_widths):
                        break
                    w = col_widths[c_idx]
                    str_val = str(cell_val if cell_val is not None else "—")
                    # Truncate if long
                    char_limit = max(8, int(w / 5.5))
                    if len(str_val) > char_limit:
                        str_val = str_val[:char_limit - 2] + ".."
                    canvas.draw_text(str_val, cur_x + 5, cursor_y - row_height + 6, font="F1", size=7.5)
                    cur_x += w

                cursor_y -= row_height

    # -------------------------------------------------------------------------
    # AI ADVISORY SECTION (IF PRESENT)
    # -------------------------------------------------------------------------
    if ai_advisories:
        ai_box_height = 80.0
        if cursor_y - ai_box_height < margin_bottom + 25:
            draw_footer(current_page)
            canvas.start_new_page()
            current_page += 1
            draw_running_header()
            cursor_y = page_height - 50

        cursor_y -= 12
        canvas.set_color_fill(0.96, 0.95, 0.99)  # Soft purple tint
        canvas.draw_rect(margin_x, cursor_y - 65, usable_width, 65, fill=True)
        canvas.set_color_stroke(0.75, 0.65, 0.90)
        canvas.draw_rect(margin_x, cursor_y - 65, usable_width, 65, fill=False, stroke=True)

        canvas.set_color_fill(0.40, 0.18, 0.70)
        canvas.draw_text("✦ AI ADVISORY DECISION SUPPORT (NON-AUTHORITATIVE)", margin_x + 10, cursor_y - 16, font="F2", size=8.5)

        canvas.set_color_fill(0.25, 0.25, 0.35)
        note = "Generated by automated AI decision support for human operator review. Rule-based risk scores remain authoritative."
        canvas.draw_text(note, margin_x + 10, cursor_y - 30, font="F3", size=7.5)

        for adv in ai_advisories[:2]:
            adv_text = f"* {adv.get('title', 'Recommendation')}: {str(adv.get('recommendation', ''))[:80]}"
            canvas.draw_text(adv_text, margin_x + 10, cursor_y - 45, font="F1", size=7.5)
            break

        cursor_y -= 75

    # -------------------------------------------------------------------------
    # DISCLAIMER BOX
    # -------------------------------------------------------------------------
    disc_height = 36.0
    if cursor_y - disc_height < margin_bottom + 25:
        draw_footer(current_page)
        canvas.start_new_page()
        current_page += 1
        draw_running_header()
        cursor_y = page_height - 50

    cursor_y -= 8
    canvas.set_color_fill(0.95, 0.96, 0.97)
    canvas.draw_rect(margin_x, cursor_y - disc_height, usable_width, disc_height, fill=True)
    canvas.set_color_stroke(0.85, 0.87, 0.90)
    canvas.draw_rect(margin_x, cursor_y - disc_height, usable_width, disc_height, fill=False, stroke=True)

    canvas.set_color_fill(0.35, 0.40, 0.48)
    canvas.draw_text(
        "MANDATORY AUDIT & COMPLIANCE NOTICE:",
        margin_x + 8,
        cursor_y - 12,
        font="F2",
        size=7.0,
    )
    canvas.draw_text(
        disclaimer[:140],
        margin_x + 8,
        cursor_y - 23,
        font="F1",
        size=6.5,
    )

    draw_footer(current_page)
    return canvas.finish_document()
