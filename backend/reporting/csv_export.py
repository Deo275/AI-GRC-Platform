"""Safe CSV Export Formatter with Formula Injection (CSV Injection) Protection.

Defensive Guarantees:
- Enforces MAX_REPORT_ROWS (10,000) ceiling; rejects oversized datasets rather than silently truncating.
- Protects against spreadsheet formula injection (OWASP CSV Injection): prepends a single quote
  to any string value starting with dangerous calculation characters ('=', '+', '-', '@', '\t', '\r').
- Includes standard compliance disclaimer and report metadata header.
"""

import csv
import io
from typing import Any, List, Optional
from datetime import datetime

MAX_REPORT_ROWS = 10000
DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

STANDARD_DISCLAIMER = (
    "DISCLAIMER: This report is generated automatically by the AI-GRC Platform for internal "
    "risk management, vulnerability prioritization, and compliance tracking purposes. It does "
    "not constitute formal legal counsel, regulatory certification, or guarantee of third-party audit attestation."
)


def sanitize_csv_cell(val: Any) -> Any:
    """Neutralize potential CSV formula injection attacks on spreadsheet applications.

    Prepends a single quote (') to any string beginning with characters that trigger
    formula execution in Excel, Google Sheets, or LibreOffice Calc.
    """
    if val is None:
        return ""
    if isinstance(val, (int, float, bool)):
        return val

    s = str(val)
    if s.startswith(DANGEROUS_PREFIXES):
        return f"'{s}"
    return s


def build_csv_report(
    headers: List[str],
    rows: List[List[Any]],
    title: str,
    generated_at: Optional[datetime] = None,
    disclaimer: str = STANDARD_DISCLAIMER,
) -> str:
    """Assemble a complete CSV report with metadata comments, headers, and sanitized rows.

    Raises:
        ValueError: If row count exceeds MAX_REPORT_ROWS (no silent truncation permitted).
    """
    if len(rows) > MAX_REPORT_ROWS:
        raise ValueError(
            f"Report '{title}' query returned {len(rows)} rows, exceeding the maximum "
            f"supported export limit of {MAX_REPORT_ROWS} rows. Please apply query filters "
            f"to narrow the export range."
        )

    ts = generated_at or datetime.utcnow()
    output = io.StringIO()

    # Prepend UTF-8 BOM so Excel opens non-ASCII characters seamlessly
    output.write("\ufeff")

    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # 1. Metadata comment header
    writer.writerow([f"# REPORT: {title}"])
    writer.writerow([f"# GENERATED_AT: {ts.isoformat()}Z"])
    writer.writerow([f"# TOTAL_ROWS: {len(rows)}"])
    writer.writerow([f"# {disclaimer}"])
    writer.writerow([])  # blank separator line

    # 2. Table Column Headers
    writer.writerow(headers)

    # 3. Data Rows with strict cell sanitization
    for row in rows:
        sanitized_row = [sanitize_csv_cell(cell) for cell in row]
        writer.writerow(sanitized_row)

    return output.getvalue()
