"""Memory-bounded JSONL/CSV exports and single-pass XLSX output."""

from __future__ import annotations

import csv
import json
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import xlsxwriter

from core.models import AssetRecord, SearchPage

_INVALID_SHEET_CHARS = re.compile(r"[:\\/?*\[\]]")
_EXCEL_MAX_URLS = 65_000
_WIDE_HEADERS = {"URL", "HOST", "TITLE", "HEADER", "BANNER", "CERT", "BODY"}
_NARROW_HEADERS = {"ID", "PORT", "CTRY", "COUNTRY", "PROTOCOL", "STATUS_CODE", "BASE_PROTOCOL", "REGION", "CITY"}
_CENTER_FIELDS = {"port", "protocol", "country", "region", "city", "status_code", "base_protocol"}
_LINK_FIELDS = {"host", "url", "link"}


def unique_sheet_name(name: str, used: set[str]) -> str:
    cleaned = _INVALID_SHEET_CHARS.sub("_", name).strip() or "assets"
    cleaned = cleaned[:31]
    candidate = cleaned
    index = 2
    while candidate in used:
        suffix = f"_{index}"
        candidate = f"{cleaned[: 31 - len(suffix)]}{suffix}"
        index += 1
    used.add(candidate)
    return candidate


def _column_width(header: str) -> int:
    if header in _WIDE_HEADERS:
        return 36
    if header in _NARROW_HEADERS:
        return 12
    return 22


@dataclass
class XlsxTheme:
    header: Any
    cell: Any
    center: Any
    row_id: Any
    url: Any

    @classmethod
    def create(cls, workbook: xlsxwriter.Workbook) -> XlsxTheme:
        # Match FofaMap 2.0 core/excel.py: teal header, bordered cells, ID column.
        return cls(
            header=workbook.add_format(
                {
                    "bold": True,
                    "font_color": "white",
                    "bg_color": "#4BACC6",
                    "align": "center",
                    "valign": "vcenter",
                    "border": 1,
                    "font_size": 12,
                }
            ),
            cell=workbook.add_format({"border": 1, "align": "left", "valign": "vcenter", "text_wrap": False}),
            center=workbook.add_format({"border": 1, "align": "center", "valign": "vcenter", "text_wrap": False}),
            row_id=workbook.add_format({"border": 1, "align": "center", "valign": "vcenter"}),
            url=workbook.add_format(
                {
                    "border": 1,
                    "align": "left",
                    "valign": "vcenter",
                    "text_wrap": False,
                    "font_color": "blue",
                    "underline": 1,
                }
            ),
        )


class StyledXlsxSheet:
    def __init__(self, worksheet: Any, theme: XlsxTheme) -> None:
        self.worksheet = worksheet
        self.theme = theme
        self.fields: list[str] = []
        self.row = 0
        self._url_count = 0

    def start(self, fields: list[str]) -> None:
        self.fields = fields
        headers = ["ID", *[field.upper() for field in fields]]
        self.worksheet.set_row(0, 25)
        self.worksheet.freeze_panes(1, 0)
        self.worksheet.set_default_row(18)
        for column, header in enumerate(headers):
            self.worksheet.write(0, column, header, self.theme.header)
            self.worksheet.set_column(column, column, _column_width(header))
        last_col = max(len(headers) - 1, 0)
        self.worksheet.autofilter(0, 0, 1_048_575, last_col)
        self.row = 1

    def write_record(self, record: AssetRecord) -> None:
        self.worksheet.write(self.row, 0, self.row, self.theme.row_id)
        for column, field in enumerate(self.fields, start=1):
            self._write_cell(column, field, record.values.get(field))
        self.row += 1

    def _write_cell(self, column: int, field: str, value: Any) -> None:
        if value is None or value == "":
            self.worksheet.write_blank(self.row, column, None, self.theme.cell)
            return
        if (
            field.lower() in _LINK_FIELDS
            and isinstance(value, str)
            and value.startswith(("http://", "https://"))
            and len(value) <= 2079
            and self._url_count < _EXCEL_MAX_URLS
        ):
            self.worksheet.write_url(self.row, column, value, self.theme.url, value)
            self._url_count += 1
            return
        cell_format = self.theme.center if field.lower() in _CENTER_FIELDS else self.theme.cell
        if isinstance(value, bool):
            self.worksheet.write_boolean(self.row, column, value, cell_format)
            return
        if isinstance(value, (int, float)):
            self.worksheet.write_number(self.row, column, value, cell_format)
            return
        self.worksheet.write_string(self.row, column, str(value), cell_format)


class StreamingXlsxWorkbook:
    """Constant-memory workbook that can receive one FOFA query per sheet."""

    def __init__(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.destination = destination
        self.workbook = xlsxwriter.Workbook(str(destination), {"constant_memory": True})
        self.theme = XlsxTheme.create(self.workbook)
        self.count = 0
        self._used_names: set[str] = set()
        self._sheet: StyledXlsxSheet | None = None

    def start_sheet(self, name: str) -> None:
        worksheet = self.workbook.add_worksheet(unique_sheet_name(name, self._used_names))
        self._sheet = StyledXlsxSheet(worksheet, self.theme)

    def write_page(self, page: SearchPage) -> None:
        if self._sheet is None:
            raise RuntimeError("start_sheet() must be called before write_page()")
        if not self._sheet.fields:
            self._sheet.start(page.fields)
        elif page.fields != self._sheet.fields:
            raise ValueError("FOFA fields changed during export")
        for record in page.records:
            self._sheet.write_record(record)
            self.count += 1

    def close(self) -> Path:
        self.workbook.close()
        return self.destination


async def export_pages(pages: AsyncIterator[SearchPage], destination: Path, format: str) -> tuple[Path, int]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    fields: list[str] = []
    if format == "jsonl":
        with destination.open("w", encoding="utf-8") as handle:
            async for page in pages:
                fields = page.fields
                for record in page.records:
                    handle.write(json.dumps(record.values, ensure_ascii=False) + "\n")
                    count += 1
        return destination, count

    if format == "csv":
        with destination.open("w", encoding="utf-8-sig", newline="") as handle:
            writer: csv.DictWriter | None = None
            async for page in pages:
                if writer is None:
                    fields = page.fields
                    writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="raise")
                    writer.writeheader()
                for record in page.records:
                    writer.writerow(record.values)
                    count += 1
        return destination, count

    if format != "xlsx":
        raise ValueError(f"unsupported export format: {format}")
    workbook = xlsxwriter.Workbook(str(destination), {"constant_memory": True})
    sheet = StyledXlsxSheet(workbook.add_worksheet("FOFA资产"), XlsxTheme.create(workbook))
    try:
        async for page in pages:
            if not fields:
                fields = page.fields
                sheet.start(fields)
            if page.fields != fields:
                raise ValueError("FOFA fields changed during export")
            for record in page.records:
                sheet.write_record(record)
                count += 1
    finally:
        workbook.close()
    return destination, count


async def records_to_pages(records: list[AssetRecord], fields: list[str], query: str = "") -> AsyncIterator[SearchPage]:
    yield SearchPage(records=records, fields=fields, query=query)
