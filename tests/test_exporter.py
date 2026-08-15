import tracemalloc
import zipfile
from pathlib import Path

import pytest

from core.exporter import export_pages
from core.models import AssetRecord, SearchPage


async def hundred_thousand_records():
    for page_number in range(100):
        records = [AssetRecord(values={"host": f"asset-{page_number}-{index}"}) for index in range(1000)]
        yield SearchPage(records=records, fields=["host"], query='app="test"')


@pytest.mark.asyncio
async def test_hundred_thousand_jsonl_export_is_memory_bounded(tmp_path: Path):
    tracemalloc.start()
    path, count = await export_pages(hundred_thousand_records(), tmp_path / "assets.jsonl", "jsonl")
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert count == 100_000
    assert path.stat().st_size > 1_000_000
    assert peak < 25 * 1024 * 1024


async def two_records():
    yield SearchPage(
        query='app="test"',
        fields=["host", "title"],
        records=[
            AssetRecord(values={"host": "https://one.example", "title": "第一条"}),
            AssetRecord(values={"host": "https://two.example", "title": "第二条"}),
        ],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("format_name", ["csv", "xlsx"])
async def test_v2_export_formats_keep_all_rows_and_fields(tmp_path: Path, format_name: str):
    destination = tmp_path / f"assets.{format_name}"
    path, count = await export_pages(two_records(), destination, format_name)
    assert path == destination
    assert count == 2
    assert path.stat().st_size > 0
    if format_name == "csv":
        content = path.read_text(encoding="utf-8-sig")
        assert "host,title" in content
        assert "https://one.example,第一条" in content
        assert "https://two.example,第二条" in content


@pytest.mark.asyncio
async def test_xlsx_restores_fofamap_v2_table_style(tmp_path: Path):
    destination = tmp_path / "assets.xlsx"
    path, count = await export_pages(two_records(), destination, "xlsx")
    assert count == 2
    with zipfile.ZipFile(path) as archive:
        styles = archive.read("xl/styles.xml").decode()
        sheet = archive.read("xl/worksheets/sheet1.xml").decode()
    assert "4BACC6" in styles.upper()
    assert "freezePanes" in sheet or "pane" in sheet
    assert "autoFilter" in sheet
    assert "<v>1</v>" in sheet


@pytest.mark.asyncio
async def test_streaming_xlsx_workbook_keeps_one_sheet_per_query(tmp_path: Path):
    from core.exporter import StreamingXlsxWorkbook

    book = StreamingXlsxWorkbook(tmp_path / "batch.xlsx")
    book.start_sheet('app="one"')
    book.write_page(
        SearchPage(
            query='app="one"',
            fields=["host"],
            records=[AssetRecord(values={"host": "https://one.example"})],
        )
    )
    book.start_sheet('app="two"')
    book.write_page(
        SearchPage(
            query='app="two"',
            fields=["host"],
            records=[AssetRecord(values={"host": "https://two.example"})],
        )
    )
    path = book.close()
    assert path.stat().st_size > 0
    assert book.count == 2
