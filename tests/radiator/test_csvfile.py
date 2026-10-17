from datetime import UTC, datetime

import pytest

from yk_portal.radiator import csvfile
from yk_portal.radiator.csvfile import CsvError

HEADER = (
    b"username,public_id,private_id,aes_key,password,active,created,accessed,counter,low,high,label"
)


def test_header_is_radiator_yubikeys():
    assert csvfile.HEADER.encode() == HEADER
    assert csvfile.OLD_HEADER == csvfile.HEADER.removesuffix(",label")


@pytest.mark.parametrize(
    ("values", "line"),
    [
        (["a", "b"], "a,b\n"),
        (["", ""], ",\n"),
        (["spare, slot 2", "x"], '"spare, slot 2",x\n'),
        (['say "hi"', "x"], '"say ""hi""",x\n'),
        (["two\nlines", "cr\r"], '"two\nlines","cr\r"\n'),
        (["ümlaut ok", "'single'"], "ümlaut ok,'single'\n"),
    ],
)
def test_format_row_quotes_as_radiator_yubikey_does(values, line):
    assert csvfile.format_row(values) == line


def test_times():
    moment = datetime(2026, 10, 16, 9, 5, 3, 999999, tzinfo=UTC)
    assert csvfile.format_time(moment) == "2026-10-16 09:05:03"
    assert csvfile.format_time(None) == ""
    assert csvfile.parse_time("2026-10-16 09:05:03") == moment.replace(microsecond=0)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "2026-10-16",
        "2026-10-16T09:05:03",
        "2026-10-16 09:05:03+00",
        "2026-02-30 00:00:00",
        "2026-13-01 00:00:00",
    ],
)
def test_parse_time_rejects_other_text(text):
    assert csvfile.parse_time(text) is None


def test_read():
    data = HEADER + b'\nalice,a,b,c,d,1,,,0,0,0,"spare, ""old""\nslot 2"\r\n\nbob,a,,,,,,,,,,x\n'
    columns, rows = csvfile.read(data)
    assert columns == 12
    assert rows == [
        (
            2,
            [
                b"alice",
                b"a",
                b"b",
                b"c",
                b"d",
                b"1",
                b"",
                b"",
                b"0",
                b"0",
                b"0",
                b'spare, "old"\nslot 2',
            ],
        ),
        (5, [b"bob", b"a", b"", b"", b"", b"", b"", b"", b"", b"", b"", b"x"]),
    ]


def test_read_an_export_from_before_radiator_yubikey_1_8_0():
    columns, rows = csvfile.read(csvfile.OLD_HEADER.encode() + b"\nalice,x\n")
    assert columns == 11
    assert rows == [(2, [b"alice", b"x"])]


def test_read_without_a_final_line_break():
    assert csvfile.read(HEADER + b"\na,b")[1] == [(2, [b"a", b"b"])]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "empty"),
        (b"\n\n", "empty"),
        (b"username,public_id\nalice,x\n", "not an export file"),
        (b"alice,x\n" + HEADER + b"\n", "not an export file"),
        (HEADER + b'\nali"ce,x\n', "line 2: malformed CSV"),
        (HEADER + b'\n"alice,x\n', "line 2: malformed CSV"),
        (HEADER + b'\n"alice"x,y\n', "line 2: malformed CSV"),
        (HEADER + b"\nalice\rx\n", "line 2: malformed CSV"),
    ],
)
def test_read_rejects_a_file_that_is_not_an_export(data, message):
    with pytest.raises(CsvError, match=message):
        csvfile.read(data)
