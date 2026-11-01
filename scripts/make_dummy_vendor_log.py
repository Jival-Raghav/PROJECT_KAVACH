"""Write a dummy "Acme NGFW" JSON-lines log by rewriting a FortiGate log, to exercise the
learned-schema parser end to end (batch and live).

    python scripts/make_dummy_vendor_log.py IN.log OUT.jsonl [--lines N] [--write-schema]

--write-schema also (re)writes config/log_sources/acme_ngfw.yaml, the reviewed schema that
`choose_parser` picks automatically for Acme logs.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO / "backend")]

from killchain.onboard import save_schema  # noqa: E402
from tests.kc_vendor import SCHEMA, to_acme  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("src")
    p.add_argument("out")
    p.add_argument("--lines", type=int, default=0, help="stop after this many input lines (0 = all)")
    p.add_argument("--write-schema", action="store_true")
    a = p.parse_args()
    if a.write_schema:
        save_schema(SCHEMA, REPO / "config/log_sources/acme_ngfw.yaml")
    read = written = 0
    with open(a.src, "rb") as fin, open(a.out, "w", encoding="utf-8") as fout:
        for raw in fin:
            read += 1
            if a.lines and read > a.lines:
                break
            try:
                line = to_acme(raw.decode("utf-8"))
            except UnicodeDecodeError:
                line = None
            if line:
                fout.write(line + "\n")
                written += 1
    print(f"read {read - (1 if a.lines and read > a.lines else 0):,} lines, wrote {written:,} "
          f"Acme NGFW lines to {a.out}")


if __name__ == "__main__":
    main()
