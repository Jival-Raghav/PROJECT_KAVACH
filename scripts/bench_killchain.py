"""Run the kill-chain pipeline on the dataset and write reports/killchain_benchmark.{md,json}.

Usage (from the repo root):  python scripts/bench_killchain.py [--skip-ingest]
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from killchain.cli import main  # noqa: E402

if __name__ == "__main__":
    args = sys.argv[1:]
    main(["run", *args])
    main(["bench"])
