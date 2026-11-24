import json
from pathlib import Path

from si.gallery import build_gallery


def test_gallery_rebuild_changes_when_core_bytes_change(tmp_path, monkeypatch):
    cases = tmp_path / "cases"
    case = cases / "sample"
    build = case / "build"
    build.mkdir(parents=True)
    (case / "ground_truth.json").write_text(json.dumps({"expected_top_hypothesis": "H-NULL"}))
    elf = build / "debug.elf"
    core = build / "debug.core"
    elf.write_bytes(b"ELF fixture placeholder")
    core.write_bytes(b"first")

    def pipeline(elf_path, core_path, out, case_name):
        # The gallery must call the pipeline again with the current core on each build.
        raw = Path(core_path).read_bytes()
        top = "H-NULL" if raw == b"first" else "H-WILD"
        status = "SUPPORTED" if top == "H-NULL" else "UNDETERMINED"
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "report.html").write_text(f"<p>{raw.hex()}</p>", encoding="utf-8")
        return {"hypotheses": [{"hypothesis": {"id": top}, "status": status}]}

    monkeypatch.setattr("si.gallery.investigate", pipeline)
    out = tmp_path / "dist"
    index_path = build_gallery(out, cases)
    first_index = index_path.read_text(encoding="utf-8")
    first_report = (out / "reports/sample/report.html").read_text(encoding="utf-8")

    core.write_bytes(b"modified core")
    build_gallery(out, cases)
    second_index = index_path.read_text(encoding="utf-8")
    second_report = (out / "reports/sample/report.html").read_text(encoding="utf-8")

    assert first_report != second_report
    assert "H-NULL" in first_index and "SUPPORTED" in first_index
    assert "H-WILD" in second_index and "UNDETERMINED" in second_index
    assert "srcdoc=cases[index].report_html" in second_index
