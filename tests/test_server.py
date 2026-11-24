import threading
from http.server import HTTPServer
from urllib.request import Request, urlopen

from si.server import make_handler


def test_server_upload_routes_artifacts_to_pipeline_without_execution(tmp_path, monkeypatch):
    def pipeline(elf, core, out, case_name):
        assert elf.read_bytes() == b"ELF bytes"
        assert core.read_bytes() == b"core bytes"
        assert case_name == "Uploaded artifacts"
        report_dir = out
        report_dir.mkdir(parents=True)
        (report_dir / "report.html").write_text("<p>pipeline report</p>", encoding="utf-8")
        return {}

    monkeypatch.setattr("si.server.investigate", pipeline)
    cases_dir = tmp_path / "cases"
    (cases_dir / "example").mkdir(parents=True)
    (cases_dir / "example" / "ground_truth.json").write_text("{}", encoding="utf-8")
    server = HTTPServer(("127.0.0.1", 0), make_handler(cases_dir))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    boundary = "si-test-boundary"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"elf\"; filename=\"sample.elf\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + b"ELF bytes\r\n" + (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"core\"; filename=\"sample.core\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + b"core bytes\r\n" + f"--{boundary}--\r\n".encode()
    try:
        request = Request(f"http://127.0.0.1:{server.server_port}/investigate", data=body, method="POST",
                          headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        with urlopen(request) as response:
            page = response.read().decode("utf-8")
        assert "pipeline report" in page
        assert "example — build ELF/core pair on Linux first" in page
        assert "Linux x86-64 ELF core (ET_CORE" in page
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
