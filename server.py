"""Giao diện web local cho Apple No2FA Password Tool."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import secrets
import threading
import time
import webbrowser
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from apple_no2fa_password_tool import AppleToolError, auto_change_pass, parse_account_data


APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web" if (APP_DIR / "web" / "index.html").is_file() else APP_DIR
MAX_BODY_BYTES = 64 * 1024
SERVER_TOKEN = secrets.token_urlsafe(32)
CLOUD_MODE = os.environ.get("CLOUD_MODE", "").lower() == "true" or bool(
    os.environ.get("RENDER")
)


@dataclass
class Job:
    id: str
    token: str
    email: str
    status: str = "queued"
    message: str = "Đang xếp hàng"
    new_password: str | None = None
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def public_data(self) -> dict[str, object]:
        data = asdict(self)
        data.pop("token", None)
        data.pop("created_at", None)
        data.pop("updated_at", None)
        return data


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


def _clean_text(value: object, field_name: str, max_length: int = 300) -> str:
    if not isinstance(value, str):
        raise AppleToolError(f"{field_name} không hợp lệ")
    value = value.strip()
    if not value:
        raise AppleToolError(f"Chưa nhập {field_name}")
    if len(value) > max_length or "\x00" in value:
        raise AppleToolError(f"{field_name} quá dài hoặc không hợp lệ")
    return value


def _escape_pipe(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def build_account_line(payload: dict[str, object]) -> str:
    email = _clean_text(payload.get("email"), "Apple ID", 254)
    password = _clean_text(payload.get("password"), "mật khẩu hiện tại", 256)
    birth_date = _clean_text(payload.get("birth_date"), "ngày sinh", 20)
    questions = payload.get("questions")
    if not isinstance(questions, list) or len(questions) != 3:
        raise AppleToolError("Cần nhập đủ 3 câu hỏi bảo mật")

    fields = [email, password, birth_date]
    for index, item in enumerate(questions, start=1):
        if not isinstance(item, dict):
            raise AppleToolError(f"Câu hỏi {index} không hợp lệ")
        fields.extend(
            (
                _clean_text(item.get("question"), f"câu hỏi {index}"),
                _clean_text(item.get("answer"), f"câu trả lời {index}"),
            )
        )
    account_line = "|".join(_escape_pipe(value) for value in fields)
    parse_account_data(account_line)
    return account_line


def _remove_expired_jobs() -> None:
    cutoff = time.time() - 60 * 60
    with JOBS_LOCK:
        expired = [job_id for job_id, job in JOBS.items() if job.updated_at < cutoff]
        for job_id in expired:
            JOBS.pop(job_id, None)


def _has_active_job() -> bool:
    return any(job.status in {"queued", "running"} for job in JOBS.values())


def _update_job(job_id: str, **changes: object) -> None:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        for key, value in changes.items():
            setattr(job, key, value)
        job.updated_at = time.time()


def _run_job(
    job_id: str,
    account_line: str,
    password_length: int,
    show_browser: bool,
) -> None:
    _update_job(job_id, status="running", message="Đang khởi động")

    def progress(message: str) -> None:
        _update_job(job_id, status="running", message=message)

    try:
        result = auto_change_pass(
            account_line,
            password_length,
            headless=not show_browser,
            slow_mo=70 if show_browser else 0,
            timeout_ms=45_000,
            progress_callback=progress,
        )
    except AppleToolError as exc:
        _update_job(job_id, status="failed", message="Không hoàn tất", error=str(exc))
    except Exception as exc:
        print(f"Lỗi nội bộ: {type(exc).__name__}: {exc}")
        _update_job(
            job_id,
            status="failed",
            message="Không hoàn tất",
            error="Lỗi trình duyệt hoặc kết nối, hãy mở chế độ hiện trình duyệt và thử lại",
        )
    else:
        _update_job(
            job_id,
            status="succeeded",
            message="Đổi mật khẩu thành công",
            new_password=result.new_password,
        )
    finally:
        # Xóa tham chiếu sớm; dữ liệu tài khoản không được ghi xuống ổ đĩa.
        account_line = ""


class AppHandler(BaseHTTPRequestHandler):
    server_version = "AppleNo2FA/1.0"

    def log_message(self, format: str, *args: object) -> None:
        # Không ghi URL/API polling chứa mã job ra terminal.
        if not self.path.startswith("/api/jobs/"):
            super().log_message(format, *args)

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        return parsed.scheme in {"http", "https"} and parsed.netloc == self.headers.get("Host")

    def _authorized(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-App-Token", ""), SERVER_TOKEN)

    def _read_json(self) -> dict[str, object]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise AppleToolError("Yêu cầu không hợp lệ")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise AppleToolError("Yêu cầu không hợp lệ") from exc
        if length <= 0 or length > MAX_BODY_BYTES:
            raise AppleToolError("Dữ liệu gửi lên quá lớn hoặc đang trống")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AppleToolError("Dữ liệu JSON không hợp lệ") from exc
        if not isinstance(payload, dict):
            raise AppleToolError("Dữ liệu không hợp lệ")
        return payload

    def _serve_file(self, relative_path: str) -> None:
        allowed = {
            "index.html": WEB_DIR / "index.html",
            "app.css": WEB_DIR / "app.css",
            "app.js": WEB_DIR / "app.js",
        }
        path = allowed.get(relative_path)
        if not path or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{mime}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._serve_file("index.html")
            return
        if parsed.path == "/app.css":
            self._serve_file("app.css")
            return
        if parsed.path == "/app.js":
            self._serve_file("app.js")
            return
        if parsed.path == "/api/config":
            self._send_json(
                HTTPStatus.OK,
                {"app_token": SERVER_TOKEN, "cloud_mode": CLOUD_MODE},
            )
            return
        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job or not secrets.compare_digest(
                    self.headers.get("X-Job-Token", ""), job.token
                ):
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy tác vụ"})
                    return
                payload = job.public_data()
            self._send_json(HTTPStatus.OK, payload)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path != "/api/jobs":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if not self._same_origin() or not self._authorized():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Phiên giao diện không hợp lệ"})
            return
        try:
            payload = self._read_json()
            account_line = build_account_line(payload)
            length_value = payload.get("password_length", 12)
            if isinstance(length_value, bool):
                raise ValueError
            password_length = int(length_value)
            if not 8 <= password_length <= 32:
                raise AppleToolError("Độ dài mật khẩu mới phải từ 8 đến 32")
            show_browser = payload.get("show_browser", True) is not False and not CLOUD_MODE
        except (AppleToolError, TypeError, ValueError) as exc:
            message = str(exc) if str(exc) else "Dữ liệu không hợp lệ"
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": message})
            return

        _remove_expired_jobs()
        with JOBS_LOCK:
            if _has_active_job():
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"error": "Đang xử lý một tài khoản khác, hãy chờ hoàn tất"},
                )
                return
            job = Job(
                id=secrets.token_urlsafe(18),
                token=secrets.token_urlsafe(24),
                email=parse_account_data(account_line).email,
            )
            JOBS[job.id] = job

        thread = threading.Thread(
            target=_run_job,
            args=(job.id, account_line, password_length, show_browser),
            daemon=True,
        )
        thread.start()
        self._send_json(
            HTTPStatus.ACCEPTED,
            {"job_id": job.id, "job_token": job.token},
        )

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/jobs/"):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        job_id = parsed.path.rsplit("/", 1)[-1]
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job or not secrets.compare_digest(
                self.headers.get("X-Job-Token", ""), job.token
            ):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Không tìm thấy tác vụ"})
                return
            if job.status in {"queued", "running"}:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"error": "Không thể xóa khi tác vụ đang chạy"},
                )
                return
            JOBS.pop(job_id, None)
        self._send_json(HTTPStatus.OK, {"ok": True})


def main() -> int:
    parser = argparse.ArgumentParser(description="Apple No2FA local web setup")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8765")))
    parser.add_argument("--no-open", action="store_true")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), AppHandler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"Giao diện đang chạy tại {url}")
    print("Nhấn Ctrl+C để tắt")
    if not args.no_open:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
