r"""Đổi mật khẩu Apple Account no-2FA bằng câu hỏi bảo mật.

Chỉ sử dụng với tài khoản thuộc sở hữu của bạn hoặc tài khoản bạn được phép
quản lý. Tool không vượt CAPTCHA, 2FA hay mã xác minh thiết bị.

Định dạng dữ liệu tương thích code cũ:
    email:mat_khau_cu:DD/MM/YYYY:cau_hoi_1:tra_loi_1:cau_hoi_2:tra_loi_2:cau_hoi_3:tra_loi_3

Nếu dữ liệu có dấu ``:`` bên trong một trường, hãy escape thành ``\:`` hoặc
dùng dấu ``|`` làm dấu phân cách.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import getpass
import re
import secrets
import string
import sys
import time
import unicodedata
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Callable, Iterable, Sequence


SIGN_IN_URL = "https://account.apple.com/sign-in"
MANAGE_URL = "https://account.apple.com/account/manage"


class AppleToolError(RuntimeError):
    """Lỗi có thể hiển thị an toàn cho người dùng tool."""


class QuestionMatchError(AppleToolError):
    """Không thể ghép chắc chắn câu hỏi Apple với dữ liệu đã lưu."""


@dataclass(frozen=True)
class SecurityQA:
    question: str
    answer: str


@dataclass(frozen=True)
class AccountData:
    email: str
    password: str
    birth_date: date
    questions: tuple[SecurityQA, SecurityQA, SecurityQA]


@dataclass(frozen=True)
class QuestionMatch:
    qa: SecurityQA
    index: int
    score: float


@dataclass(frozen=True)
class ChangeResult:
    email: str
    new_password: str


ProgressCallback = Callable[[str], None]


def _emit_progress(callback: ProgressCallback | None, message: str) -> None:
    if callback is None:
        return
    try:
        callback(message)
    except Exception:
        # Callback giao diện không được phép làm hỏng luồng đổi mật khẩu.
        pass


def _split_account_line(account_data: str) -> list[str]:
    text = account_data.strip()
    if not text:
        raise AppleToolError("Dữ liệu tài khoản đang trống")

    # Ưu tiên | vì câu hỏi tiếng Việt đôi khi chứa dấu hai chấm.
    delimiter = "|" if text.count("|") >= 8 else ":"
    try:
        row = next(
            csv.reader(
                [text],
                delimiter=delimiter,
                escapechar="\\",
                quotechar='"',
                skipinitialspace=True,
            )
        )
    except (csv.Error, StopIteration) as exc:
        raise AppleToolError("Không đọc được dòng dữ liệu tài khoản") from exc

    parts = [part.strip() for part in row]
    if len(parts) != 9:
        raise AppleToolError(
            "Dữ liệu phải có đúng 9 trường: ID, mật khẩu, ngày sinh và 3 cặp câu hỏi/trả lời"
        )
    if any(not part for part in parts):
        raise AppleToolError("Dữ liệu có trường đang để trống")
    return parts


def _parse_birth_date(value: str) -> date:
    cleaned = value.strip()
    for pattern in ("%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(cleaned, pattern).date()
        except ValueError:
            pass
    raise AppleToolError(
        "Ngày sinh không hợp lệ, hãy dùng DD/MM/YYYY (ví dụ 15/05/2000)"
    )


def parse_account_data(account_data: str) -> AccountData:
    parts = _split_account_line(account_data)
    email, password = parts[0], parts[1]
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise AppleToolError("Apple Account/email không hợp lệ")

    questions = tuple(
        SecurityQA(parts[index], parts[index + 1]) for index in (3, 5, 7)
    )
    normalized_questions = [_normalize_text(item.question) for item in questions]
    if len(set(normalized_questions)) != 3:
        raise AppleToolError("Ba câu hỏi bảo mật phải khác nhau")

    return AccountData(
        email=email,
        password=password,
        birth_date=_parse_birth_date(parts[2]),
        questions=questions,  # type: ignore[arg-type]
    )


def generate_random_password(length: int = 12) -> str:
    """Tạo mật khẩu mạnh, luôn có chữ hoa, chữ thường và chữ số."""
    if length < 8:
        length = 8

    alphabet = string.ascii_letters + string.digits
    rng = secrets.SystemRandom()
    while True:
        chars = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
        ]
        chars.extend(secrets.choice(alphabet) for _ in range(length - 3))
        rng.shuffle(chars)
        password = "".join(chars)
        if not re.search(r"(.)\1\1", password):
            return password


def _normalize_text(value: str) -> str:
    value = value.casefold().replace("đ", "d")
    value = "".join(
        char
        for char in unicodedata.normalize("NFKD", value)
        if not unicodedata.combining(char)
    )
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


_STOP_WORDS = {
    "ai",
    "ban",
    "cai",
    "cho",
    "cua",
    "da",
    "duoc",
    "gi",
    "khi",
    "la",
    "luc",
    "mot",
    "nao",
    "nguoi",
    "ten",
    "the",
    "thi",
    "where",
    "what",
    "when",
    "which",
    "who",
    "was",
    "were",
    "is",
    "are",
    "your",
    "you",
    "the",
    "a",
    "an",
    "of",
    "in",
    "on",
    "did",
    "do",
    "name",
}


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in _normalize_text(value).split()
        if token not in _STOP_WORDS and len(token) > 1
    }


# Các nhóm này giúp ghép được cả câu viết tắt, bản dịch Việt/Anh và cách diễn đạt
# khác nhau. So khớp token vẫn là lớp dự phòng cho câu hỏi chưa nằm trong bảng.
_QUESTION_CONCEPTS: dict[str, tuple[str, ...]] = {
    "childhood_nickname": (
        "biet danh",
        "biet danh luc nho",
        "biet danh thoi tho au",
        "childhood nickname",
        "nickname as a child",
    ),
    "first_pet": (
        "thu cung",
        "vat nuoi",
        "thu cung dau tien",
        "con vat nuoi dau tien",
        "pet",
        "first pet",
    ),
    "best_school_friend": (
        "ban than",
        "ban than thoi trung hoc",
        "ban than o truong",
        "best friend",
        "best friend in high school",
        "best school friend",
    ),
    "first_food": (
        "hoc nau",
        "mon dau tien hoc nau",
        "mon an dau tien nau",
        "learned to cook",
        "first thing learned to cook",
        "first food cooked",
    ),
    "first_movie": (
        "xem o rap",
        "phim dau tien xem o rap",
        "bo phim dau tien tai rap",
        "movie in cinema",
        "film in theater",
        "first film in theater",
        "first movie in cinema",
    ),
    "first_flight": (
        "di may bay",
        "lan dau di may bay",
        "noi den dau tien bang may bay",
        "flew on a plane",
        "first time flew on a plane",
        "first flight destination",
    ),
    "dream_job": (
        "cong viec mo uoc",
        "nghe nghiep mo uoc",
        "dream job",
    ),
    "childrens_book": (
        "sach thieu nhi",
        "sach tre em",
        "sach thieu nhi yeu thich",
        "sach tre em yeu thich",
        "children book",
        "childrens book",
        "favorite children book",
        "favourite childrens book",
    ),
    "first_car": (
        "xe dau tien",
        "mau xe dau tien",
        "kieu xe dau tien",
        "model of first car",
        "first car",
    ),
    "film_character": (
        "ngoi sao dien anh",
        "nhan vat dien anh",
        "ngoi sao dien anh yeu thich",
        "nhan vat dien anh yeu thich",
        "film star",
        "movie character",
        "favorite film star",
        "favourite movie character",
    ),
    "singer_band": (
        "ca si",
        "ban nhac",
        "ca si yeu thich thoi trung hoc",
        "ban nhac yeu thich thoi trung hoc",
        "singer",
        "band",
        "favorite singer in high school",
        "favorite band in high school",
    ),
    "teacher": (
        "giao vien",
        "thay co",
        "giao vien yeu thich",
        "thay co yeu thich",
        "teacher",
        "favorite teacher",
        "favourite teacher",
    ),
    "street_grew_up": (
        "con duong",
        "duong pho",
        "con duong noi lon len",
        "duong pho luc nho",
        "street",
        "street where grew up",
        "street you grew up on",
    ),
    "oldest_cousin": (
        "anh chi em ho",
        "anh chi em ho lon tuoi nhat",
        "nguoi ho hang lon tuoi nhat",
        "cousin",
        "oldest cousin",
    ),
    "first_beach": (
        "bai bien",
        "bai bien dau tien",
        "beach",
        "first beach visited",
    ),
    "first_album": (
        "album",
        "dia nhac",
        "album dau tien mua",
        "dia nhac dau tien mua",
        "first album purchased",
        "first album bought",
    ),
    "sports_team": (
        "doi the thao",
        "doi the thao yeu thich",
        "sports team",
        "favorite sports team",
        "favourite sports team",
    ),
    "january_2000": (
        "ngay 1 1 2000 o dau",
        "ngay 01 01 2000 o dau",
        "january 1 2000",
        "1 1 2000",
    ),
}


def _concepts(value: str) -> set[str]:
    normalized = _normalize_text(value)
    result: set[str] = set()
    for concept, aliases in _QUESTION_CONCEPTS.items():
        if any(_normalize_text(alias) in normalized for alias in aliases):
            result.add(concept)
    return result


def _question_score(stored_question: str, apple_question: str) -> float:
    stored = _normalize_text(stored_question)
    asked = _normalize_text(apple_question)
    if not stored or not asked:
        return 0.0

    stored_tokens = _tokens(stored)
    asked_tokens = _tokens(asked)
    overlap = stored_tokens & asked_tokens
    coverage = len(overlap) / max(1, min(len(stored_tokens), len(asked_tokens)))
    union = stored_tokens | asked_tokens
    jaccard = len(overlap) / max(1, len(union))
    sequence = difflib.SequenceMatcher(None, stored, asked).ratio()

    score = 0.55 * coverage + 0.20 * jaccard + 0.25 * sequence
    if len(stored) >= 5 and (stored in asked or asked in stored):
        score = max(score, 0.97)
    if _concepts(stored) & _concepts(asked):
        score = max(score, 0.95)
    return min(score, 1.0)


def match_security_question(
    apple_question: str,
    stored_questions: Sequence[SecurityQA],
    excluded_indexes: Iterable[int] = (),
) -> QuestionMatch:
    excluded = set(excluded_indexes)
    candidates = sorted(
        (
            QuestionMatch(qa=qa, index=index, score=_question_score(qa.question, apple_question))
            for index, qa in enumerate(stored_questions)
            if index not in excluded
        ),
        key=lambda item: item.score,
        reverse=True,
    )
    if not candidates or candidates[0].score < 0.55:
        raise QuestionMatchError(
            f'Không nhận dạng được câu hỏi Apple: "{apple_question}"'
        )

    best = candidates[0]
    if (
        len(candidates) > 1
        and best.score < 0.90
        and best.score - candidates[1].score < 0.08
    ):
        raise QuestionMatchError(
            f'Câu hỏi Apple bị khớp mơ hồ: "{apple_question}"'
        )
    return best


class AppleAccountAutomator:
    EMAIL_SELECTORS = (
        "input#account_name_text_field",
        "input[name='accountName']",
        "input[autocomplete='username']",
        "input[type='email']",
    )
    PASSWORD_SELECTORS = (
        "input#password_text_field",
        "input[name='password']",
        "input[autocomplete='current-password']",
        "input[type='password']",
    )
    SIGN_IN_SELECTORS = (
        "button#sign-in",
        "button[type='submit']",
        "button:has-text('Đăng nhập')",
        "button:has-text('Sign In')",
    )
    DOB_INPUT_SELECTORS = (
        "input#birth_date",
        "input#date_of_birth",
        "input[name*='birth' i]",
        "input[id*='birth' i]",
    )
    ANSWER_INPUT_SELECTORS = (
        "input.security-answer",
        "input[name*='securityAnswer' i]",
        "input[id*='securityAnswer' i]",
        "input[name*='answer' i]",
        "input[id*='answer' i]",
    )
    QUESTION_LABEL_SELECTORS = (
        ".security-question-label",
        "[class*='security-question' i] label",
        "label[for*='securityAnswer' i]",
        "label[for*='answer' i]",
        "[data-testid*='question' i]",
    )
    CONTINUE_SELECTORS = (
        "button#continue-btn",
        "button[type='submit']",
        "button:has-text('Tiếp tục')",
        "button:has-text('Continue')",
        "button:has-text('Xác minh')",
        "button:has-text('Verify')",
    )

    def __init__(
        self,
        page: Any,
        account: AccountData,
        new_password: str,
        timeout_ms: int = 30_000,
    ) -> None:
        self.page = page
        self.account = account
        self.new_password = new_password
        self.timeout_ms = timeout_ms

    def _roots(self) -> list[Any]:
        # Apple đặt form đăng nhập trong iframe; Page và Frame đều có locator().
        return [self.page, *[frame for frame in self.page.frames if frame != self.page.main_frame]]

    @staticmethod
    def _visible_items(root: Any, selector: str) -> list[Any]:
        try:
            locator = root.locator(selector)
            count = min(locator.count(), 10)
        except Exception:
            return []
        result: list[Any] = []
        for index in range(count):
            item = locator.nth(index)
            try:
                if item.is_visible(timeout=150):
                    result.append(item)
            except Exception:
                continue
        return result

    def _find_all(self, selectors: Sequence[str], timeout_ms: int = 0) -> list[Any]:
        deadline = time.monotonic() + timeout_ms / 1000
        while True:
            for root in self._roots():
                for selector in selectors:
                    items = self._visible_items(root, selector)
                    if items:
                        return items
            if time.monotonic() >= deadline:
                return []
            self.page.wait_for_timeout(200)

    def _find_one(self, selectors: Sequence[str], timeout_ms: int | None = None) -> Any:
        items = self._find_all(
            selectors,
            self.timeout_ms if timeout_ms is None else timeout_ms,
        )
        if not items:
            raise AppleToolError(f"Không tìm thấy thành phần Apple cần thiết: {selectors[0]}")
        return items[0]

    def _click(self, selectors: Sequence[str], timeout_ms: int | None = None) -> None:
        self._find_one(selectors, timeout_ms).click()

    def _page_text(self) -> str:
        chunks: list[str] = []
        for root in self._roots():
            try:
                chunks.append(root.locator("body").inner_text(timeout=500))
            except Exception:
                pass
        return _normalize_text(" ".join(chunks))

    def _has_visible(self, selectors: Sequence[str]) -> bool:
        return bool(self._find_all(selectors, 0))

    def _raise_for_blocker(self) -> None:
        text = self._page_text()
        captcha_selectors = (
            "iframe[src*='captcha' i]",
            "[class*='captcha' i]",
            "[id*='captcha' i]",
        )
        two_factor_selectors = (
            "input[autocomplete='one-time-code']",
            "input[inputmode='numeric'][maxlength='1']",
            "[data-testid*='verification-code' i]",
        )
        if self._has_visible(captcha_selectors) or any(
            marker in text for marker in ("captcha", "xac minh ban khong phai robot")
        ):
            raise AppleToolError("Apple đang yêu cầu CAPTCHA, cần xử lý thủ công")
        if self._has_visible(two_factor_selectors) or any(
            marker in text
            for marker in (
                "two factor authentication",
                "verification code",
                "ma xac minh",
                "trusted phone number",
                "so dien thoai tin cay",
            )
        ):
            raise AppleToolError("Tài khoản đang yêu cầu 2FA hoặc mã xác minh, tool đã dừng")

    def sign_in(self) -> None:
        self.page.goto(SIGN_IN_URL, wait_until="domcontentloaded")
        email_input = self._find_one(self.EMAIL_SELECTORS)
        email_input.fill(self.account.email)
        self._click(self.SIGN_IN_SELECTORS)

        password_input = self._find_one(self.PASSWORD_SELECTORS)
        password_input.fill(self.account.password)
        self._click(self.SIGN_IN_SELECTORS)
        self.page.wait_for_timeout(1_000)
        self._raise_for_blocker()

    def fill_birth_date_if_requested(self) -> bool:
        # Chờ đúng challenge xuất hiện nhưng thoát sớm nếu Apple chuyển thẳng
        # sang câu hỏi, tránh lỗi do trang tải ngày sinh chậm.
        deadline = time.monotonic() + min(self.timeout_ms, 10_000) / 1000
        inputs: list[Any] = []
        while time.monotonic() < deadline:
            self._raise_for_blocker()
            inputs = self._find_all(self.DOB_INPUT_SELECTORS, 0)
            if inputs:
                break
            if self._has_visible(self.ANSWER_INPUT_SELECTORS):
                return False
            self.page.wait_for_timeout(200)
        if not inputs:
            return False

        field = inputs[0]
        try:
            input_type = (field.get_attribute("type") or "").lower()
        except Exception:
            input_type = ""
        value = (
            self.account.birth_date.isoformat()
            if input_type == "date"
            else self.account.birth_date.strftime("%d/%m/%Y")
        )
        field.fill(value)
        self._click(self.CONTINUE_SELECTORS)
        self.page.wait_for_timeout(800)
        self._raise_for_blocker()
        return True

    def _visible_question_labels(self) -> list[Any]:
        return self._find_all(self.QUESTION_LABEL_SELECTORS, 0)

    @staticmethod
    def _nearby_text(input_locator: Any) -> list[str]:
        try:
            values = input_locator.evaluate(
                """
                (el) => {
                  const out = [];
                  for (const label of (el.labels || [])) out.push(label.innerText || label.textContent || '');
                  out.push(el.getAttribute('aria-label') || '');
                  out.push(el.getAttribute('placeholder') || '');
                  let node = el.previousElementSibling;
                  for (let i = 0; node && i < 3; i++, node = node.previousElementSibling) {
                    out.push(node.innerText || node.textContent || '');
                  }
                  let parent = el.parentElement;
                  for (let i = 0; parent && i < 3; i++, parent = parent.parentElement) {
                    out.push(parent.innerText || parent.textContent || '');
                  }
                  return out.filter(Boolean);
                }
                """
            )
            return [str(value).strip() for value in values if str(value).strip()]
        except Exception:
            return []

    def _question_text_for_input(
        self,
        input_locator: Any,
        input_index: int,
        labels: Sequence[Any],
        excluded_indexes: set[int],
    ) -> str:
        # Khi có đúng số label và input, thứ tự DOM là cách ghép đáng tin nhất.
        if len(labels) > input_index:
            try:
                text = labels[input_index].inner_text(timeout=500).strip()
                if text:
                    return text
            except Exception:
                pass

        nearby = self._nearby_text(input_locator)
        ranked: list[tuple[float, str]] = []
        for text in nearby:
            try:
                match = match_security_question(
                    text,
                    self.account.questions,
                    excluded_indexes,
                )
                ranked.append((match.score, text))
            except QuestionMatchError:
                continue
        if not ranked:
            raise QuestionMatchError("Không đọc được nội dung câu hỏi bảo mật trên trang Apple")
        return max(ranked, key=lambda item: item[0])[1]

    def answer_two_security_questions(self) -> None:
        used_indexes: set[int] = set()
        answered = 0

        for _ in range(4):
            self._raise_for_blocker()
            answer_inputs = self._find_all(self.ANSWER_INPUT_SELECTORS, 5_000)
            if not answer_inputs:
                if answered >= 2:
                    return
                raise AppleToolError("Apple không hiển thị đủ 2 câu hỏi bảo mật")

            labels = self._visible_question_labels()
            filled_now = 0
            for input_index, field in enumerate(answer_inputs):
                if answered + filled_now >= 2:
                    break
                apple_question = self._question_text_for_input(
                    field,
                    input_index,
                    labels,
                    used_indexes,
                )
                match = match_security_question(
                    apple_question,
                    self.account.questions,
                    used_indexes,
                )
                field.fill(match.qa.answer)
                used_indexes.add(match.index)
                filled_now += 1

            if not filled_now:
                raise AppleToolError("Không điền được câu trả lời bảo mật")

            self._click(self.CONTINUE_SELECTORS)
            answered += filled_now
            self.page.wait_for_timeout(1_000)
            self._raise_for_blocker()
            if answered >= 2:
                return

        raise AppleToolError("Luồng câu hỏi bảo mật không hoàn tất")

    def change_password(self) -> None:
        self.page.goto(MANAGE_URL, wait_until="domcontentloaded")
        self.page.wait_for_timeout(1_000)
        self._raise_for_blocker()

        password_card_selectors = (
            "button:has-text('Mật khẩu')",
            "[role='button']:has-text('Mật khẩu')",
            "a:has-text('Mật khẩu')",
            "button:has-text('Password')",
            "[role='button']:has-text('Password')",
            "a:has-text('Password')",
            "[data-testid*='password' i]",
        )
        self._click(password_card_selectors)

        current = self._find_one(
            (
                "input#current-password",
                "input[name='currentPassword']",
                "input[autocomplete='current-password']",
            )
        )
        new_fields = self._find_all(
            (
                "input#new-password",
                "input[name='newPassword']",
                "input[autocomplete='new-password']",
            ),
            self.timeout_ms,
        )
        confirm_fields = self._find_all(
            (
                "input#confirm-password",
                "input[name='confirmPassword']",
                "input[name*='confirm' i]",
            ),
            1_000,
        )

        if len(new_fields) >= 2 and not confirm_fields:
            new_field, confirm = new_fields[0], new_fields[1]
        elif new_fields and confirm_fields:
            new_field, confirm = new_fields[0], confirm_fields[0]
        else:
            raise AppleToolError("Không tìm thấy đủ ô mật khẩu mới trên Apple")

        current.fill(self.account.password)
        new_field.fill(self.new_password)
        confirm.fill(self.new_password)
        self._click(
            (
                "button:has-text('Lưu thay đổi')",
                "button:has-text('Save Changes')",
                "button:has-text('Thay đổi mật khẩu')",
                "button:has-text('Change Password')",
                "button[type='submit']",
            )
        )
        deadline = time.monotonic() + 8
        form_selectors = (
            "input#new-password",
            "input[name='newPassword']",
            "input[autocomplete='new-password']",
        )
        success_markers = (
            "mat khau da duoc thay doi",
            "doi mat khau thanh cong",
            "password has been changed",
            "password changed",
        )
        while time.monotonic() < deadline:
            alerts = self._find_all(("[role='alert']", ".form-message-wrapper"), 0)
            visible_alerts: list[str] = []
            for alert in alerts:
                try:
                    text = alert.inner_text(timeout=300).strip()
                    if text:
                        visible_alerts.append(text)
                except Exception:
                    pass

            normalized_alerts = _normalize_text(" ".join(visible_alerts))
            if any(marker in normalized_alerts for marker in success_markers):
                return
            if visible_alerts and self._has_visible(form_selectors):
                raise AppleToolError(f"Apple từ chối đổi mật khẩu: {visible_alerts[0]}")
            if not self._has_visible(form_selectors):
                return
            self.page.wait_for_timeout(250)

        raise AppleToolError("Apple chưa xác nhận đổi mật khẩu, tool không báo thành công")


def auto_change_pass(
    account_data: str,
    pass_length: int = 12,
    *,
    headless: bool = False,
    slow_mo: int = 0,
    timeout_ms: int = 30_000,
    progress_callback: ProgressCallback | None = None,
) -> ChangeResult:
    """Đăng nhập, nhận dạng 2/3 câu hỏi và đổi mật khẩu.

    Hàm trả về mật khẩu mới để backend tự lưu. Không tự ghi credential ra file.
    """
    _emit_progress(progress_callback, "Đang kiểm tra dữ liệu")
    account = parse_account_data(account_data)
    new_password = generate_random_password(pass_length)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise AppleToolError(
            "Thiếu Playwright; chạy: pip install playwright && playwright install chromium"
        ) from exc

    with sync_playwright() as playwright:
        _emit_progress(progress_callback, "Đang mở trình duyệt Apple")
        browser = playwright.chromium.launch(headless=headless, slow_mo=slow_mo)
        context = browser.new_context(locale="vi-VN")
        page = context.new_page()
        page.set_default_timeout(timeout_ms)
        automator = AppleAccountAutomator(page, account, new_password, timeout_ms)
        try:
            _emit_progress(progress_callback, "Đang đăng nhập Apple Account")
            automator.sign_in()
            _emit_progress(progress_callback, "Đang kiểm tra ngày sinh")
            automator.fill_birth_date_if_requested()
            _emit_progress(progress_callback, "Đang nhận dạng 2 câu hỏi bảo mật")
            automator.answer_two_security_questions()
            _emit_progress(progress_callback, "Đã xác thực, đang đổi mật khẩu")
            automator.change_password()
            _emit_progress(progress_callback, "Đổi mật khẩu thành công")
            return ChangeResult(account.email, new_password)
        finally:
            context.close()
            browser.close()


def _run_self_test() -> None:
    data = parse_account_data(
        "user@icloud.com:OldPass123:15/05/2000:Biệt danh:An:Thú cưng:Miu:Đội thể thao:MU"
    )
    cases = (
        ("Biệt danh lúc nhỏ của bạn là gì?", "An"),
        ("Tên của thú cưng đầu tiên của bạn là gì?", "Miu"),
        ("What is the name of your favorite sports team?", "MU"),
    )
    for question, expected_answer in cases:
        match = match_security_question(question, data.questions)
        assert match.qa.answer == expected_answer, (question, match)

    assert len(generate_random_password(7)) == 8
    assert len(generate_random_password(14)) == 14
    print("Self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser(description="Đổi mật khẩu Apple Account no-2FA")
    parser.add_argument(
        "account",
        nargs="?",
        help="Dòng ID:pass:ngày-sinh:câu1:đáp1:câu2:đáp2:câu3:đáp3",
    )
    parser.add_argument("--length", type=int, default=12, help="Độ dài mật khẩu mới")
    parser.add_argument("--headless", action="store_true", help="Chạy ẩn trình duyệt")
    parser.add_argument("--slow-mo", type=int, default=0, help="Độ trễ từng thao tác (ms)")
    parser.add_argument("--self-test", action="store_true", help="Chỉ test parser/matcher")
    args = parser.parse_args()

    if args.self_test:
        _run_self_test()
        return 0

    # Prompt ẩn tránh lộ mật khẩu trong lịch sử terminal/process list.
    account_line = args.account or getpass.getpass("Dán dữ liệu tài khoản: ")
    try:
        result = auto_change_pass(
            account_line,
            args.length,
            headless=args.headless,
            slow_mo=max(0, args.slow_mo),
        )
    except AppleToolError as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        return 1

    print(f"Xong {result.email} | Pass mới: {result.new_password}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
