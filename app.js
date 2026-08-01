"use strict";

const formPanel = document.querySelector("#form-panel");
const form = document.querySelector("#setup-form");
const submitButton = document.querySelector("#submit-button");
const statusPanel = document.querySelector("#status-panel");
const resultPanel = document.querySelector("#result-panel");
const errorPanel = document.querySelector("#error-panel");
const statusTitle = document.querySelector("#status-title");
const statusAccount = document.querySelector("#status-account");
const progressBar = document.querySelector("#progress-bar");
const errorMessage = document.querySelector("#error-message");
const resultPassword = document.querySelector("#result-password");
const lengthInput = document.querySelector("#password-length");
const lengthOutput = document.querySelector("#length-output");
const toast = document.querySelector("#toast");

let appToken = "";
let currentJob = null;
let pollTimer = null;
let toastTimer = null;

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function loadConfig() {
  const response = await fetch("/api/config", { cache: "no-store" });
  if (!response.ok) throw new Error("Không kết nối được với tool local");
  const data = await response.json();
  appToken = data.app_token;
}

function showOnly(panel) {
  [formPanel, statusPanel, resultPanel, errorPanel].forEach((item) => {
    item.classList.toggle("hidden", item !== panel);
  });
  window.scrollTo({ top: Math.max(0, panel.offsetTop - 92), behavior: "smooth" });
}

function normalizeText(value) {
  return value
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/đ/g, "d")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function setFieldError(input, message = "") {
  const field = input.closest(".field");
  if (!field) return;
  field.classList.toggle("invalid", Boolean(message));
  const target = field.querySelector(".field-error");
  if (target) target.textContent = message;
}

function validateForm() {
  let valid = true;
  const requiredInputs = [...form.querySelectorAll("input[required]")];
  requiredInputs.forEach((input) => {
    const message = input.value.trim() ? "" : "Không được để trống";
    setFieldError(input, message);
    if (message) valid = false;
  });

  const email = form.elements.email;
  if (email.value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim())) {
    setFieldError(email, "Apple ID/email chưa đúng định dạng");
    valid = false;
  }

  const date = form.elements.birth_date;
  if (date.value && Number.isNaN(Date.parse(date.value))) {
    setFieldError(date, "Ngày sinh không hợp lệ");
    valid = false;
  }

  const questionInputs = [1, 2, 3].map((index) => form.elements[`question_${index}`]);
  const normalized = questionInputs.map((input) => normalizeText(input.value));
  questionInputs.forEach((input, index) => {
    if (normalized[index] && normalized.filter((value) => value === normalized[index]).length > 1) {
      setFieldError(input, "Câu hỏi này đang bị trùng");
      valid = false;
    }
  });

  if (!valid) {
    form.querySelector(".field.invalid input")?.focus({ preventScroll: true });
    form.querySelector(".field.invalid")?.scrollIntoView({ behavior: "smooth", block: "center" });
  }
  return valid;
}

function buildPayload() {
  return {
    email: form.elements.email.value.trim(),
    password: form.elements.password.value,
    birth_date: form.elements.birth_date.value,
    questions: [1, 2, 3].map((index) => ({
      question: form.elements[`question_${index}`].value.trim(),
      answer: form.elements[`answer_${index}`].value,
    })),
    password_length: Number(lengthInput.value),
    show_browser: document.querySelector("#show-browser").checked,
  };
}

function progressForMessage(message) {
  const normalized = normalizeText(message);
  if (normalized.includes("thanh cong")) return 100;
  if (normalized.includes("doi mat khau")) return 84;
  if (normalized.includes("cau hoi")) return 62;
  if (normalized.includes("ngay sinh")) return 44;
  if (normalized.includes("dang nhap")) return 28;
  if (normalized.includes("trinh duyet")) return 16;
  return 8;
}

async function pollJob(jobId, jobToken) {
  let consecutiveErrors = 0;
  while (currentJob?.id === jobId) {
    try {
      const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, {
        cache: "no-store",
        headers: { "X-Job-Token": jobToken },
      });
      if (!response.ok) throw new Error("Mất kết nối với tác vụ");
      const job = await response.json();
      consecutiveErrors = 0;
      statusTitle.textContent = job.message || "Đang xử lý";
      progressBar.style.width = `${progressForMessage(job.message || "")}%`;

      if (job.status === "succeeded") {
        progressBar.style.width = "100%";
        resultPassword.textContent = job.new_password;
        clearSensitiveInputs();
        await sleep(420);
        showOnly(resultPanel);
        return;
      }
      if (job.status === "failed") {
        errorMessage.textContent = job.error || "Tool không thể hoàn tất tác vụ";
        showOnly(errorPanel);
        return;
      }
    } catch (error) {
      consecutiveErrors += 1;
      if (consecutiveErrors >= 5) {
        errorMessage.textContent = error.message || "Mất kết nối với tool local";
        showOnly(errorPanel);
        return;
      }
    }
    await sleep(900);
  }
}

function clearSensitiveInputs() {
  form.elements.password.value = "";
  [1, 2, 3].forEach((index) => {
    form.elements[`answer_${index}`].value = "";
  });
}

async function deleteCurrentJob() {
  if (!currentJob) return;
  const job = currentJob;
  currentJob = null;
  try {
    await fetch(`/api/jobs/${encodeURIComponent(job.id)}`, {
      method: "DELETE",
      headers: { "X-Job-Token": job.token },
    });
  } catch (_) {
    // Server tự dọn tác vụ cũ sau một giờ.
  }
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 1800);
}

form.addEventListener("input", (event) => {
  if (event.target.matches("input")) setFieldError(event.target, "");
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!validateForm()) return;

  submitButton.disabled = true;
  try {
    if (!appToken) await loadConfig();
    const payload = buildPayload();
    const sendJob = () => fetch("/api/jobs", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-App-Token": appToken,
        },
        body: JSON.stringify(payload),
      });
    let response = await sendJob();
    if (response.status === 403) {
      // Render đổi process/token khi deploy hoặc đánh thức máy miễn phí.
      await loadConfig();
      response = await sendJob();
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Không tạo được tác vụ");

    currentJob = { id: data.job_id, token: data.job_token };
    statusTitle.textContent = "Đang khởi động";
    statusAccount.textContent = payload.email;
    progressBar.style.width = "8%";
    showOnly(statusPanel);
    pollJob(currentJob.id, currentJob.token);
  } catch (error) {
    errorMessage.textContent = error.message || "Không kết nối được với tool local";
    showOnly(errorPanel);
  } finally {
    submitButton.disabled = false;
  }
});

document.querySelectorAll("[data-reveal]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.reveal);
    const revealing = input.type === "password";
    input.type = revealing ? "text" : "password";
    button.textContent = revealing ? "Ẩn" : "Hiện";
    button.setAttribute("aria-label", revealing ? "Ẩn nội dung" : "Hiện nội dung");
  });
});

lengthInput.addEventListener("input", () => {
  lengthOutput.value = lengthInput.value;
  lengthOutput.textContent = lengthInput.value;
});

document.querySelector("#copy-button").addEventListener("click", async () => {
  const value = resultPassword.textContent;
  try {
    await navigator.clipboard.writeText(value);
  } catch (_) {
    const temporary = document.createElement("textarea");
    temporary.value = value;
    temporary.style.position = "fixed";
    temporary.style.opacity = "0";
    document.body.appendChild(temporary);
    temporary.select();
    document.execCommand("copy");
    temporary.remove();
  }
  showToast("Đã sao chép mật khẩu");
});

document.querySelector("#reset-button").addEventListener("click", async () => {
  await deleteCurrentJob();
  resultPassword.textContent = "";
  form.reset();
  lengthOutput.textContent = "12";
  showOnly(formPanel);
});

document.querySelector("#retry-button").addEventListener("click", () => {
  showOnly(formPanel);
});

loadConfig().catch(() => {
  errorMessage.textContent = "Không kết nối được với tool local, hãy tắt rồi mở lại";
  showOnly(errorPanel);
});
