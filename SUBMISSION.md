# K4 Day 26 — NTN

Thành viên duy nhất: **Nguyễn Thành Nam — MSSV 2A202602694**.

Thư mục nộp là `K4-DAY26-NTN/`, chứa `TEAMMATES.md` và `NTN.bundle`.
Bundle được tạo bằng `make submit TEAM=NTN`; manifest, file hashes và bản sao
đã được kiểm tra. Sau khi sửa source, cần tạo lại bundle trước khi nộp.

## Kiểm tra

- Full public suite trên Linux/Python 3.12: **4608 passed, 7 skipped**.
- Tests của đội: **178 passed**, bao gồm gateway, guardrails, prosecutor,
  mutations và guarded answer với dữ liệu world thật.
- `make validate`: **0 FAIL, 1 WARN** (lethality proxy).
- Scorer prosecutor: precision **1.000**, recall **0.471**, F1 **0.640**,
  false-claim rate **0.000**; 16 verified trên 40 fixtures.
- Adversary AS=prosecutor, seeds 1–5: **55 verified, 0 false**.
- `kit/`, `bots/`, `fixtures/` không được sửa; bài làm dùng stdlib và kit.

Runtime dùng `.venv` Python 3.12. Corpus phải được tải từ release chính thức
và kiểm tra SHA256 trước khi giải nén; không có truth.json trong world sinh viên.
Không cần API key. Xem README gốc để tải world; tên nhóm là NTN.

Trên Windows, chạy full suite bằng Docker để tránh lỗi có sẵn của test
isolation dùng msvcrt.open. Từ thư mục repo trong PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\tools\ntn\check.ps1 -Build
```

Source được mount read-only, container kiểm thử chạy không có network.
`student_tests/` chỉ phục vụ kiểm thử, không được đóng vào bundle.

## Giới hạn đánh giá

Stock spar tạo ANSWER riêng và không sử dụng guardrail/prompt của đội.
Đường kiểm tra ANSWER thực được triển khai trong `agent/answer.py`; hướng dẫn
tích hợp ở `agent/INTEGRATION.md`. Chỉ trích dẫn dữ liệu thực returned trong
cùng exchange, dùng nguồn được caller xác minh trust/relevance, giữ nguyên
câu nguồn và không loại bỏ phủ định.

Lethality của từng lá trong private arena và các lớp ngữ nghĩa cần trọng tài
không thể được chứng nhận chỉ bằng test/spar local. Bảy public test skip theo
điều kiện suite, gồm sandbox macOS. Nơi nộp và quy định nhóm một người theo
thông báo của giảng viên; GitHub chứa code và artifact để nộp.
