# Apple No2FA Setup

Giao diện local để đổi mật khẩu Apple Account no2FA bằng ngày sinh và 3 câu hỏi bảo mật. Tool tự nhận dạng 2 câu bất kỳ Apple hiển thị, kể cả khi câu hỏi được nhập ngắn như `Biệt danh`, `Thú cưng`, `Đội thể thao`.

## Chạy trên Windows

1. Cài Python 3.10 trở lên và nhớ bật **Add Python to PATH**.
2. Nhấp đúp `START_WINDOWS.bat`.
3. Lần đầu chờ tool tự cài Playwright và Chromium, sau đó giao diện sẽ tự mở.

Những lần sau chỉ cần mở lại `START_WINDOWS.bat`.

## Chạy trên macOS hoặc Linux

Mở Terminal trong thư mục này rồi chạy:

```bash
chmod +x START_LINUX_MAC.command
./START_LINUX_MAC.command
```

## Cách dùng

1. Nhập Apple ID, mật khẩu hiện tại và ngày sinh.
2. Nhập đủ 3 câu hỏi cùng câu trả lời. Có thể viết câu hỏi ngắn nhưng phải đủ phân biệt.
3. Chọn độ dài mật khẩu mới, nên giữ **Hiện trình duyệt Apple**.
4. Nhấn **Bắt đầu đổi mật khẩu** và chờ kết quả.

Tool chỉ chạy tại `127.0.0.1`, không ghi tài khoản hay mật khẩu xuống file. Nếu Apple yêu cầu 2FA hoặc CAPTCHA, tool dừng để tránh xử lý sai. Chỉ dùng với tài khoản thuộc sở hữu của bạn hoặc tài khoản bạn được phép quản lý.
