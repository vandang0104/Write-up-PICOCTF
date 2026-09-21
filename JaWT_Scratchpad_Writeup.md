# JaWT Scratchpad — picoCTF Writeup

- **Category:** Web Exploitation
- **Difficulty:** Medium
- **Tác giả bài toán:** John Hammond (picoCTF 2019)
- **Tags:** `jwt`, `hs256`, `weak-secret`, `hashcat`, `rockyou`

## Mô tả

> Check the admin scratchpad!

**Hints:**
1. What is that cookie?
2. Have you heard of JWT?

## Quá trình giải

### Bước 1 — Khảo sát trang web

Truy cập instance (`http://fickle-tempest.picoctf.net:<port>`), trang hiển thị tiêu đề **JaWT** với dòng giới thiệu:

> *"JaWT is an online scratchpad, where you can 'jot' down whatever you'd like! Consider it a notebook for your thoughts."*

Trang yêu cầu **đăng ký với một tên (username)**. Mình nhập tên **`John`** (gợi ý ám chỉ đến công cụ *John the Ripper* sẽ dùng ở bước sau) và được trang chào:

```
Hello John!
Here is your JaWT scratchpad!
```

### Bước 2 — Phát hiện cookie `jwt`

Mở DevTools → tab **Application → Cookies**, thấy trang set một cookie tên **`jwt`** với giá trị dạng:

```
eyJhbGciOiJIUzI1NiIs...(header).(payload).(signature)
```

Đây chính là định dạng chuẩn của **JSON Web Token**: `header.payload.signature`, khớp với hint số 2.

### Bước 3 — Phân tích JWT

Đưa token vào [jwt.io](https://jwt.io/#debugger) để decode:

- **Header:**
  ```json
  {"alg":"HS256","typ":"JWT"}
  ```
  → Token được ký bằng **HMAC-SHA256**, nghĩa là chữ ký được tạo từ header + payload bằng một **secret key** đối xứng. Nếu biết secret key, ai cũng có thể tự tạo token hợp lệ với payload tuỳ ý.

- **Payload:**
  ```json
  {"user":"John"}
  ```
  → Payload chỉ chứa duy nhất trường `user`. Mục tiêu rõ ràng: đổi giá trị này thành `"admin"` để xem được nội dung scratchpad của admin (đề bài: *"Check the admin scratchpad!"*).

  Nếu chỉ đơn giản sửa `user` → `admin` mà không có secret key đúng, chữ ký (signature) sẽ không khớp và server sẽ từ chối token.

→ **Hướng tấn công:** phải tìm ra secret key dùng để ký token, vì HS256 dùng cùng một key để ký và xác minh.

### Bước 4 — Crack secret key bằng Hashcat + rockyou.txt

Vì đây là secret key tự chọn của lập trình viên (không phải khóa ngẫu nhiên mạnh), có khả năng nó là một mật khẩu yếu/dễ đoán → thử tấn công từ điển (dictionary attack).

Dùng **Hashcat** với mode dành riêng cho JWT (HS256) và wordlist **rockyou.txt**:

```bash
hashcat -a 0 -m 16500 jwt_token.txt rockyou.txt
```

(trong đó `jwt_token.txt` chứa nguyên token lấy từ cookie)

Kết quả: tìm ra secret key là:

```
ilovepico
```

### Bước 5 — Tạo JWT giả mạo với `user: admin`

Quay lại **jwt.io**:
1. Dán lại token gốc vào ô decode.
2. Sửa payload từ `{"user":"John"}` thành:
   ```json
   {"user":"admin"}
   ```
3. Nhập secret key `ilovepico` vào ô **Verify Signature** (bên phần "your-256-bit-secret").
4. jwt.io tự động tính lại chữ ký hợp lệ và sinh ra token mới, dạng:

   ```
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.<signature-mới>
   ```

### Bước 6 — Thay cookie và lấy flag

- Quay lại DevTools → **Application → Cookies**.
- Sửa giá trị cookie `jwt` thành token mới vừa tạo (payload `user: admin`).
- Reload lại trang.

Server verify chữ ký bằng secret `ilovepico` → hợp lệ → nhận diện `user = admin` → trả về scratchpad của admin, bên trong chứa flag:

```
picoCTF{jawt_was_just_what_you_thought_bbb82bd4a57564aefb32d69dafb60583}
```

## Nguyên nhân lỗ hổng (Root cause)

- Server tin tưởng hoàn toàn vào trường `user` trong **payload** của JWT để xác định quyền truy cập (phân quyền dựa trên dữ liệu client có thể chỉnh sửa được).
- Secret key dùng để ký HS256 quá yếu (`ilovepico`), nằm trong các wordlist phổ biến → dễ dàng bị brute-force/dictionary attack bằng Hashcat/John the Ripper.
- Vì HS256 là thuật toán **đối xứng**, biết được secret key đồng nghĩa với việc có thể ký (forge) bất kỳ token nào tuỳ ý.

## Cách khắc phục (Mitigation)

- Dùng secret key đủ dài, ngẫu nhiên, không nằm trong wordlist thông dụng (hoặc chuyển sang thuật toán bất đối xứng như RS256).
- Không nên dựa hoàn toàn vào nội dung JWT phía client để cấp quyền nhạy cảm mà không có thêm kiểm tra phía server (ví dụ: kiểm tra trong database, session server-side).
- Giới hạn số lần thử sai, theo dõi các request bất thường để phát hiện brute-force.

## Flag

```
picoCTF{jawt_was_just_what_you_thought_bbb82bd4a57564aefb32d69dafb60583}
```
