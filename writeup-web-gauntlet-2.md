# Web Gauntlet 2 — SQLite Login Bypass

Challenge web đăng nhập, backend PHP + SQLite. Query gốc kiểu:

```sql
SELECT username, password FROM users WHERE username='<username>' AND password='<password>'
```

Không dùng prepared statement, input được nối chuỗi thẳng vào query. Có hai filter:

- Không được chứa từ `admin` trong input
- Chặn luôn comment (`--`, `#`, `/* */`)

Nên trick "cắt đuôi query bằng --" không xài được ở đây, phải nghĩ cách khác.

## Thử lần đầu: Null Byte, và tại sao nó fail

Ý tưởng ban đầu là chèn `%00` để mong SQLite/PHP coi như chuỗi kết thúc tại đó, phần sau bị bỏ qua:

```
Username: ad'||'min%00
Password: 123
```

Query build ra:

```sql
WHERE username='ad'||'min%00' AND password='123'
```

Chạy thì báo lỗi:

```
near "' AND password='": syntax error
```

Lý do: gõ `%00` vào ô input trên web thì nó **không** phải byte null thật, chỉ là 3 ký tự thường `%`, `0`, `0` thôi. Null byte injection chỉ ăn khi nó thực sự nằm ở tầng string xử lý kiểu C (một số hàm filesystem, regex engine cũ...), còn ở đây SQLite parser đọc nó như sau:

- `'ad'||'min'` → ghép chuỗi bình thường, ra `admin`
- Tới `%` → SQLite hiểu là toán tử **modulo**, không phải ký hiệu gì đặc biệt
- `00` sau đó → số 0
- Dấu `'` ngay sau lại mở ra một chuỗi mới, nuốt luôn cả đoạn `' AND password=`
- `123` bị đọc là số
- Dấu `'` cuối cùng đóng chuỗi nhưng lệch cặp, dư ra

=> cú pháp gãy ngay chỗ `' AND password='`. Null byte kiểu này không giúp gì cả, chỉ làm rối query thêm thôi.

## Cách làm đúng: không cắt query, mà làm cho nó luôn đúng

Vì không cắt được phần đuôi `AND password=...`, thì thay vì né nó, cứ để nguyên và biến cả hai vế thành true.

**Username**, giữ nguyên trick nối chuỗi để né filter `admin`:

```
ad'||'min
```

**Password**, thay vì cố đoán hay dùng `=`, dùng:

```
' IS NOT '
```

Query cuối cùng:

```sql
WHERE username='ad'||'min' AND password='' IS NOT ''
```

SQLite xử lý vế password như sau:
1. `password=''` — so với password thật của admin, chắc chắn không rỗng → ra `0` (false)
2. `0 IS NOT ''` — số 0 khác chuỗi rỗng → luôn đúng → `1` (true)
3. Vậy `AND` cuối là `TRUE AND TRUE` → pass

Login vào được admin mà không cần biết password thật. `' GLOB '*` cũng chạy tương tự vì `GLOB '*'` match mọi giá trị kể cả số 0/1 mà SQLite ép kiểu ngầm.

## Vì sao nó hoạt động — thứ tự ưu tiên toán tử

Cái mấu chốt là `IS NOT` có precedence thấp hơn `=` trong SQLite, nên:

```
password='' IS NOT ''
```

được đọc là `(password='') IS NOT ('')`, chứ không phải so sánh trực tiếp password với kết quả của `IS NOT`. Nhờ vậy một phép so sánh sai (`password=''`) lại bị lật thành true ở lớp ngoài.

## Fix cho app thật (nếu ai làm lab tương tự)

- Dùng prepared statement (`?` placeholder), đừng nối chuỗi trực tiếp
- Đừng chặn theo blacklist từ khóa (`admin`, `--`) — dễ bypass bằng biến thể cú pháp tương đương như trên
- Hash password, so ở tầng app chứ không so trực tiếp trong SQL
