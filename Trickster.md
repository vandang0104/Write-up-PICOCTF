Trang web cho cho up png file.

**Kiểm tra**
Thử up 1 payload.php đổi extension thành payload.png lên -> không cho phép.
Thử up 1 ảnh png thường thì lại nhận.
=>Filter magic types.

Thay đổi magic types của file php, bằng cách thêm vào dòng 89 50 4E 47 0D 0A 1A 0A (magic type của png).
Xong lưu file với .png.php. Upload lên và lấy cờ 
