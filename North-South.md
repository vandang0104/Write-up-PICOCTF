Đọc description web thì thấy nó cấm ip ở các vị trị địa lí cố định và cho phép ở 1 vài nơi.
Nó sử dụng GEO-IP để tìm vị trí địa lí => Nó tìm ở tầng transport.
Vậy nên không thể thay đổi X-Forwarded-For để lừa nó được.

Đọc file config thì thấy:
<img width="652" height="718" alt="image" src="https://github.com/user-attachments/assets/fe29ba17-d29c-4246-adc1-6b7c74ca5844" /> .
Nó chỉ cho phép các ip ở IS mới được truy cập trang web.

**Hướng giải quyết**
1. Ta có thể fake ip sang Iceland để bypass.


2. Có thể thay đổi source IP trực tiếp trong gói tin bằng Tor
- Tải tor bằng lệnh sudo apt install tor

- Thêm vào file config exit node IS:
ExitNodes {is}
StrictNodes 1

- Khởi động lại tor: sudo systemctl restart tor
- Request lại trang web với lệnh curl --socks5 127.0.0.1:9050 url
Ý nghĩa của lệnh này là bắt buộc gói tin đi qua tor trước khi tới url 


