Đầu tiên khi quan sát trang web thì thấy 

<img width="1028" height="118" alt="image" src="https://github.com/user-attachments/assets/cf1ddec1-3ccb-4e02-a6c5-9ff571722b93" />

Trang này filter các từ khóa os,eval,exec,bind,connect,python,socket,ls,cat,shell,bind và dùng cả regex để lọc các kiểu encode hex,unicode,url và lọc cả '/' '\' cả extension cho file

Vì nó cấm các từ khóa cụ thể như vậy nên thử thay bằng __import__('o'+'s').popen('whoami').read() vẫn trả về app nghĩa là có thể bypass filter đầu

Tạo ra 1 payload để tìm flag, vì hint có bảo flag nằm ở /flag.txt nên payload:
__import__('o'+'s').popen('c'+'at ' + chr(47) +'flag'+'.'+'txt').read() 

**Giải thích payload:**
- Ở đây ta biết bộ lọc đã lọc cat nên ta tách động ra thành 'c' + 'at' để bypass
- Vì / bị lọc riêng nên không thể dùng các tách động như trên, nên ta dùng chr(47) để chuyển từ ascii về kí tự
- Regex lọc extension của file nên ta tách động ra như cách cũ để bypass 'flag'+'.'+'txt'

