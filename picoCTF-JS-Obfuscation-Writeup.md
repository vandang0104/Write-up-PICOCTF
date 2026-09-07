# picoCTF Writeup: JavaScript Obfuscation

**Category:** Web Exploitation | **Difficulty:** Easy

Bài này chỉ có 1 ô nhập password, đúng thì hiện flag. Logic check nằm hết ở client-side nên việc của mình là đọc source, deobfuscate rồi lấy flag ra.

---

## 1. Source ban đầu

F12 mở lên là thấy ngay một cục obfuscator.io kinh điển:

```javascript
var _0x5a46=['daf93}','_again_4','this','Password\x20Verified','Incorrect\x20password','getElementById','value','substring','picoCTF{','not_this'];(function(_0x4bd822,_0x2bd6f7){var _0xb4bdb3=function(_0x1d68f6){while(--_0x1d68f6){_0x4bd822['push'](_0x4bd822['shift']());}};_0xb4bdb3(++_0x2bd6f7);}(_0x5a46,0x1b3));var _0x4b5b=function(_0x2d8f05,_0x4b81bb){_0x2d8f05=_0x2d8f05-0x0;var _0x4d74cb=_0x5a46[_0x2d8f05];return _0x4d74cb;};function verify(){checkpass=document[_0x4b5b('0x0')]('pass')[_0x4b5b('0x1')];split=0x4;if(checkpass[_0x4b5b('0x2')](0x0,split*0x2)==_0x4b5b('0x3')){if(checkpass[_0x4b5b('0x2')](0x7,0x9)=='{n'){if(checkpass[_0x4b5b('0x2')](split*0x2,split*0x2*0x2)==_0x4b5b('0x4')){if(checkpass[_0x4b5b('0x2')](0x3,0x6)=='oCT'){if(checkpass[_0x4b5b('0x2')](split*0x3*0x2,split*0x4*0x2)==_0x4b5b('0x5')){if(checkpass['substring'](0x6,0xb)=='F{not'){if(checkpass[_0x4b5b('0x2')](split*0x2*0x2,split*0x3*0x2)==_0x4b5b('0x6')){if(checkpass[_0x4b5b('0x2')](0xc,0x10)==_0x4b5b('0x7')){alert(_0x4b5b('0x8'));}}}}}}}}else{alert(_0x4b5b('0x9'));}}
```

## 2. Format lại cho dễ đọc

Quăng qua prettier là đọc được liền:

```javascript
var _0x5a46 = [
  'daf93}', '_again_4', 'this', "Password Verified",
  "Incorrect password", 'getElementById', 'value',
  'substring', 'picoCTF{', 'not_this'
];

(function (_0x4bd822, _0x2bd6f7) {
  var _0xb4bdb3 = function (_0x1d68f6) {
    while (--_0x1d68f6) {
      _0x4bd822.push(_0x4bd822.shift());
    }
  };
  _0xb4bdb3(++_0x2bd6f7);
})(_0x5a46, 0x1b3);

var _0x4b5b = function (_0x2d8f05, _0x4b81bb) {
  _0x2d8f05 = _0x2d8f05 - 0x0;
  var _0x4d74cb = _0x5a46[_0x2d8f05];
  return _0x4d74cb;
};

function verify() {
  checkpass = document[_0x4b5b('0x0')]('pass')[_0x4b5b('0x1')];
  split = 0x4;
  if (checkpass[_0x4b5b('0x2')](0x0, split * 0x2) == _0x4b5b('0x3')) {
    if (checkpass[_0x4b5b('0x2')](0x7, 0x9) == '{n') {
      if (checkpass[_0x4b5b('0x2')](split * 0x2, split * 0x2 * 0x2) == _0x4b5b('0x4')) {
        if (checkpass[_0x4b5b('0x2')](0x3, 0x6) == 'oCT') {
          if (checkpass[_0x4b5b('0x2')](split * 0x3 * 0x2, split * 0x4 * 0x2) == _0x4b5b('0x5')) {
            if (checkpass.substring(0x6, 0xb) == 'F{not') {
              if (checkpass[_0x4b5b('0x2')](split * 0x2 * 0x2, split * 0x3 * 0x2) == _0x4b5b('0x6')) {
                if (checkpass[_0x4b5b('0x2')](0xc, 0x10) == _0x4b5b('0x7')) {
                  alert(_0x4b5b('0x8'));
                }
              }
            }
          }
        }
      }
    }
  } else {
    alert(_0x4b5b('0x9'));
  }
}
```

## 3. Giải mã mảng string

Cái IIFE ở đầu chỉ đang `shift()` phần tử đầu rồi `push()` xuống cuối, lặp `0x1b3` = 435 lần. Thay vì tính tay, paste thẳng đoạn khởi tạo mảng + IIFE vào Console rồi `console.log(_0x5a46)` là ra kết quả:

```javascript
[
  'getElementById',    // 0x0
  'value',             // 0x1
  'substring',         // 0x2
  'picoCTF{',          // 0x3
  'not_this',          // 0x4
  'daf93}',            // 0x5
  '_again_4',          // 0x6
  'this',              // 0x7
  'Password Verified', // 0x8
  'Incorrect password' // 0x9
]
```

Map ngược vào `verify()` là ra bản gốc:

```javascript
function verify() {
    var checkpass = document.getElementById('pass').value;
    var split = 4;

    if (checkpass.substring(0, 8) == 'picoCTF{') {
        if (checkpass.substring(7, 9) == '{n') {
            if (checkpass.substring(8, 16) == 'not_this') {
                if (checkpass.substring(3, 6) == 'oCT') {
                    if (checkpass.substring(24, 32) == 'daf93}') {
                        if (checkpass.substring(6, 11) == 'F{not') {
                            if (checkpass.substring(16, 24) == '_again_4') {
                                if (checkpass.substring(12, 16) == 'this') {
                                    alert('Password Verified');
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        alert('Incorrect password');
    }
}
```

Đống if lồng nhau thật ra thừa quá nửa — mấy điều kiện như `substring(7,9)`, `substring(3,6)`, `substring(6,11)` chỉ check trùng lại phần đã nằm trong 4 khối `substring` chính. Chỉ cần quan tâm 4 dòng thật sự quyết định:

| Vị trí | Giá trị |
|---|---|
| `0-8`   | `picoCTF{` |
| `8-16`  | `not_this` |
| `16-24` | `_again_4` |
| `24-32` | `daf93}` |

## Flag

```
picoCTF{not_this_again_4daf93}
```

---

Rút kinh nghiệm: obfuscate kiểu này chỉ làm khó mắt người đọc chứ không chống được reverse, với lại check password ở client thì flag coi như public luôn rồi.
