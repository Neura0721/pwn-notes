[README.md](https://github.com/user-attachments/files/32228747/README.md)
# pwn-notes# pwn-notes

PWN 学习笔记与 CTF 赛题复盘 —— 从 ROP 入门到常见漏洞利用

记录我在二进制安全方向的学习路径：每个知识点先理解原理，再通过真实赛题验证，最后复盘卡点与思路。

---

## 内容目录

### 一、ROP（返回导向编程）

| 笔记 | 内容 |
|---|---|
| 64 位 ROP 解 `level2_x64` | 64 位调用约定、寄存器传参、gadget 链构造 |
| 32 位 ROP 解 `get_start_3dsctf_x32` | 32 位栈布局、函数调用链 |
| **ret2libc** | libc 基址泄露、`system("/bin/sh")` 调用链构造 |
| **ret2shellcode** | 可执行栈利用、shellcode 写入与跳转 |
| **ret2syscall** | 系统调用号与寄存器约束、`execve` 调用链 |
| **栈迁移** | 栈空间不足时的 `leave; ret` 迁移原理与利用 |

**ROP 实战赛题复盘：**

- `rip` —— 入门题，理解返回地址覆盖
- `warmup_csaw_2016` —— 栈溢出 + 后门函数跳转
- `ciscn_2019_n_1` —— 浮点数比较绕过

### 二、Canary 保护绕过

- Canary 机制原理与泄露手法
- 绕过思路与实战

### 三、格式化字符串漏洞

- 格式化字符串原理（`%p` / `%n` 任意地址读写）
- 偏移计算与利用链构造

**实战赛题复盘：**

- `jarvisoj_level2`
- `ciscn_2019_n_8`
- `bjdctf_2020_babystack`
- `ciscn_2019_c_1`

### 四、赛事复盘

- **XYCTF** —— 记录解题思路与未攻克题目的卡点分析

### 五、工具链备忘

| 工具 | 用途 |
|---|---|
| **ROPgadget** | 搜索 gadget、构造 ROP 链 |
| **GDB / pwndbg** | 动态调试、栈布局查看、断点跟踪 |
| **objdump** | 反汇编、段信息查看 |
| **Radare2** | 逆向分析框架 |
| **OllyDbg** | Windows 平台动态调试 |

### 六、Linux 常用指令备忘

- 基础命令与易混淆命令对比
- 调试与信息收集常用组合

---

## 学习路径建议

如果你是刚入门 PWN 的同学，建议按这个顺序看：

```
栈溢出基础 → ROP（32 位 → 64 位）→ ret2libc → ret2shellcode / ret2syscall
    → 栈迁移 → Canary 绕过 → 格式化字符串
```

---

## 说明

- 笔记为个人学习整理，部分题目来自 BUUCTF、攻防世界、CTFHub 等公开平台
- 赛题名称保留原始平台命名，方便对照查找
