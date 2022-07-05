## 									Google CTF 2022

### Misc

####  Appnote.txt

> Every single archive manager unpacks this to a different file.ZIP压缩包相关题目。

##### 分析

首先给了一个dump.zip，解压之后发现hello.txt。

<img src="https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20220705010030.png" width=500 height=350/>

但压缩包有60K，应该不止一个txt，尝试foremost分离无果。因此使用010 editor查看文件结构。会看到藏了很多以504B开头为标志的压缩包。

<img src="https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20220705011231.png" width=600 height=400/>

并且会看到ZIP的数据区(倒数第五行)显示flag00，翻到结尾是flag18，这里猜测flag有19位。并且发现在每个flagxx后给了单个字符，很显然flag是根据位数一个个拼接得到的，但是我们可以看到很多压缩包都对应flag00，flag00后又有不同的字符，因此猜测：

​	**如果flag{n}{x}对应正确的压缩包，那么x就是FLAG的第n位**

问题就转化为如何判断真的压缩包，通过查阅资料可知，zip格式压缩包主要由三大部分组成：数据区(0x04034b50)、中央目录记录区(0x02014b50)、中央目录记录尾部区(0x06054b50)。可以发现假的压缩包是没有

中央目录记录尾部区的，因此全局搜索504B0506。

![](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20220705014056.png)

有21个结果，第一个是hello.txt，第二个是hi.txt，剩下19个是真的压缩包flag{n}，中央目录记录尾部区主要作用是用来定位中央目录记录区的开始位置的。因此写脚本判断出尾部，再根据尾部区域对应的中央目录记录区的起始偏移找到第flagxx后的字符即可得到FLAG。

> ```fallback
>  中央目录记录尾部区结构:
> 
>  中央目录记录尾部开头标记    4 bytes  (0x06054b50)
>  中央目录记录尾部区所在磁盘编号             2 bytes
>  中央目录开始位置所在的磁盘编号  2 bytes
>  该磁盘上所记录的核心目录数量  2 bytes
>  zip压缩包中的文件总数           2 bytes
>  整个中央目录的大小（以字节为单位）   4 bytes
>  中央目录开始位置相对位移        4 bytes
>  注释内容的长度        2 bytes
>  注释内容       (variable size)
> ```

找到开头标记后，当前位置+16(因为中央目录开始位置相对位移的相对位置在16~20)，找到中央目录开始位置的offset，再-1即可找到字符(因为中央目录开始位置的偏移的前一个字符就是数据区中的数据)。

##### 解题

`exp`

```python
a = open("dump.zip", "rb").read()
flag = b""
for i in range(len(a)-4):
  if a[i:i+4]==b"PK\x05\x06":
    offset = int.from_bytes(a[i+0x10:i+0x14], "little")       //0x10对应+16
    flag += a[offset-1:offset]
print(flag)
```

CTF{p0s7m0d3rn_z1p}

-----------------------------------

### WEB

#### LOG4J

> 具体原理还是没有完全理解，先记录一下解题过程。

##### 分析

访问靶机，会发现只有一个chatbot，随便输入点击submit后提示需要以/为前缀，题目给了源码，直接看代码分析。

<img src="https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20220705145853.png" width=500 height=200/>

打开源码可以看到使用flask写的路由，这里贴附关键代码。可以看到和chatbot交互实际上是通过运行jar来进行的，省略的部分就是以空格分割出cmd以及text。比如输入：love you。此时cmd为love，text为you，然后返回标准输出。这里的cmd比较可疑，我们接着审计java部分。

```python
@app.route("/", methods=['GET', 'POST'])
def start():
    if request.method == 'POST':
        text = request.form['text'].split(' ')
        cmd = ''
        ......
        result = chat(cmd, text)
        return result
    return render_template('index.html')
def chat(cmd, text):
    # run java jar with a 10 second timeout
    res = subprocess.run(['java', '-jar', '-Dcmd=' + cmd, 'chatbot/target/app-1.0-SNAPSHOT.jar', '--', text], capture_output=True, timeout=10)
    print(res.stderr.decode('utf8'))
    return res.stdout.decode('utf-8')
```

java部分代码审下来大概就是这些功能：

* 输入help或者/help，返回提示：Try some of our free commands below!  wc time repeat.
* 输入/wc,返回0，输入/wc {str}，返回str的长度。
* 输入/time，返回时间。
* 输入/repeat，返回空，输入/repeat {str}，返回str。

这里还是没啥头绪，因为这题是LOG4J，因此翻一下xml配置文件，发现了可疑点。PatternLayout是log4j用于指定输出格式的的一个参数，那么可以看到它是通过EL表达式${}的形式进行了命令执行。

![](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20220705151856.png)

这里的cmd是我们可控的，又由于代码给出了flag变量，并且是从环境变量中提取的。

```java
String flag = System.getenv("FLAG");
```

尝试一下${flag},没用。但是通过测试，输入${java:flag}发现了有趣的事，抛出了异常信息。

<img src="https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20220705152609.png" width=850 height=320/>

经过搜索发现EL表达式可以获取环境变量:${env:xxx}，那么尝试用${java:${env:FLAG}}直接从环境变量取出flag。

![](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20220705153104.png)

CTF{d95528534d14dc6eb6aeb81c994ce8bd}

这里我不知道为什么输入${java:xxx}就显示Exception，而${flag}这样的形式就不会输出Exception。希望看到的师傅们能给出解答，跪谢。