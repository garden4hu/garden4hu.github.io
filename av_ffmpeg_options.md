## FFMpeg 播放时 option 小记 (一)

ffmepg 在命令行还有编程开发里，都需要有 option 的存在。无论是用于命令行参数的设定，还是库编程的时候，都需要处理 options。本文从一个角度给出 option 的一些逻辑细节。

    免责：不全面，不严谨，非教程和百科，仅用于笔记。

在开始之前，先贴几篇 blog 介绍 AVOption 和如何自定义 AVOption。

[cnblog-AVOption](https://www.cnblogs.com/TaigaCon/p/10182169.html)

[ffmpeg结构体解析-AVClass 和 AVOption](https://www.jianshu.com/p/25a087619b7c)

[ffmpeg中AVOption的实现分析](https://www.cnblogs.com/tocy/p/ffmpeg-libavutil-avoption.html)

让我们从 `avformat_open_input` 开始，
`avformat_open_input(AVFormatContext **ps, const char *filename, const AVInputFormat *fmt, AVDictionary **options)` 中，最后一项就是 options，在 ffplay 中，其用法如下：
```c
AVDictionary *format_opts;
/* Other code */
AVFormatContext* ic = avformat_alloc_context();
if (!av_dict_get(format_opts, "scan_all_pmts", NULL, AV_DICT_MATCH_CASE)) {
        av_dict_set(&format_opts, "scan_all_pmts", "1", AV_DICT_DONT_OVERWRITE);
        scan_all_pmts_set = 1;
}
err = avformat_open_input(&ic, is->filename, is->iformat, &format_opts);
```

其中选项的设置/获取也分为 `av_opt_set_dict` 和 `av_opt_get`。获取 option 键值很简单，存在就返回存在值，否则为空。
那么 `av_opt_set_dict(void *obj, AVDictionary **options)` 呢？一言蔽之：该函数的作用是：如果 `obj` 中存在 `option` 中定义的选项，那么就从 `options` 中取出来（不是复制），设设置到 obj 中的 option 中，注意，`obj` 应该是包含了 `AVClass` 的某种结构体（常见于各种 Context）；没有匹配的选项，则继续保留在 `options`  中。

首先呢，说一下几种常见结构体的关系：
FFFormatContext 与 AVFormatContext

```text
   --------------->|----------------------| <------ The Address
        |          |                      |
        |          |   AVFormatContext    |
        |          |                      |
 FFFormatContext   |----------------------|
        |          |                      |
        |          |     Other Params     |
        |          |       for internal   |
   --------------->|----------------------|
```
类似的结构关系还有：
| Public      | Internal    |
|:-----------:|:-----------:|
| AVIOContext | FFIOContext |
| AVStream    | FFStream    |
| AVCodec     | FFCodec     |

下面来看 `avformat_open_input` 函数内部，有如下流程：

## avformat_open_input
```c
int avformat_open_input(AVFormatContext **ps, const char *filename, const AVInputFormat *fmt, AVDictionary **options)
{
    AVFormatContext *s = *ps;
    FFFormatContext *si;
    AVDictionary *tmp = NULL;
    
    /* other code */
    // 为什么要复制呢？ 这里需要说明一下：每次执行 init_input 我们传入的是 tmp，因为  av_opt_set_dict 是会修改 options的
    if (options)
        av_dict_copy(&tmp, *options, 0); // 拷贝一份到 tmp
    
    /* other code */

    if ((ret = av_opt_set_dict(s, &tmp)) < 0) // 设置 tmp 到 AVFormatContext，没有命中的选项继续留在 tmp 中
        goto fail;
    if ((ret = init_input(s, filename, &tmp)) < 0)
        goto fail;
      // 可以暂停，转入分析 init_input
    // 总结下 init_input 的结果：初始化 URLContext/URLProtocol, AVInputFormat， AVIOContext/FFIOContext
    // 至此，我们得到了要处理的媒体类型，并为止分配了上下文，包括 IO 上下文
    
    /* Other Code */
    
    // 为 AVInputFormat 中指向的具体媒体类型的 Context 分配空间，比如：对 hls 的连接类型，priv_data 就是 HLSContext
    // 这段函数目的是为 媒体类型实例化，并设置参数
    // 注意：这里设置 AVFormatContext.priv_data 为 *Context ，这里的 *Context 是各种媒体类型的 Context，比如 HLSContext
    if (s->iformat->priv_data_size > 0) {
        if (!(s->priv_data = av_mallocz(s->iformat->priv_data_size))) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        if (s->iformat->priv_class) {
            *(const AVClass **) s->priv_data = s->iformat->priv_class; // 注意：在 Context 中，成员 AVClass 的地址是与 Context 地址一样的
            av_opt_set_defaults(s->priv_data); // 初始化 HLSContext 中的 AVClass 中的 option
            if ((ret = av_opt_set_dict(s->priv_data, &tmp)) < 0) // 将 tmp 中剩余的 option 设置给 Context
                goto fail;
        }
    }
    
    // read_header 是 *Context 提供的，从 buffer 中读取数据，使用 *Context 进行处理
    // OK 这里是一个漫长的处理过程，因不同的媒资资源格式不同而不同。
    // 举个例子：对于 HLS 类型的格式，其就会循环嵌套处理，因为又 master Manifest，sub Manifest 和 Streams 的关系，
    // 每个资源对象都会构造一个 AVFormatContext 进行处理。
    if (s->iformat->read_header)
        if ((ret = s->iformat->read_header(s)) < 0) {
            if (s->iformat->flags_internal & FF_FMT_INIT_CLEANUP)
                goto close;
            goto fail;
        }
    
    // 对于一些流，其有封面（一般只有一个，且在文件开头），ffmpeg 会将这个封面作为一个 stream，并设置 AV_DISPOSITION_ATTACHED_PIC 标志
    if ((ret = avformat_queue_attached_pictures(s)) < 0)
        goto close;
        
    update_stream_avctx(s);

    // 保留剩余的 option
    if (options) {
        av_dict_free(options);
        *options = tmp;
    }
}
```

### avformat_open_input    init_input
中断 avformat_open_input 的分析，进入 `init_input` 函数：

```c
static int init_input(AVFormatContext *s, const char *filename, AVDictionary **options)
{
    // s->pb:  AVIOContext *pb; 
    if (s->pb) { // 如果 invoker 自定义了 AVIOContext，此时应该已经有 buffer 在 ffmpeg 中，直接探测格式，并返回
        s->flags |= AVFMT_FLAG_CUSTOM_IO;
        if (!s->iformat)
            return av_probe_input_buffer2(s->pb, &s->iformat, filename,
                                          s, 0, s->format_probesize);
        else if (s->iformat->flags & AVFMT_NOFILE)
            av_log(s, AV_LOG_WARNING, "Custom AVIOContext makes no sense and "
                                      "will be ignored with AVFMT_NOFILE format.\n");
        return 0;
    }
    
    // 如果没有设置 AVInputFormat 的内容（s->iformat），需要av_probe_input_format2 确定格式，主要是通过你的 url 字符串确定
    if ((s->iformat && s->iformat->flags & AVFMT_NOFILE) ||
        (!s->iformat && (s->iformat = av_probe_input_format2(&pd, 0, &score))))
        return score;
    // 如果没有设置 AVInputFormat，那么就需要调用 io_open 进行继续处理
    // 转入 io_open 函数 进行继续处理
    if ((ret = s->io_open(s, &s->pb, filename, AVIO_FLAG_READ | s->avio_flags, options)) < 0)
        return ret;
    
    if (s->iformat)
        return 0;
    // 实现原理：每种格式都有特定的表示，比如 mp4 文件第 4-7位是 "ftyp",HLS 第一行是 "#EXTM3U", 遍历格式，得到最高得分的格式胜出，结束比较
    // 从而获得 s->iformat
    return av_probe_input_buffer2(s->pb, &s->iformat, filename,
                                  s, 0, s->format_probesize);
}
```

`io_open` 是一个回调函数，其目的是为了让不同的 IO 形式实现自己的 io 内容，类似于面向对象的接口。

在 `avformat_alloc_context` 中，给出了 `AVFormatContext` 中默认的 io 函数：

```c
AVFormatContext *avformat_alloc_context(void)
{
    FFFormatContext *const si = av_mallocz(sizeof(*si));
    AVFormatContext *s;
    s = &si->pub;
    s->av_class = &av_format_context_class;
    s->io_open  = io_open_default;
    s->io_close = ff_format_io_close_default;
    s->io_close2= io_close2_default;
    av_opt_set_defaults(s);
    si->pkt = av_packet_alloc();
    si->parse_pkt = av_packet_alloc();

}
```
对于`AVFormatContext`而言，默认的 `io_open` 是 `io_open_default`：
关于此函数，有更详细的解释：[ffmpeg源码分析4-io_open_default()](https://www.jianshu.com/p/9a46fdedee12)

```c

static int io_open_default(AVFormatContext *s, AVIOContext **pb,
                           const char *url, int flags, AVDictionary **options)
{
    /* 一些校验代码 */
    // 转入分析 ffio_open_whitelist
    return ffio_open_whitelist(pb, url, flags, &s->interrupt_callback, options, s->protocol_whitelist, s->protocol_blacklist);
}
```

#### avformat_open_input     init_input     ffio_open_whitelist
OK，接下来分析 `ffio_open_whitelist`，这个函数的主要作用的为 初始化 `URLContext`，以及根据`URLContext `初始化`AVIOContext`。

```c
int ffio_open_whitelist(AVIOContext **s, const char *filename, int flags,
                         const AVIOInterruptCB *int_cb, AVDictionary **options,
                         const char *whitelist, const char *blacklist
                        )
{
    URLContext *h;
    int err;
    *s = NULL;
    
    // ffurl_open_whitelist 函数主要用于初始化 URLContext *h
    err = ffurl_open_whitelist(&h, filename, flags, int_cb, options, whitelist, blacklist, NULL);
    
    if (err < 0)
        return err;
        
    err = ffio_fdopen(s, h);
    
    if (err < 0) {
        ffurl_close(h);
        return err;
    }
    return 0;
}
```

#### avformat_open_input     init_input     ffio_open_whitelist  ffurl_open_whitelist
下面分析下 `ffurl_open_whitelist`:

```c
int ffurl_open_whitelist(URLContext **puc, const char *filename, int flags,
                         const AVIOInterruptCB *int_cb, AVDictionary **options,
                         const char *whitelist, const char* blacklist,
                         URLContext *parent)
{
    AVDictionary *tmp_opts = NULL;
    AVDictionaryEntry *e;
    // 构造 URLContext *puc
    int ret = ffurl_alloc(puc, filename, flags, int_cb);
    // 这里说一下 ffurl_alloc, ffurl_alloc 用于为 URLContext *puc构造内容，步骤如下：
    // Step 01: URLProtocol* p = url_find_protocol(filename); 获取 url 协议结构体，比如：https 协议获取的是 URLProtocol ff_https_protocol 协议。
    // Step 02: url_alloc_for_protocol(URLContext **puc, const URLProtocol *up, const char *filename, int flags, const AVIOInterruptCB *int_cb)
    //           进行 URLContext *pub 的构造，其中，根据 URLProtocol.priv_data_size 的大小分配 URLContext.priv_data 需要的存储空间
    //           URLProtocol.priv_data_size 和 URLContext.priv_data 是什么呢？ 以 HTTPCONTEXT 举例：
    //            const URLProtocol ff_http_protocol = {
    //              .name                = "http",
    //              .priv_data_size      = sizeof(HTTPContext),
    //              .priv_data_class     = &http_context_class,
    //              .flags               = URL_PROTOCOL_FLAG_NETWORK,
    //              .default_whitelist   = "http,https,tls,rtp,tcp,udp,crypto,httpproxy,data"
    //            };
    //            可以看到，priv_data_size 就是 HTTPContext 的大小，而 URLContext.priv_data 就是根据这个大小分配的 HTTPContext 的实例。
    //            以上可以得出，Step 02 中做的事情主要有 2 点，一：根据 filename 找到 URLProtocol 类型
     //                二： 根据 URLProtocol 类型，创建 URLContext ，并构造 URLContext 中的 priv_data
    //            其中 priv_data 是 URLContext 的核心，因为 URLContext 的行为取决于 priv_data 的类型，之所以称为 priv_data 是因为，其是唯一的。
    if (ret < 0)
        return ret;
    if (parent) {
        ret = av_opt_copy(*puc, parent);
        if (ret < 0)
            goto fail;
    }
    if (options &&
        (ret = av_opt_set_dict(*puc, options)) < 0) // OK: 注意，这里讲 option 设置入 URLContext
        goto fail;
    if (options && (*puc)->prot->priv_data_class && // 如果还剩下没有设置的选项，那么，继续设置入 priv_data，比如： HTTPContext 的 option
        (ret = av_opt_set_dict((*puc)->priv_data, options)) < 0)
        goto fail;

    if (!options)
        options = &tmp_opts;

    // 设置协议的黑/白名单，当然，如果你没有设置，这里是空的
    av_assert0(!whitelist ||
               !(e=av_dict_get(*options, "protocol_whitelist", NULL, 0)) ||
               !strcmp(whitelist, e->value));
    av_assert0(!blacklist ||
               !(e=av_dict_get(*options, "protocol_blacklist", NULL, 0)) ||
               !strcmp(blacklist, e->value));
    if ((ret = av_dict_set(options, "protocol_whitelist", whitelist, 0)) < 0)
        goto fail;
    if ((ret = av_dict_set(options, "protocol_blacklist", blacklist, 0)) < 0)
        goto fail;
    if ((ret = av_opt_set_dict(*puc, options)) < 0)
        goto fail;

    // 下面分析 ffurl_connect
    ret = ffurl_connect(*puc, options);

    if (!ret)
        return 0;
fail:
    ffurl_closep(puc);
    return ret;
}
```
`ffurl_open_whitelist` 中，最后一个步骤就是 `ffurl_connect` ，顾名思义，这个就是 connect 连接的动作，比如： http 协议的连接。

```c
int ffurl_connect(URLContext *uc, AVDictionary **options)
{
    int err;
    AVDictionary *tmp_opts = NULL;

    if (!options)
        options = &tmp_opts;

    // Check that URLContext was initialized correctly and lists are matching if set
    /*Other Code: 检查设置 黑白名单 */

    // url_open2 和 url_open 什么区别呢？ url_open2 多了 options，url_open2 用于嵌套类型，比如：https 嵌套了 tls，tls 嵌套了 tcp
    // options 目的是为了透传某些参数到内部嵌套的协议
    // https://github.com/FFmpeg/FFmpeg/blob/636631d9db82f5e86330ab42dacc8a106684b349/libavformat/url.h#L61
    // url_open 和 url_open2 是回调函数，同样是协议接口，留待具体协议进行实现。比如：http(s) 协议的实现： https://github.com/FFmpeg/FFmpeg/blob/e71d5156c8fec67a7198a0032262036ae7d46bcd/libavformat/http.c#L674
    err =
        uc->prot->url_open2 ? 
                              uc->prot->url_open2(uc,uc->filename,uc->flags,options) 
                            : uc->prot->url_open(uc, uc->filename, uc->flags);

    av_dict_set(options, "protocol_whitelist", NULL, 0);
    av_dict_set(options, "protocol_blacklist", NULL, 0);

    if (err)
        return err;
    uc->is_connected = 1;
    /* We must be careful here as ffurl_seek() could be slow,
     * for example for http */
    if ((uc->flags & AVIO_FLAG_WRITE) || !strcmp(uc->prot->name, "file"))
        if (!uc->is_streamed && ffurl_seek(uc, 0, SEEK_SET) < 0)
            uc->is_streamed = 1;
    return 0;
}

```

#### avformat_open_input     init_input     ffio_open_whitelist  ffio_fdopen
好，至此，我们分析了 `ffio_open_whitelist`中的 `ffurl_open_whitelist`， 让我们返回 `ffio_open_whitelist` ，继续分析后续的步骤 `ffio_fdopen`：

```c
int ffio_fdopen(AVIOContext **s, URLContext *h)
{
    /*
        Other Code
        为 buffer 分配空间
        buffer = av_malloc(buffer_size);
    */
    
    // 初始化 AVIOContext *s
    *s = avio_alloc_context(buffer, buffer_size, h->flags & AVIO_FLAG_WRITE, h,
                            (int (*)(void *, uint8_t *, int))  ffurl_read,
                            (int (*)(void *, uint8_t *, int))  ffurl_write,
                            (int64_t (*)(void *, int64_t, int))ffurl_seek);
    
    /* Other Code */
}
```
这里看一下 `avio_alloc_context` :

```c
// https://github.com/FFmpeg/FFmpeg/blob/c8b5f2848dcdc7103a5b85c50c4c3082382d1f82/libavformat/avio_internal.h#L29
// 注意：这里 FFIOContext 的地址和 AVIOContext 的地址是相同的，所以，取决于你将地址视作哪个类型得地址：
// 比如：void* p = long(some_addr);
// FFIOContext* p1 = (FFIOContext*) p;
// AVIOContext* p2 = (AVIOContext*) p;
typedef struct FFIOContext {
    AVIOContext pub;
    /*
        Other param
    */
}
// opaque 指向了 URLContext 对象，
// read_packet/write_packet/seek 都是 URLContext 对象提供得方法
AVIOContext *avio_alloc_context(
                  unsigned char *buffer,
                  int buffer_size,
                  int write_flag,
                  void *opaque,
                  int (*read_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int (*write_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int64_t (*seek)(void *opaque, int64_t offset, int whence))
{
    FFIOContext *s = av_malloc(sizeof(*s));
    if (!s)
        return NULL;
    // 
    ffio_init_context(s, buffer, buffer_size, write_flag, opaque,
                  read_packet, write_packet, seek);
    return &s->pub;
}
```

再看下 `ffurl_read` :
```c
int ffurl_read(URLContext *h, unsigned char *buf, int size)
{
    if (!(h->flags & AVIO_FLAG_READ))
        return AVERROR(EIO);
    return retry_transfer_wrapper(h, buf, size, 1, h->prot->url_read);
}

// retry_transfer_wrapper 是一个保障机制，目的是为了在操作部分完成的情况下，进行重试，以完成期望的操作。
// 比如：期望读取20，结果一次读取12，那么就需要一个保障机制来保证读取的值是期望值
static inline int retry_transfer_wrapper(URLContext *h, uint8_t *buf, int size, int size_min,
                                         int (*transfer_func)(URLContext *h, uint8_t *buf, int size))
{
    int ret, len;
    int fast_retries = 5;
    int64_t wait_since = 0;

    len = 0;
    while (len < size_min) {
        if (ff_check_interrupt(&h->interrupt_callback))
            return AVERROR_EXIT;
        ret = transfer_func(h, buf + len, size - len);
        if (ret == AVERROR(EINTR))
            continue;
        if (h->flags & AVIO_FLAG_NONBLOCK)
            return ret;
        if (ret == AVERROR(EAGAIN)) {
            ret = 0;
            if (fast_retries) {
                fast_retries--;
            } else {
                if (h->rw_timeout) {
                    if (!wait_since)
                        wait_since = av_gettime_relative();
                    else if (av_gettime_relative() > wait_since + h->rw_timeout)
                        return AVERROR(EIO);
                }
                av_usleep(1000);
            }
        } else if (ret == AVERROR_EOF)
            return (len > 0) ? len : AVERROR_EOF;
        else if (ret < 0)
            return ret;
        if (ret) {
            fast_retries = FFMAX(fast_retries, 2);
            wait_since = 0;
        }
        len += ret;
    }
    return len;
}
```

## 总结

至此，总结下 options 在整个链路的设置过程，按照调用顺序：

+ 设置 AVFormatContext 中的 option
+ 设置 URLContext 中的 option
+ 设置 URLContext.priva_data 中的 option，比如 http(s) 协议中的 HTTPContext 的 option
+ 在调用 url_open2 时，对 具有嵌套 URLContext 的 option 进行设置，比如 HTTPContext 嵌套了 TLSContext，TLSContext 嵌套了 TCPContext
+ 设置 AVInputFormat.priv_data 中的 option

最后还是会剩下一下没有被设置的 option，因为没有匹配项。

**最后一句需要强调的是，设置的这些 options, 都必须在 Context 中存在对应项，否则就会被忽略。**
