/*
 * QMC (QQ Music Encrypted) protocol
 * Copyright (c) 2026 lerd
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <inttypes.h>
#include <string.h>

#include "libavutil/avstring.h"
#include "libavutil/error.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/qmc.h"
#include "url.h"

/* --------------------------------------------------------------------------
 * QMC URL 协议实现
 *
 * 使用 "qmc+" 或 "qmc:" 前缀后接嵌套 URL，
 * 通过 -ekey 选项传递 Base64 编码的密钥。
 * 算法对称，读取时解密，写入时加密。
 * -------------------------------------------------------------------------- */

typedef struct QMCContext {
    const AVClass *class;
    URLContext *inner;          /* 底层协议上下文 */
    char *ekey;                 /* 用户提供的 Base64 密钥 */
    int64_t position;           /* 当前文件偏移（用于加解密） */
    QMCState *state;            /* 加解密状态 */
    uint8_t *write_buf;         /* 写操作临时缓冲区 */
    int write_buf_size;         /* 缓冲区大小 */
} QMCContext;

/* 命令行选项定义 */
#define OFFSET(x) offsetof(QMCContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
static const AVOption options[] = {
    { "ekey", "set QMC encryption/decryption key (base64 encoded)", OFFSET(ekey), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { NULL }
};

static const AVClass qmc_class = {
    .class_name = "qmc",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

/**
 * 打开 QMC 协议
 *
 * 解析 URL 前缀，检查密钥，初始化算法状态，并打开嵌套协议。
 *
 * @param h        URLContext 句柄
 * @param uri      完整的 QMC URL（例如 "qmc:file://..."）
 * @param flags    打开标志（读/写等）
 * @param options  额外选项字典（可包含嵌套协议的选项）
 * @return 0 成功，负值失败
 */
static int qmc_open(URLContext *h, const char *uri, int flags, AVDictionary **options)
{
    QMCContext *c = h->priv_data;
    const char *nested_url;
    int ret;

    /* 检查 URL 前缀 */
    if (!av_strstart(uri, "qmc+", &nested_url) &&
        !av_strstart(uri, "qmc:", &nested_url)) {
        av_log(h, AV_LOG_ERROR, "Invalid URL: must start with 'qmc+' or 'qmc:'\n");
        return AVERROR(EINVAL);
    }
    if (!*nested_url) {
        av_log(h, AV_LOG_ERROR, "No nested URL specified\n");
        return AVERROR(EINVAL);
    }

    /* 检查密钥是否提供 */
    if (!c->ekey || !c->ekey[0]) {
        av_log(h, AV_LOG_ERROR, "No encryption/decryption key provided (use -ekey)\n");
        return AVERROR(EINVAL);
    }

    /* 初始化加解密状态 */
    c->state = NULL;
    ret = qmc_init_state(c->ekey, &c->state);
    if (ret < 0) {
        av_log(h, AV_LOG_ERROR, "Failed to initialize QMC state\n");
        goto err;
    }

    /* 打开嵌套协议（自动识别 file/http 等） */
    ret = ffurl_open_whitelist(&c->inner, nested_url, flags,
                               &h->interrupt_callback, options,
                               h->protocol_whitelist, h->protocol_blacklist, h);
    if (ret < 0) {
        av_log(h, AV_LOG_ERROR, "Unable to open nested URL '%s'\n", nested_url);
        goto err;
    }

    /* 初始化内部位置 */
    c->position = 0;

    /* 如果底层是流式，则本协议也标记为流式 */
    if (c->inner->is_streamed)
        h->is_streamed = 1;

    return 0;

err:
    qmc_free_state(c->state);
    c->state = NULL;
    return ret;
}

/**
 * 读取数据并解密
 *
 * 从嵌套协议读取原始数据，使用当前 position 作为偏移进行解密，
 * 并更新 position。
 *
 * @param h    URLContext
 * @param buf  目标缓冲区
 * @param size 请求读取的字节数
 * @return 实际读取的字节数（已解密），失败返回负值
 */
static int qmc_read(URLContext *h, uint8_t *buf, int size)
{
    QMCContext *c = h->priv_data;
    int ret;

    /* 直接读取，解密偏移使用当前 position */
    ret = ffurl_read(c->inner, buf, size);
    if (ret <= 0)
        return ret;

    /* 解密 */
    qmc_crypt(c->state, buf, c->position, ret);
    c->position += ret;   /* 更新位置 */

    return ret;
}

/**
 * 写入并加密
 *
 * 将数据复制到内部缓冲区，加密后写入嵌套协议。
 * 注意：不支持部分写入，如果底层只写入部分，将返回错误以保证状态一致。
 *
 * @param h    URLContext
 * @param buf  要写入的数据
 * @param size 数据长度
 * @return 成功时返回 size，失败返回负值
 */
static int qmc_write(URLContext *h, const uint8_t *buf, int size)
{
    QMCContext *c = h->priv_data;
    int ret;

    if (!c->state)
        return AVERROR(EINVAL);

    /* 确保缓冲区足够大 */
    av_fast_malloc(&c->write_buf, &c->write_buf_size, size);
    if (!c->write_buf)
        return AVERROR(ENOMEM);

    /* 复制数据到可写缓冲区 */
    memcpy(c->write_buf, buf, size);

    /* 加密 */
    qmc_crypt(c->state, c->write_buf, c->position, size);

    /* 写入底层协议 */
    ret = ffurl_write(c->inner, c->write_buf, size);
    if (ret < 0)
        return ret;

    /* 处理部分写入：如果底层没有写完全部数据，则返回错误，避免状态不一致 */
    if (ret != size) {
        av_log(h, AV_LOG_ERROR, "Partial write not supported for encrypted stream\n");
        return AVERROR(EIO);
    }

    c->position += ret;
    return ret;
}

/**
 * Seek 操作：直接透传底层协议
 *
 * 对于 AVSEEK_SIZE，直接返回底层文件大小；
 * 对于其他 whence，执行底层 seek 并更新内部 position。
 *
 * @param h      URLContext
 * @param pos    偏移量（含义取决于 whence）
 * @param whence SEEK_SET, SEEK_CUR, SEEK_END 或 AVSEEK_SIZE
 * @return 新位置或文件大小，失败返回负值
 */
static int64_t qmc_seek(URLContext *h, int64_t pos, int whence)
{
    QMCContext *c = h->priv_data;
    int64_t ret;

    /* 查询文件大小：直接透传，不改变当前读写位置 */
    if (whence == AVSEEK_SIZE)
        return ffurl_seek(c->inner, pos, AVSEEK_SIZE);

    /* 其他 seek 方式：透传给底层，成功后更新内部位置为返回的绝对偏移 */
    ret = ffurl_seek(c->inner, pos, whence);
    if (ret < 0)
        return ret;

    c->position = ret;
    return ret;
}

/**
 * 关闭协议，释放资源
 *
 * 关闭嵌套协议，释放算法状态和写缓冲区。
 *
 * @param h URLContext
 * @return 0 成功，负值失败
 */
static int qmc_close(URLContext *h)
{
    QMCContext *c = h->priv_data;
    int ret = ffurl_closep(&c->inner);
    if (ret < 0)
        av_log(h, AV_LOG_WARNING, "Error closing inner URL\n");

    qmc_free_state(c->state);
    c->state = NULL;

    av_freep(&c->write_buf);
    c->write_buf_size = 0;

    return ret;
}

/* 定义 URLProtocol 结构体 */
const URLProtocol ff_qmc_protocol = {
    .name                = "qmc",
    .url_open2           = qmc_open,
    .url_read            = qmc_read,
    .url_write           = qmc_write,
    .url_seek            = qmc_seek,
    .url_close           = qmc_close,
    .priv_data_size      = sizeof(QMCContext),
    .priv_data_class     = &qmc_class,
    .flags               = URL_PROTOCOL_FLAG_NESTED_SCHEME,
};