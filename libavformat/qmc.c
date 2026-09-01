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
#include <math.h>

#include "libavutil/avstring.h"
#include "libavutil/base64.h"
#include "libavutil/error.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "url.h"

/* --------------------------------------------------------------------------
 * QMC 加密/解密协议实现
 *
 * 本文件将 QMC 对称加解密算法封装为 FFmpeg 的 URL 协议。
 * 协议名为 "qmc"，使用 "qmc+" 或 "qmc:" 前缀后接嵌套 URL。
 * 用户通过 -ekey 选项传递 Base64 编码的密钥字符串。
 * 算法对称，读取时解密，写入时加密，使用相同的处理函数。
 *
 * 算法流程：
 *   1. 对用户提供的密钥进行 Base64 解码；
 *   2. 根据是否包含 "QQMusic EncV2,Key:" 前缀选择 V1 或 V2 派生流程；
 *   3. 派生得到实际密钥（通常为 512 字节，用于 RC4 变种，或更短用于 Map 或 Static 模式）；
 *   4. 根据密钥长度选择算法类型：
 *        - >300 字节：RC4 变种
 *        - 1~300 字节：Map 模式
 *        - 0 字节：Static 模式
 *   5. 每次读取/写入时，根据当前文件偏移量对数据块进行解密/加密。
 * -------------------------------------------------------------------------- */

/* 算法类型 */
typedef enum QMCCipherType {
    QMC_CIPHER_STATIC = 0,
    QMC_CIPHER_MAP,
    QMC_CIPHER_RC4,
} QMCCipherType;

/* 加解密状态结构体，保存初始化后的密钥和上下文 */
typedef struct QMCState {
    QMCCipherType type;             /* 算法类型 */

    /* Map 模式数据 */
    uint8_t *map_key;               /* Map 使用的密钥 */
    size_t map_key_size;            /* 密钥长度 */

    /* RC4 模式数据 */
    uint8_t rc4_key[512];           /* RC4 密钥（固定 512 字节，不足补 0） */
    size_t rc4_key_size;            /* 实际密钥长度（用于取模等） */
    uint8_t rc4_box[512];           /* RC4 初始置换盒 */
    uint32_t rc4_hash;              /* 密钥哈希值，用于计算段跳过 */
    size_t rc4_segment_size;        /* 普通段大小（5120） */
    size_t rc4_first_segment_size;  /* 首段大小（128） */
} QMCState;

/* ---------------- TEA 解密 ---------------- */

/**
 * 从字节数组中读取大端 32 位整数
 */
static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/**
 * 将 32 位整数以大端序写入字节数组
 */
static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/**
 * TEA 单块解密（8 字节），原地修改
 * @param block 输入/输出块
 * @param key   16 字节密钥
 */
static void tea_decipher_block(uint8_t block[8], const uint8_t key[16])
{
    uint32_t y = load_be32(block);
    uint32_t z = load_be32(block + 4);
    uint32_t k[4];
    for (int i = 0; i < 4; i++)
        k[i] = load_be32(key + i * 4);
    const uint32_t delta = 0x9E3779B9;
    uint32_t sum = (delta << 4) & 0xFFFFFFFF;
    for (int i = 0; i < 16; i++) {
        z -= (((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3]));
        z &= 0xFFFFFFFF;
        y -= (((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1]));
        y &= 0xFFFFFFFF;
        sum = (sum - delta) & 0xFFFFFFFF;
    }
    store_be32(block, y);
    store_be32(block + 4, z);
}

/**
 * 异或两个等长数据块
 */
static void xor_blocks(uint8_t *dst, const uint8_t *a, const uint8_t *b, int len)
{
    for (int i = 0; i < len; i++)
        dst[i] = a[i] ^ b[i];
}

/**
 * TEA 解密完整数据（CBC-like 模式，并去除填充）
 * @param key        16 字节密钥
 * @param ciphertext 密文数据
 * @param len        密文长度（必须为 8 的倍数）
 * @param out_data   输出解密后去除填充的数据（由调用者 av_free）
 * @param out_len    输出数据长度
 * @return 0 成功，负值失败
 */
static int tea_decrypt(const uint8_t *key, const uint8_t *ciphertext, size_t len,
                       uint8_t **out_data, size_t *out_len)
{
    if (!key || !ciphertext || len < 8 || len % 8 != 0)
        return AVERROR(EINVAL);

    uint8_t *result = av_malloc(len);
    if (!result)
        return AVERROR(ENOMEM);
    size_t result_size = 0;

    uint8_t pre_crypt[8], pre_plain[8], curr_block[8], xored[8], x[8], prev_cipher[8];
    uint8_t pre_crypt_orig[8];   /* 保存第一个密文块，用于后续 CBC 异或 */

    /* 解密首块 */
    memcpy(pre_crypt, ciphertext, 8);
    memcpy(pre_crypt_orig, pre_crypt, 8);   /* 备份原始密文 */
    tea_decipher_block(pre_crypt, key);     /* 原地解密，pre_crypt 变为明文 */
    memcpy(pre_plain, pre_crypt, 8);
    memcpy(prev_cipher, pre_crypt_orig, 8); /* 使用原始密文作为 previousCipher */
    memcpy(result, pre_plain, 8);
    result_size = 8;

    /* 处理后续块（CBC-like 模式） */
    for (size_t i = 8; i < len; i += 8) {
        memcpy(curr_block, ciphertext + i, 8); /* 提取 currentBlock */
        xor_blocks(xored, curr_block, pre_plain, 8);
        tea_decipher_block(xored, key);
        xor_blocks(x, xored, prev_cipher, 8);

        memcpy(result + result_size, x, 8);
        result_size += 8;

        xor_blocks(pre_plain, x, prev_cipher, 8);
        memcpy(prev_cipher, curr_block, 8);
    }

    /* 验证填充：最后 7 个字节必须为 0 */
    if (result_size < 7 ||
        result[result_size - 7] != 0 ||
        result[result_size - 6] != 0 ||
        result[result_size - 5] != 0 ||
        result[result_size - 4] != 0 ||
        result[result_size - 3] != 0 ||
        result[result_size - 2] != 0 ||
        result[result_size - 1] != 0) {
        av_free(result);
        return AVERROR_INVALIDDATA;
    }

    /* 计算填充长度并检查合法性 */
    uint8_t pos = (result[0] & 0x07) + 2;
    if ((size_t)pos + 1 >= (result_size - 7)) {
        av_free(result);
        return AVERROR_INVALIDDATA;
    }

    size_t data_len = result_size - 7 - (pos + 1);
    memmove(result, result + pos + 1, data_len);
    result_size = data_len;
    *out_data = result;
    *out_len = result_size;
    return 0;
}

/* ---------------- 密钥派生 ---------------- */

/**
 * V1 密钥派生
 * @param raw_key_dec Base64 解码后的原始密钥（长度至少 16）
 * @param raw_len      原始密钥长度
 * @param out_key      输出派生密钥
 * @param out_len      输出派生密钥长度
 * @return 0 成功，负值失败
 */
static int derive_key_v1(const uint8_t *raw_key_dec, size_t raw_len,
                         uint8_t **out_key, size_t *out_len)
{
    if (raw_len < 16)
        return AVERROR(EINVAL);

    /* 生成简单密钥表（基于 tan 函数） */
    int simple_key[8];
    for (int i = 0; i < 8; i++) {
        double tan_val = tan(106 + i * 0.1);
        simple_key[i] = (int)(fabs(tan_val) * 100.0);
    }

    /* 构造 TEA 密钥（16 字节）：交替存入 simple_key 和原始密钥前 8 字节 */
    uint8_t tea_key[16];
    for (int i = 0; i < 8; i++) {
        tea_key[i * 2] = (uint8_t)simple_key[i];
        tea_key[i * 2 + 1] = raw_key_dec[i];
    }

    /* 对原始密钥第 8 字节之后的部分进行 TEA 解密 */
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;
    int ret = tea_decrypt(tea_key, raw_key_dec + 8, raw_len - 8,
                          &decrypted, &decrypted_len);
    if (ret < 0)
        return ret;

    /* 组合结果：前 8 字节来自原始密钥，后面是解密后的数据 */
    size_t result_len = 8 + decrypted_len;
    uint8_t *result = av_malloc(result_len);
    if (!result) {
        av_free(decrypted);
        return AVERROR(ENOMEM);
    }
    memcpy(result, raw_key_dec, 8);
    memcpy(result + 8, decrypted, decrypted_len);
    av_free(decrypted);

    *out_key = result;
    *out_len = result_len;
    return 0;
}

/**
 * V2 密钥派生
 * @param raw     去掉前缀后的原始数据（Base64 编码的密文）
 * @param raw_len 数据长度
 * @param out_key 输出派生密钥
 * @param out_len 输出派生密钥长度
 * @return 0 成功，负值失败
 */
static int derive_key_v2(const uint8_t *raw, size_t raw_len,
                         uint8_t **out_key, size_t *out_len)
{
    static const uint8_t key1[16] = {
        0x33, 0x38, 0x36, 0x5A, 0x4A, 0x59, 0x21, 0x40,
        0x23, 0x2A, 0x24, 0x25, 0x5E, 0x26, 0x29, 0x28
    };
    static const uint8_t key2[16] = {
        0x2A, 0x2A, 0x23, 0x21, 0x28, 0x23, 0x24, 0x25,
        0x26, 0x5E, 0x61, 0x31, 0x63, 0x5A, 0x2C, 0x54
    };

    uint8_t *buf1 = NULL, *buf2 = NULL;
    size_t buf1_len = 0, buf2_len = 0;
    int ret = tea_decrypt(key1, raw, raw_len, &buf1, &buf1_len);
    if (ret < 0)
        goto fail;
    ret = tea_decrypt(key2, buf1, buf1_len, &buf2, &buf2_len);
    if (ret < 0)
        goto fail;

    /* 将结果转为字符串进行 Base64 解码 */
    char *str = av_malloc(buf2_len + 1);
    if (!str) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    memcpy(str, buf2, buf2_len);
    str[buf2_len] = '\0';

    int decoded_size = AV_BASE64_DECODE_SIZE(strlen(str));
    uint8_t *decoded = av_malloc(decoded_size);
    if (!decoded) {
        av_free(str);
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    int decoded_len_ret = av_base64_decode(decoded, str, decoded_size);
    av_free(str);
    if (decoded_len_ret < 0) {
        av_free(decoded);
        ret = AVERROR_INVALIDDATA;
        goto fail;
    }
    size_t decoded_len = (size_t)decoded_len_ret;

    *out_key = decoded;
    *out_len = decoded_len;
    ret = 0;

fail:
    av_free(buf1);
    av_free(buf2);
    return ret;
}

/**
 * 密钥派生主入口
 * @param raw_key 用户提供的 Base64 密钥字符串
 * @param out_key 输出派生密钥
 * @param out_len 输出派生密钥长度
 * @return 0 成功，负值失败
 */
static int derive_key(const char *raw_key, uint8_t **out_key, size_t *out_len)
{
    int ret = 0;
    size_t raw_len = 0;

    int raw_dec_size = AV_BASE64_DECODE_SIZE(strlen(raw_key));
    uint8_t *raw_key_dec = av_malloc(raw_dec_size);
    if (!raw_key_dec)
        return AVERROR(ENOMEM);

    int raw_len_ret = av_base64_decode(raw_key_dec, raw_key, raw_dec_size);
    if (raw_len_ret < 0) {
        av_free(raw_key_dec);
        av_log(NULL, AV_LOG_ERROR, "[QMC] Base64 decode failed\n");
        return AVERROR_INVALIDDATA;
    }
    raw_len = (size_t)raw_len_ret;

    const char prefix[] = "QQMusic EncV2,Key:";
    size_t prefix_len = strlen(prefix);

    /* 根据是否存在 V2 前缀选择派生流程 */
    if (raw_len >= prefix_len && memcmp(raw_key_dec, prefix, prefix_len) == 0) {
        uint8_t *trimmed = av_malloc(raw_len - prefix_len);
        if (!trimmed) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        memcpy(trimmed, raw_key_dec + prefix_len, raw_len - prefix_len);
        ret = derive_key_v2(trimmed, raw_len - prefix_len, out_key, out_len);
        av_free(trimmed);
    } else {
        ret = derive_key_v1(raw_key_dec, raw_len, out_key, out_len);
    }

fail:
    av_free(raw_key_dec);
    return ret;
}

/* ---------------- Map Cipher ---------------- */

/**
 * 位旋转辅助函数
 */
static uint8_t rotate_left(uint8_t value, uint8_t bits)
{
    uint8_t rotate = (bits + 4) % 8;
    return (value << rotate) | (value >> rotate);
}

/**
 * 计算 Map 模式指定偏移处的掩码字节
 */
static uint8_t map_get_mask(QMCState *state, size_t offset)
{
    if (offset > 0x7FFF)
        offset %= 0x7FFF;
    size_t idx = (offset * offset + 71214) % state->map_key_size;
    return rotate_left(state->map_key[idx], (uint8_t)(idx & 0x7));
}

/**
 * Map 模式加/解密（对称 XOR）
 */
static void map_crypt(QMCState *state, uint8_t *buf, size_t size, size_t offset)
{
    for (size_t i = 0; i < size; i++)
        buf[i] ^= map_get_mask(state, offset + i);
}

/* ---------------- Static Cipher ---------------- */

/* 静态密盒（256 字节预定义数据） */
static const uint8_t static_box[256] = {
    0x77, 0x48, 0x32, 0x73, 0xDE, 0xF2, 0xC0, 0xC8,
    0x95, 0xEC, 0x30, 0xB2, 0x51, 0xC3, 0xE1, 0xA0,
    0x9E, 0xE6, 0x9D, 0xCF, 0xFA, 0x7F, 0x14, 0xD1,
    0xCE, 0xB8, 0xDC, 0xC3, 0x4A, 0x67, 0x93, 0xD6,
    0x28, 0xC2, 0x91, 0x70, 0xCA, 0x8D, 0xA2, 0xA4,
    0xF0, 0x08, 0x61, 0x90, 0x7E, 0x6F, 0xA2, 0xE0,
    0xEB, 0xAE, 0x3E, 0xB6, 0x67, 0xC7, 0x92, 0xF4,
    0x91, 0xB5, 0xF6, 0x6C, 0x5E, 0x84, 0x40, 0xF7,
    0xF3, 0x1B, 0x02, 0x7F, 0xD5, 0xAB, 0x41, 0x89,
    0x28, 0xF4, 0x25, 0xCC, 0x52, 0x11, 0xAD, 0x43,
    0x68, 0xA6, 0x41, 0x8B, 0x84, 0xB5, 0xFF, 0x2C,
    0x92, 0x4A, 0x26, 0xD8, 0x47, 0x6A, 0x7C, 0x95,
    0x61, 0xCC, 0xE6, 0xCB, 0xBB, 0x3F, 0x47, 0x58,
    0x89, 0x75, 0xC3, 0x75, 0xA1, 0xD9, 0xAF, 0xCC,
    0x08, 0x73, 0x17, 0xDC, 0xAA, 0x9A, 0xA2, 0x16,
    0x41, 0xD8, 0xA2, 0x06, 0xC6, 0x8B, 0xFC, 0x66,
    0x34, 0x9F, 0xCF, 0x18, 0x23, 0xA0, 0x0A, 0x74,
    0xE7, 0x2B, 0x27, 0x70, 0x92, 0xE9, 0xAF, 0x37,
    0xE6, 0x8C, 0xA7, 0xBC, 0x62, 0x65, 0x9C, 0xC2,
    0x08, 0xC9, 0x88, 0xB3, 0xF3, 0x43, 0xAC, 0x74,
    0x2C, 0x0F, 0xD4, 0xAF, 0xA1, 0xC3, 0x01, 0x64,
    0x95, 0x4E, 0x48, 0x9F, 0xF4, 0x35, 0x78, 0x95,
    0x7A, 0x39, 0xD6, 0x6A, 0xA0, 0x6D, 0x40, 0xE8,
    0x4F, 0xA8, 0xEF, 0x11, 0x1D, 0xF3, 0x1B, 0x3F,
    0x3F, 0x07, 0xDD, 0x6F, 0x5B, 0x19, 0x30, 0x19,
    0xFB, 0xEF, 0x0E, 0x37, 0xF0, 0x0E, 0xCD, 0x16,
    0x49, 0xFE, 0x53, 0x47, 0x13, 0x1A, 0xBD, 0xA4,
    0xF1, 0x40, 0x19, 0x60, 0x0E, 0xED, 0x68, 0x09,
    0x06, 0x5F, 0x4D, 0xCF, 0x3D, 0x1A, 0xFE, 0x20,
    0x77, 0xE4, 0xD9, 0xDA, 0xF9, 0xA4, 0x2B, 0x76,
    0x1C, 0x71, 0xDB, 0x00, 0xBC, 0xFD, 0x0C, 0x6C,
    0xA5, 0x47, 0xF7, 0xF6, 0x00, 0x79, 0x4A, 0x11
};

/**
 * 计算静态掩码字节
 */
static uint8_t static_get_mask(size_t offset)
{
    if (offset > 0x7FFF)
        offset %= 0x7FFF;
    size_t idx = (offset * offset + 27) & 0xff;
    return static_box[idx];
}

/**
 * 静态模式加/解密（对称 XOR）
 */
static void static_crypt(uint8_t *buf, size_t size, size_t offset)
{
    for (size_t i = 0; i < size; i++)
        buf[i] ^= static_get_mask(offset + i);
}

/* ---------------- RC4 Cipher (变种) ---------------- */

/**
 * 计算指定段 ID 的跳过量
 */
static size_t rc4_get_segment_skip(QMCState *state, size_t id)
{
    int seed = (int)state->rc4_key[id % state->rc4_key_size];
    if (seed == 0)
        seed = 1;
    size_t idx = (size_t)((double)state->rc4_hash /
                          (double)((unsigned long long)(id + 1) * seed) * 100.0);
    return idx % state->rc4_key_size;
}

/**
 * 处理首段（直接用密钥异或）
 */
static void rc4_crypt_first_segment(QMCState *state, uint8_t *buf, size_t size, size_t offset)
{
    for (size_t i = 0; i < size; i++) {
        size_t skip_idx = rc4_get_segment_skip(state, offset + i);
        if (skip_idx < state->rc4_key_size)
            buf[i] ^= state->rc4_key[skip_idx];
    }
}

/**
 * 处理普通段（变种 RC4 流）
 */
static void rc4_crypt_segment(QMCState *state, uint8_t *buf, size_t size, size_t offset)
{
    uint8_t cbox[512];
    memcpy(cbox, state->rc4_box, sizeof(cbox));
    size_t j = 0, k = 0;
    size_t skip_len = (offset % state->rc4_segment_size) +
                      rc4_get_segment_skip(state, offset / state->rc4_segment_size);

    for (int64_t i = -(int64_t)skip_len; i < (int64_t)size; i++) {
        j = (j + 1) % 512;
        k = (cbox[j] + k) % 512;
        uint8_t tmp = cbox[j];
        cbox[j] = cbox[k];
        cbox[k] = tmp;
        if (i >= 0)
            buf[i] ^= cbox[(cbox[j] + cbox[k]) % 512];
    }
}

/**
 * RC4 加/解密主函数（处理段边界）
 * @param state  加解密状态
 * @param buf    数据缓冲区
 * @param size   数据长度
 * @param offset 全局偏移
 */
static void rc4_crypt(QMCState *state, uint8_t *buf, size_t size, size_t offset)
{
    size_t to_process = size;
    size_t processed = 0;

    while (to_process > 0) {
        if (offset < state->rc4_first_segment_size) {
            size_t block_size = FFMIN(to_process,
                                      state->rc4_first_segment_size - offset);
            rc4_crypt_first_segment(state, buf + processed, block_size, offset);
            offset += block_size;
            processed += block_size;
            to_process -= block_size;
            if (to_process == 0)
                break;
        }

        size_t current_seg_remaining = state->rc4_segment_size -
                                       (offset % state->rc4_segment_size);
        size_t block_size = FFMIN(to_process, current_seg_remaining);
        rc4_crypt_segment(state, buf + processed, block_size, offset);
        offset += block_size;
        processed += block_size;
        to_process -= block_size;
    }
}

/* ---------------- 初始化与加解密入口 ---------------- */

/**
 * 根据用户提供的密钥初始化加解密状态
 * @param ekey      Base64 密钥字符串
 * @param out_state 输出加解密状态指针
 * @return 0 成功，负值失败
 */
static int qmc_init_state(const char *ekey, QMCState **out_state)
{
    int ret;
    uint8_t *derived_key = NULL;
    size_t derived_len = 0;

    /* 密钥派生 */
    ret = derive_key(ekey, &derived_key, &derived_len);
    if (ret < 0) {
        av_log(NULL, AV_LOG_ERROR, "[QMC] Key derivation failed\n");
        return ret;
    }

    QMCState *state = av_mallocz(sizeof(QMCState));
    if (!state) {
        av_free(derived_key);
        return AVERROR(ENOMEM);
    }

    /* 根据密钥长度选择解密器 */
    if (derived_len > 300) {
        state->type = QMC_CIPHER_RC4;
        state->rc4_key_size = derived_len;
        memset(state->rc4_key, 0, sizeof(state->rc4_key));
        memcpy(state->rc4_key, derived_key,
               FFMIN(derived_len, sizeof(state->rc4_key)));
        state->rc4_segment_size = 5120;
        state->rc4_first_segment_size = 128;

        /* 初始化置换盒 */
        for (size_t i = 0; i < 512; i++)
            state->rc4_box[i] = (uint8_t)i;
        int j = 0;
        for (size_t i = 0; i < 512; i++) {
            j = (j + state->rc4_box[i] + state->rc4_key[i % 512]) % 512;
            uint8_t tmp = state->rc4_box[i];
            state->rc4_box[i] = state->rc4_box[j];
            state->rc4_box[j] = tmp;
        }

        /* 计算哈希值 */
        uint32_t hash = 1;
        for (size_t i = 0; i < 512; i++) {
            uint8_t v = state->rc4_key[i];
            if (v == 0)
                continue;
            uint32_t next_hash = hash * v;
            if (next_hash == 0 || next_hash <= hash)
                break;
            hash = next_hash;
        }
        state->rc4_hash = hash;
    } else if (derived_len > 0) {
        state->type = QMC_CIPHER_MAP;
        state->map_key_size = derived_len;
        state->map_key = av_malloc(derived_len);
        if (!state->map_key) {
            av_free(derived_key);
            av_free(state);
            return AVERROR(ENOMEM);
        }
        memcpy(state->map_key, derived_key, derived_len);
    } else {
        state->type = QMC_CIPHER_STATIC;
    }

    av_free(derived_key);
    *out_state = state;
    return 0;
}

/**
 * 加/解密数据块（对称操作）
 * @param state  加解密状态
 * @param buffer 数据缓冲区（原地变换）
 * @param offset 缓冲区首字节在文件中的绝对偏移量
 * @param length 数据长度
 */
static void qmc_crypt(QMCState *state, uint8_t *buffer, int64_t offset, int length)
{
    if (!state || length <= 0 || offset < 0)
        return;

    size_t off = (size_t)offset;
    switch (state->type) {
    case QMC_CIPHER_STATIC:
        static_crypt(buffer, length, off);
        break;
    case QMC_CIPHER_MAP:
        map_crypt(state, buffer, length, off);
        break;
    case QMC_CIPHER_RC4:
        rc4_crypt(state, buffer, length, off);
        break;
    default:
        break;
    }
}

/**
 * 释放加解密状态
 */
static void qmc_free_state(QMCState *state)
{
    if (state) {
        if (state->type == QMC_CIPHER_MAP)
            av_free(state->map_key);
        av_free(state);
    }
}

/* --------------------------------------------------------------------------
 * URLProtocol 实现
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
 * 打开协议
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
 * 写入并加密（使用内部缓冲区避免频繁分配）
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