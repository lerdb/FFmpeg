/*
 * QMC (QQ Music Encrypted) algorithm API
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

#ifndef AVUTIL_QMC_H
#define AVUTIL_QMC_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file
 * QMC (QQ Music Encrypted) symmetric encryption/decryption algorithm.
 *
 * This API provides the core cipher used by the QMC URL protocol.
 * The algorithm is symmetric, so the same function can be used for
 * both encryption and decryption.
 */

/**
 * Opaque context for QMC cipher.
 * Holds all state needed for encryption/decryption (key, algorithm type, etc.).
 */
typedef struct QMCState QMCState;

/**
 * Initialize a QMC cipher context from a base64-encoded key string.
 *
 * This function performs the following steps:
 *   1. Base64-decodes the input key.
 *   2. Detects whether the key is a V1 or V2 key (based on prefix).
 *   3. Derives the actual encryption key (via TEA or other method).
 *   4. Selects the appropriate cipher (Static, Map, or RC4 variant) based on key length.
 *   5. Initializes all internal structures for the selected cipher.
 *
 * @param ekey      Base64-encoded key string as provided by the user.
 * @param out_state Pointer to a location where the newly allocated QMCState
 *                  will be stored. Caller is responsible for freeing it with
 *                  qmc_free_state().
 * @return 0 on success, a negative AVERROR code on failure:
 *         - AVERROR(EINVAL) if input key is invalid or too short.
 *         - AVERROR(ENOMEM) if memory allocation fails.
 *         - AVERROR_INVALIDDATA if Base64 decoding or key derivation fails.
 */
int qmc_init_state(const char *ekey, QMCState **out_state);

/**
 * Encrypt or decrypt a block of data in-place.
 *
 * The algorithm is symmetric: encryption and decryption are identical.
 * The function operates on the provided buffer and modifies it directly.
 * The `offset` parameter is crucial because the cipher is stream-oriented
 * and depends on the absolute byte position in the file.
 *
 * @param state  Initialized QMC context (from qmc_init_state()).
 * @param buffer Pointer to the data to be transformed. Must not be NULL.
 * @param offset Absolute byte offset of the first byte in `buffer` within the
 *               file. Must be >= 0.
 * @param length Number of bytes to process. Must be > 0.
 */
void qmc_crypt(QMCState *state, uint8_t *buffer, int64_t offset, int length);

/**
 * Free a QMC cipher context and all associated resources.
 *
 * @param state Context to free. May be NULL (function does nothing).
 */
void qmc_free_state(QMCState *state);

#endif /* AVUTIL_QMC_H */