/*
 * Copyright (C) 2015-2017  Andrew Gunnerson <andrewgunnerson@gmail.com>
 *
 * This file is part of MultiBootPatcher
 *
 * MultiBootPatcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MultiBootPatcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MultiBootPatcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mbbootimg/format/android_p.h"

#include <algorithm>
#include <type_traits>

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>

#include <openssl/sha.h>

#include "mbcommon/endian.h"
#include "mbcommon/file.h"
#include "mbcommon/string.h"

#include "mbbootimg/entry.h"
#include "mbbootimg/file_p.h"
#include "mbbootimg/header.h"
#include "mbbootimg/header_p.h"
#include "mbbootimg/writer.h"
#include "mbbootimg/writer_p.h"

enum class State
{
    START,
    KERNEL,
    RAMDISK,
    SECONDBOOT,
    DT,
    END,
};

struct AndroidWriterCtx
{
    // Header values
    AndroidHeader hdr;

    // Header
    MbBiHeader *header;
    MbBiEntry *entry;

    // Position
    uint64_t pos;
    uint32_t entry_size;

    bool have_kernel_size;
    bool have_ramdisk_size;
    bool have_second_size;
    bool have_dt_size;

    State state;

    SHA_CTX sha_ctx;
};

static void advance_state(AndroidWriterCtx *const ctx)
{
    switch (ctx->state) {
    case State::START:
        ctx->state = State::KERNEL;
        break;
    case State::KERNEL:
        ctx->state = State::RAMDISK;
        break;
    case State::RAMDISK:
        ctx->state = State::SECONDBOOT;
        break;
    case State::SECONDBOOT:
        ctx->state = State::DT;
        break;
    case State::DT:
        ctx->state = State::END;
        break;
    case State::END:
        break;
    }
}

template<typename T>
static inline T align_page_size(const T item_size, const T page_size)
{
    static_assert(!std::is_signed<T>::value, "Type is not unsigned");

    T mask = page_size - 1;

    if (!(item_size & mask)) {
        return 0;
    }

    return page_size - (item_size & mask);
}

static void fix_header_byte_order(AndroidHeader *header)
{
    header->kernel_size = mb_le32toh(header->kernel_size);
    header->kernel_addr = mb_le32toh(header->kernel_addr);
    header->ramdisk_size = mb_le32toh(header->ramdisk_size);
    header->ramdisk_addr = mb_le32toh(header->ramdisk_addr);
    header->second_size = mb_le32toh(header->second_size);
    header->second_addr = mb_le32toh(header->second_addr);
    header->tags_addr = mb_le32toh(header->tags_addr);
    header->page_size = mb_le32toh(header->page_size);
    header->dt_size = mb_le32toh(header->dt_size);
    header->unused = mb_le32toh(header->unused);

    //for (size_t i = 0; i < sizeof(header->id) / sizeof(header->id[0]); ++i) {
    //    header->id[i] = mb_le32toh(header->id[i]);
    //}
}

static void update_size_if_unset(AndroidWriterCtx *ctx, uint32_t size)
{
    uint32_t *size_ptr = nullptr;
    bool *is_set_ptr = nullptr;

    switch (ctx->state) {
    case State::KERNEL:
        is_set_ptr = &ctx->have_kernel_size;
        size_ptr = &ctx->hdr.kernel_size;
        break;
    case State::RAMDISK:
        is_set_ptr = &ctx->have_ramdisk_size;
        size_ptr = &ctx->hdr.ramdisk_size;
        break;
    case State::SECONDBOOT:
        is_set_ptr = &ctx->have_second_size;
        size_ptr = &ctx->hdr.second_size;
        break;
    case State::DT:
        is_set_ptr = &ctx->have_dt_size;
        size_ptr = &ctx->hdr.dt_size;
        break;
    default:
        break;
    }

    if (is_set_ptr && !*is_set_ptr) {
        *size_ptr = size;
        *is_set_ptr = true;
    }
}

static int android_writer_get_header(MbBiWriter *biw, void *userdata,
                                     MbBiHeader **header)
{
    (void) biw;
    AndroidWriterCtx *const ctx = static_cast<AndroidWriterCtx *>(userdata);

    mb_bi_header_clear(ctx->header);

    // TODO: Don't use private header
    ctx->header->fields_supported =
            MB_BI_HEADER_FIELD_KERNEL_SIZE
            | MB_BI_HEADER_FIELD_KERNEL_ADDRESS
            | MB_BI_HEADER_FIELD_RAMDISK_SIZE
            | MB_BI_HEADER_FIELD_RAMDISK_ADDRESS
            | MB_BI_HEADER_FIELD_SECONDBOOT_SIZE
            | MB_BI_HEADER_FIELD_SECONDBOOT_ADDRESS
            | MB_BI_HEADER_FIELD_KERNEL_TAGS_ADDRESS
            | MB_BI_HEADER_FIELD_PAGE_SIZE
            | MB_BI_HEADER_FIELD_DEVICE_TREE_SIZE
            | MB_BI_HEADER_FIELD_UNUSED
            | MB_BI_HEADER_FIELD_BOARD_NAME
            | MB_BI_HEADER_FIELD_KERNEL_CMDLINE
            | MB_BI_HEADER_FIELD_ID;

    *header = ctx->header;
    return MB_BI_OK;
}

static int android_writer_write_header(MbBiWriter *biw, void *userdata,
                                       MbBiHeader *header)
{
    AndroidWriterCtx *const ctx = static_cast<AndroidWriterCtx *>(userdata);

    // Construct header
    memset(&ctx->hdr, 0, sizeof(ctx->hdr));
    memcpy(ctx->hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

    if (mb_bi_header_kernel_address_is_set(header)) {
        ctx->hdr.kernel_addr = mb_bi_header_kernel_address(header);
    }
    if (mb_bi_header_ramdisk_address_is_set(header)) {
        ctx->hdr.ramdisk_addr = mb_bi_header_ramdisk_address(header);
    }
    if (mb_bi_header_secondboot_address_is_set(header)) {
        ctx->hdr.second_addr = mb_bi_header_secondboot_address(header);
    }
    if (mb_bi_header_kernel_tags_address_is_set(header)) {
        ctx->hdr.tags_addr = mb_bi_header_kernel_tags_address(header);
    }
    if (mb_bi_header_page_size_is_set(header)) {
        uint32_t page_size = mb_bi_header_page_size(header);

        switch (mb_bi_header_page_size(header)) {
        case 2048:
        case 4096:
        case 8192:
        case 16384:
        case 32768:
        case 65536:
        case 131072:
            ctx->hdr.page_size = page_size;
            break;
        default:
            mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                                   "Invalid page size: %" PRIu32, page_size);
            return MB_BI_FAILED;
        }
    } else {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                               "Page size field is required");
        return MB_BI_FAILED;
    }

    const char *board_name = mb_bi_header_board_name(header);
    const char *cmdline = mb_bi_header_kernel_cmdline(header);

    if (board_name) {
        if (strlen(board_name) >= sizeof(ctx->hdr.name)) {
            mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                                   "Board name too long");
            return MB_BI_FAILED;
        }

        strncpy(reinterpret_cast<char *>(ctx->hdr.name), board_name,
                sizeof(ctx->hdr.name) - 1);
        ctx->hdr.name[sizeof(ctx->hdr.name) - 1] = '\0';
    }
    if (cmdline) {
        if (strlen(cmdline) >= sizeof(ctx->hdr.cmdline)) {
            mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                                   "Kernel cmdline too long");
            return MB_BI_FAILED;
        }

        strncpy(reinterpret_cast<char *>(ctx->hdr.cmdline), cmdline,
                sizeof(ctx->hdr.cmdline) - 1);
        ctx->hdr.cmdline[sizeof(ctx->hdr.cmdline) - 1] = '\0';
    }

    // TODO: UNUSED
    // TODO: ID

    // Pretend like we wrote the header. We will actually do it in
    // android_writer_close() when we have an accurate view of everything that
    // was written.
    ctx->pos += sizeof(AndroidHeader);

    return MB_BI_OK;
}

static int android_writer_get_entry(MbBiWriter *biw, void *userdata,
                                    MbBiEntry **entry)
{
    AndroidWriterCtx *const ctx = static_cast<AndroidWriterCtx *>(userdata);
    int ret;
    int entry_type;
    State last_state;

    // Update size with number of bytes written
    update_size_if_unset(ctx, ctx->entry_size);

    // Update SHA1 hash
    switch (ctx->state) {
    case State::KERNEL:
    case State::RAMDISK:
    case State::SECONDBOOT:
    case State::DT: {
        uint32_t le32_size = mb_htole32(ctx->entry_size);

        // Include size for everything except non-empty DT images
        if ((ctx->state != State::DT || ctx->entry_size > 0)
                && !SHA1_Update(&ctx->sha_ctx, &le32_size, sizeof(le32_size))) {
            mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                                   "Failed to update SHA1 hash");
            return MB_BI_FAILED;
        }
        break;
    }
    default:
        break;
    }

    // Finish previous entry by aligning to page
    ctx->pos += align_page_size<uint64_t>(ctx->pos, ctx->hdr.page_size);

    // Reset entry size
    ctx->entry_size = 0;

    // Seek to page boundary
    ret = mb_file_seek(biw->file, ctx->pos, SEEK_SET, nullptr);
    if (ret != MB_FILE_OK) {
        mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                               "Failed to seek to page boundary: %s",
                               mb_file_error_string(biw->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    // Advance to next entry
    last_state = ctx->state;
    advance_state(ctx);

    // Update entry
    switch (ctx->state) {
    case State::KERNEL:
        entry_type = MB_BI_ENTRY_KERNEL;
        break;
    case State::RAMDISK:
        entry_type = MB_BI_ENTRY_RAMDISK;
        break;
    case State::SECONDBOOT:
        entry_type = MB_BI_ENTRY_SECONDBOOT;
        break;
    case State::DT:
        entry_type = MB_BI_ENTRY_DEVICE_TREE;
        break;
    case State::END:
        return MB_BI_EOF;
    default:
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Illegal state: %d",
                               static_cast<int>(ctx->state));
        return MB_BI_FATAL;
    }

    mb_bi_entry_clear(ctx->entry);

    if (mb_bi_entry_set_type(ctx->entry, entry_type) != MB_BI_OK) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Failed to set entry type");
        ctx->state = last_state;
        return MB_BI_FAILED;
    }

    *entry = ctx->entry;
    return MB_BI_OK;
}

static int android_writer_write_entry(MbBiWriter *biw, void *userdata,
                                      MbBiEntry *entry)
{
    AndroidWriterCtx *const ctx = static_cast<AndroidWriterCtx *>(userdata);

    // Use entry size if specified
    if (mb_bi_entry_size_is_set(entry)) {
        uint64_t size = mb_bi_entry_size(entry);

        if (size > UINT32_MAX) {
            mb_bi_writer_set_error(biw, MB_BI_ERROR_INVALID_ARGUMENT,
                                   "Invalid entry size: %" PRIu64, size);
            return MB_BI_FAILED;
        }

        update_size_if_unset(ctx, size);
    }

    return MB_BI_OK;
}

static int android_writer_write_data(MbBiWriter *biw, void *userdata,
                                     const void *buf, size_t buf_size,
                                     size_t *bytes_written)
{
    AndroidWriterCtx *const ctx = static_cast<AndroidWriterCtx *>(userdata);
    int ret;

    // At this point, we will already be aligned to a page boundary, so we can
    // directly write to the file.

    ret = _mb_bi_write_fully(biw->file, buf, buf_size, bytes_written);
    if (ret < 0) {
        mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                               "Failed to write data: %s",
                               mb_file_error_string(biw->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    } else if (*bytes_written != buf_size) {
        mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                               "Write was truncated: %s",
                               mb_file_error_string(biw->file));
        // This is a fatal error. We must guarantee that buf_size bytes will be
        // written.
        return MB_BI_FATAL;
    }

    // We always include the image in the hash. The size is sometimes included
    // and is handled in android_writer_get_entry().
    if (!SHA1_Update(&ctx->sha_ctx, buf, buf_size)) {
        mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                               "Failed to update SHA1 hash");
        // This must be fatal as the write already happened and cannot be
        // reattempted
        return MB_BI_FATAL;
    }

    if (ctx->entry_size > UINT32_MAX - buf_size
            || ctx->pos > UINT64_MAX - buf_size) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Overflow in entry size");
        return MB_BI_FATAL;
    }

    ctx->entry_size += buf_size;
    ctx->pos += buf_size;

    return MB_BI_OK;
}

static int android_writer_close(MbBiWriter *biw, void *userdata)
{
    AndroidWriterCtx *const ctx = static_cast<AndroidWriterCtx *>(userdata);
    int ret;
    size_t n;

    // If successful, finish up the boot image
    if (ctx->state == State::END) {
        // Write Samsung header
        ret = _mb_bi_write_fully(biw->file, SAMSUNG_SEANDROID_MAGIC,
                                 SAMSUNG_SEANDROID_MAGIC_SIZE, &n);
        if (ret != MB_FILE_OK || n != SAMSUNG_SEANDROID_MAGIC_SIZE) {
            mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                                   "Failed to write SEAndroid magic: %s",
                                   mb_file_error_string(biw->file));
            return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
        }

        // Set ID
        unsigned char digest[SHA_DIGEST_LENGTH];
        if (!SHA1_Final(digest, &ctx->sha_ctx)) {
            mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                                   "Failed to update SHA1 hash");
            return MB_BI_FATAL;
        }
        memcpy(ctx->hdr.id, digest, SHA_DIGEST_LENGTH);

        // Convert fields back to little-endian
        fix_header_byte_order(&ctx->hdr);

        // Seek back to beginning to write header
        ret = mb_file_seek(biw->file, 0, SEEK_SET, nullptr);
        if (ret != MB_FILE_OK) {
            mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                                   "Failed to seek to beginning: %s",
                                   mb_file_error_string(biw->file));
            return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
        }

        // Write header
        ret = _mb_bi_write_fully(biw->file, &ctx->hdr, sizeof(ctx->hdr), &n);
        if (ret != MB_FILE_OK || n != sizeof(ctx->hdr)) {
            mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                                   "Failed to write header: %s",
                                   mb_file_error_string(biw->file));
            return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
        }
    }

    return MB_BI_OK;
}

static int android_writer_free(MbBiWriter *bir, void *userdata)
{
    (void) bir;
    AndroidWriterCtx *const ctx = static_cast<AndroidWriterCtx *>(userdata);
    mb_bi_header_free(ctx->header);
    mb_bi_entry_free(ctx->entry);
    free(ctx);
    return MB_BI_OK;
}

MB_BEGIN_C_DECLS

/*!
 * \brief Set Android boot image output format
 *
 * \param biw MbBiWriter
 *
 * \return
 *   * #MB_BI_OK if the format is successfully enabled
 *   * #MB_BI_WARN if the format is already enabled
 *   * \<= #MB_BI_FAILED if an error occurs
 */
int mb_bi_writer_set_format_android(MbBiWriter *biw)
{
    AndroidWriterCtx *const ctx = static_cast<AndroidWriterCtx *>(
            calloc(1, sizeof(AndroidWriterCtx)));
    if (!ctx) {
        mb_bi_writer_set_error(biw, -errno,
                               "Failed to allocate AndroidWriterCtx: %s",
                               strerror(errno));
        return MB_BI_FAILED;
    }

    if (!SHA1_Init(&ctx->sha_ctx)) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Failed to initialize SHA_CTX");
        free(ctx);
        return false;
    }

    ctx->header = mb_bi_header_new();
    ctx->entry = mb_bi_entry_new();
    if (!ctx->header) {
        mb_bi_writer_set_error(biw, -errno,
                               "Failed to allocate header or entry: %s",
                               strerror(errno));
        mb_bi_header_free(ctx->header);
        mb_bi_entry_free(ctx->entry);
        free(ctx);
        return MB_BI_FAILED;
    }

    ctx->state = State::START;

    return _mb_bi_writer_register_format(biw,
                                         ctx,
                                         MB_BI_FORMAT_ANDROID,
                                         MB_BI_FORMAT_NAME_ANDROID,
                                         nullptr,
                                         &android_writer_get_header,
                                         &android_writer_write_header,
                                         &android_writer_get_entry,
                                         &android_writer_write_entry,
                                         &android_writer_write_data,
                                         &android_writer_close,
                                         &android_writer_free);
}

MB_END_C_DECLS
