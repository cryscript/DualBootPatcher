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

#include "mbcommon/endian.h"
#include "mbcommon/file.h"
#include "mbcommon/string.h"

#include "mbbootimg/entry.h"
#include "mbbootimg/file_p.h"
#include "mbbootimg/header.h"
#include "mbbootimg/header_p.h"
#include "mbbootimg/reader.h"
#include "mbbootimg/reader_p.h"

#define MAX_HEADER_OFFSET               512

enum class State
{
    START,
    KERNEL,
    RAMDISK,
    SECONDBOOT,
    DT,
    END,
};

struct AndroidReaderCtx
{
    // Header values
    AndroidHeader hdr;

    // Offsets
    bool have_header_offset;
    uint64_t header_offset;
    bool have_samsung_offset;
    uint64_t samsung_offset;
    uint64_t kernel_offset;
    uint64_t ramdisk_offset;
    uint64_t second_offset;
    uint64_t dt_offset;

    uint64_t file_size;

    State state;

    bool allow_truncated_dt;

    // For reading
    uint64_t read_start_offset;
    uint64_t read_end_offset;
    uint64_t read_cur_offset;
};

static const char * get_image_name(State state)
{
    switch (state) {
    case State::KERNEL:
        return "kernel";
    case State::RAMDISK:
        return "ramdisk";
    case State::SECONDBOOT:
        return "second bootloader";
    case State::DT:
        return "device tree";
    default:
        return "(unknown)";
    }
}

static void advance_state(AndroidReaderCtx *const ctx)
{
    switch (ctx->state) {
    case State::START:
        ctx->state = State::KERNEL;
        break;
    case State::KERNEL:
        ctx->state = State::RAMDISK;
        break;
    case State::RAMDISK:
        if (ctx->hdr.second_size > 0) {
            ctx->state = State::SECONDBOOT;
        } else if (ctx->hdr.dt_size > 0) {
            ctx->state = State::DT;
        } else {
            ctx->state = State::END;
        }
        break;
    case State::SECONDBOOT:
        if (ctx->hdr.dt_size > 0) {
            ctx->state = State::DT;
        } else {
            ctx->state = State::END;
        }
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

/*!
 * \brief Find and read Android boot image header
 *
 * \note The integral fields in the header will be converted to the host's byte
 *       order.
 *
 * \post The file pointer position is undefined after this function returns.
 *       Use mb_file_seek() to return to a known position.
 *
 * \param[in] bir MbBiReader
 * \param[out] header_out Pointer to store header
 * \param[out] offset_out Pointer to store header offset
 *
 * \return
 *   * MB_BI_OK if the header was found
 *   * MB_BI_WARN if the header was not found
 *   * MB_BI_FAILED if any file operations fail non-fatally
 *   * MB_BI_FATAL if any file operations fail fatally
 */
static int find_header(MbBiReader *bir, AndroidHeader *header_out,
                       uint64_t *offset_out)
{
    unsigned char buf[MAX_HEADER_OFFSET + sizeof(AndroidHeader)];
    size_t buf_size;
    int ret;
    void *ptr;
    size_t offset;

    ret = _mb_bi_read_fully(bir->file, buf, sizeof(buf), &buf_size);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to read header: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    ptr = mb_memmem(buf, buf_size, BOOT_MAGIC, BOOT_MAGIC_SIZE);
    if (!ptr) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Boot magic not found in first %d bytes",
                               MAX_HEADER_OFFSET);
        return MB_BI_WARN;
    }

    offset = static_cast<unsigned char *>(ptr) - buf;

    if (buf_size - offset < sizeof(AndroidHeader)) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Boot magic found at %" PRIu64
                               ", but header exceeds file size",
                               offset);
        return MB_BI_WARN;
    }

    // Copy header
    memcpy(header_out, ptr, sizeof(AndroidHeader));
    fix_header_byte_order(header_out);
    *offset_out = offset;

    return MB_BI_OK;
}

/*!
 * \brief Find location of Samsung SEAndroid magic
 *
 * \post The file pointer position is undefined after this function returns.
 *       Use mb_file_seek() to return to a known position.
 *
 * \param bir MbBiReader
 * \param hdr Android boot image header (in host byte order)
 * \param header_offset Offset of Android boot image header
 * \param offset Pointer to store magic offset
 *
 * \return
 *   * MB_BI_OK if the magic was found
 *   * MB_BI_WARN if the magic was not found
 *   * MB_BI_FAILED if any file operations fail non-fatally
 *   * MB_BI_FATAL if any file operations fail fatally
 */
static int find_samsung_footer(MbBiReader *bir, AndroidHeader *hdr,
                               uint64_t header_offset, uint64_t *offset)
{
    unsigned char buf[SAMSUNG_SEANDROID_MAGIC_SIZE];
    size_t buf_size;
    int ret;
    uint64_t pos = 0;

    // Skip header
    pos += header_offset;
    pos += sizeof(*hdr);
    pos += align_page_size<uint64_t>(pos, hdr->page_size);

    // Skip kernel
    pos += hdr->kernel_size;
    pos += align_page_size<uint64_t>(pos, hdr->page_size);

    // Skip ramdisk
    pos += hdr->ramdisk_size;
    pos += align_page_size<uint64_t>(pos, hdr->page_size);

    // Skip second bootloader
    pos += hdr->second_size;
    pos += align_page_size<uint64_t>(pos, hdr->page_size);

    // Skip device tree
    pos += hdr->dt_size;
    pos += align_page_size<uint64_t>(pos, hdr->page_size);

    ret = mb_file_seek(bir->file, pos, SEEK_SET, nullptr);
    if (ret < 0) {
        // If seek fails non-fatally, don't treat it as an error
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to seek SEAndroid magic offset: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_WARN;
    }

    ret = _mb_bi_read_fully(bir->file, buf, sizeof(buf), &buf_size);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to read SEAndroid magic: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    if (buf_size != SAMSUNG_SEANDROID_MAGIC_SIZE
            || memcmp(buf, SAMSUNG_SEANDROID_MAGIC, buf_size) != 0) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "SEAndroid magic not found in last %d bytes",
                               SAMSUNG_SEANDROID_MAGIC_SIZE);
        return MB_BI_WARN;
    }

    *offset = pos;
    return MB_BI_OK;
}

/*!
 * \brief Perform a bid
 *
 * \return
 *   * If \>= 0, the number of bits that conform to the Android format
 *   * MB_BI_WARN if this is a bid that can't be won
 *   * MB_BI_FAILED if any file operations fail non-fatally
 *   * MB_BI_FATAL if any file operations fail fatally
 */
static int android_reader_bid(MbBiReader *bir, void *userdata, int best_bid)
{
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(userdata);
    int bid = 0;
    int ret;

    if (best_bid >= (BOOT_MAGIC_SIZE + SAMSUNG_SEANDROID_MAGIC_SIZE) * 8) {
        // This is a bid we can't win, so bail out
        return MB_BI_WARN;
    }

    // Find the Android header
    ret = find_header(bir, &ctx->hdr, &ctx->header_offset);
    if (ret == MB_BI_OK) {
        // Update bid to account for matched bits
        ctx->have_header_offset = true;
        bid += BOOT_MAGIC_SIZE * 8;
    } else if (ret == MB_BI_WARN) {
        // Header not found. This can't be an Android boot image.
        return 0;
    } else {
        return ret;
    }

    // Find the Samsung magic
    ret = find_samsung_footer(bir, &ctx->hdr, ctx->header_offset,
                              &ctx->samsung_offset);
    if (ret == MB_BI_OK) {
        // Update bid to account for matched bits
        ctx->have_samsung_offset = true;
        bid += SAMSUNG_SEANDROID_MAGIC_SIZE * 8;
    } else if (ret == MB_BI_WARN) {
        // Nothing found. Don't change bid
    } else {
        return ret;
    }

    return bid;
}

static int android_reader_set_option(MbBiReader *bir, void *userdata,
                                     const char *key, const char *value)
{
    (void) bir;

    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(userdata);

    if (strcmp(key, "strict") == 0) {
        bool strict = strcasecmp(value, "true") == 0
                || strcasecmp(value, "yes") == 0
                || strcasecmp(value, "y") == 0
                || strcmp(value, "1") == 0;
        ctx->allow_truncated_dt = !strict;
        return MB_BI_OK;
    } else {
        return MB_BI_WARN;
    }
}

static int android_reader_read_header(MbBiReader *bir, void *userdata,
                                      MbBiHeader *header)
{
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(userdata);
    int ret;

    if (!ctx->have_header_offset) {
        // A bid might not have been performed if the user forced a particular
        // format
        ret = find_header(bir, &ctx->hdr, &ctx->header_offset);
        if (ret < 0) {
            return ret;
        }
    }

    // Get file size
    ret = mb_file_seek(bir->file, 0, SEEK_END, &ctx->file_size);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to get file size: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    char board_name[sizeof(ctx->hdr.name) + 1];
    char cmdline[sizeof(ctx->hdr.cmdline) + 1];

    strncpy(board_name, reinterpret_cast<char *>(ctx->hdr.name),
            sizeof(ctx->hdr.name));
    strncpy(cmdline, reinterpret_cast<char *>(ctx->hdr.cmdline),
            sizeof(ctx->hdr.cmdline));
    board_name[sizeof(ctx->hdr.name)] = '\0';
    cmdline[sizeof(ctx->hdr.cmdline)] = '\0';

    // TODO: Don't depend on private headers
    header->fields_supported =
            MB_BI_HEADER_FIELD_BOARD_NAME
            | MB_BI_HEADER_FIELD_KERNEL_CMDLINE
            | MB_BI_HEADER_FIELD_PAGE_SIZE
            | MB_BI_HEADER_FIELD_KERNEL_ADDRESS
            | MB_BI_HEADER_FIELD_RAMDISK_ADDRESS
            | MB_BI_HEADER_FIELD_SECONDBOOT_ADDRESS
            | MB_BI_HEADER_FIELD_KERNEL_TAGS_ADDRESS;

    ret = mb_bi_header_set_board_name(header, board_name);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_kernel_cmdline(header, cmdline);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_page_size(header, ctx->hdr.page_size);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_kernel_address(header, ctx->hdr.kernel_addr);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_ramdisk_address(header, ctx->hdr.ramdisk_addr);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_secondboot_address(header, ctx->hdr.second_addr);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_header_set_kernel_tags_address(header, ctx->hdr.tags_addr);
    if (ret != MB_BI_OK) return ret;

    // TODO: unused
    // TODO: id

    // Calculate offsets for each section

    uint64_t pos = 0;
    uint32_t page_size = mb_bi_header_page_size(header);

    // pos cannot overflow due to the nature of the operands (adding UINT32_MAX
    // a few times can't overflow a uint64_t). File length overflow is checked
    // during read.

    // Header
    pos += ctx->header_offset;
    pos += sizeof(AndroidHeader);
    pos += align_page_size<uint64_t>(pos, page_size);

    // Kernel
    ctx->kernel_offset = pos;
    pos += ctx->hdr.kernel_size;
    pos += align_page_size<uint64_t>(pos, page_size);

    // Ramdisk
    ctx->ramdisk_offset = pos;
    pos += ctx->hdr.ramdisk_size;
    pos += align_page_size<uint64_t>(pos, page_size);

    // Second bootloader
    ctx->second_offset = pos;
    pos += ctx->hdr.second_size;
    pos += align_page_size<uint64_t>(pos, page_size);

    // Device tree
    ctx->dt_offset = pos;
    pos += ctx->hdr.dt_size;
    pos += align_page_size<uint64_t>(pos, page_size);

    return MB_BI_OK;
}

static int android_reader_read_entry(MbBiReader *bir, void *userdata,
                                     MbBiEntry *entry)
{
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(userdata);

    // Advance to next entry
    advance_state(ctx);

    uint64_t offset;
    uint64_t size;
    uint64_t type;
    const char *name;
    int ret;

    switch (ctx->state) {
    case State::KERNEL:
        offset = ctx->kernel_offset;
        size = ctx->hdr.kernel_size;
        type = MB_BI_ENTRY_KERNEL;
        name = "kernel";
        break;
    case State::RAMDISK:
        offset = ctx->ramdisk_offset;
        size = ctx->hdr.ramdisk_size;
        type = MB_BI_ENTRY_RAMDISK;
        name = "ramdisk";
        break;
    case State::SECONDBOOT:
        offset = ctx->second_offset;
        size = ctx->hdr.second_size;
        type = MB_BI_ENTRY_SECONDBOOT;
        name = "secondboot";
        break;
    case State::DT:
        offset = ctx->dt_offset;
        size = ctx->hdr.dt_size;
        type = MB_BI_ENTRY_DEVICE_TREE;
        name = "device_tree";
        break;
    case State::END:
        return MB_BI_EOF;
    default:
        mb_bi_reader_set_error(bir, MB_BI_ERROR_INTERNAL_ERROR,
                               "Illegal state: %d",
                               static_cast<int>(ctx->state));
        return MB_BI_FATAL;
    }

    // Check truncation here instead of in android_reader_read_data() so we can
    // give the caller an accurate size value
    if (offset > ctx->file_size) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "%s image offset exceeds file size "
                               "(expected %" PRIu64 " more bytes)",
                               get_image_name(ctx->state),
                               ctx->read_end_offset - ctx->read_cur_offset);
        return MB_BI_FAILED;
    }

    if (size > ctx->file_size || offset > ctx->file_size - size) {
        // Except in the case of the DT image because some devices can (and do)
        // boot with a truncated image
        if (ctx->state != State::DT || !ctx->allow_truncated_dt) {
            mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                                   "%s image is truncated "
                                   "(expected %" PRIu64 " more bytes)",
                                   get_image_name(ctx->state),
                                   ctx->read_end_offset - ctx->read_cur_offset);
            return MB_BI_FAILED;
        }

        size = ctx->file_size - offset;
    }

    bool need_seek = ctx->read_cur_offset != offset;

    // Integer overflow already checked in android_reader_read_header()
    ctx->read_start_offset = offset;
    ctx->read_end_offset = ctx->read_start_offset + size;
    ctx->read_cur_offset = ctx->read_start_offset;

    if (need_seek) {
        ret = mb_file_seek(bir->file, ctx->read_start_offset, SEEK_SET,
                           nullptr);
        if (ret < 0) {
            return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
        }
    }

    ret = mb_bi_entry_set_type(entry, type);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_entry_set_name(entry, name);
    if (ret != MB_BI_OK) return ret;

    ret = mb_bi_entry_set_size(entry, size);
    if (ret != MB_BI_OK) return ret;

    return MB_BI_OK;
}

static int android_reader_read_data(MbBiReader *bir, void *userdata,
                                    void *buf, size_t buf_size,
                                    size_t *bytes_read)
{
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(userdata);

    size_t to_copy = std::min<size_t>(
            buf_size, ctx->read_end_offset - ctx->read_cur_offset);

    int ret = _mb_bi_read_fully(bir->file, buf, to_copy, bytes_read);
    if (ret < 0) {
        mb_bi_reader_set_error(bir, mb_file_error(bir->file),
                               "Failed to read data: %s",
                               mb_file_error_string(bir->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    if (ctx->read_cur_offset > SIZE_MAX - *bytes_read) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "Current offset %" PRIu64 " with read size %"
                               MB_PRIzu " would overflow integer",
                               ctx->read_cur_offset, *bytes_read);
        return MB_BI_FATAL;
    }

    ctx->read_cur_offset += *bytes_read;

    // Fail if we reach EOF early
    if (*bytes_read == 0 && ctx->read_cur_offset != ctx->read_end_offset) {
        mb_bi_reader_set_error(bir, MB_BI_ERROR_FILE_FORMAT,
                               "%s image is truncated "
                               "(expected %" PRIu64 " more bytes)",
                               get_image_name(ctx->state),
                               ctx->read_end_offset - ctx->read_cur_offset);
        return MB_BI_FATAL;
    }

    return *bytes_read == 0 ? MB_BI_EOF : MB_BI_OK;
}

static int android_reader_free(MbBiReader *bir, void *userdata)
{
    (void) bir;
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(userdata);
    free(ctx);
    return MB_BI_OK;
}

MB_BEGIN_C_DECLS

/*!
 * \brief Enable support for Android boot image format
 *
 * \param bir MbBiReader
 *
 * \return
 *   * #MB_BI_OK if the format is successfully enabled
 *   * #MB_BI_WARN if the format is already enabled
 *   * \<= #MB_BI_FAILED if an error occurs
 */
int mb_bi_reader_enable_format_android(MbBiReader *bir)
{
    AndroidReaderCtx *const ctx = static_cast<AndroidReaderCtx *>(
            calloc(1, sizeof(AndroidReaderCtx)));
    if (!ctx) {
        mb_bi_reader_set_error(bir, -errno,
                               "Failed to allocate AndroidReaderCtx: %s",
                               strerror(errno));
        return MB_BI_FAILED;
    }

    ctx->state = State::START;

    // Allow truncated dt image by default
    ctx->allow_truncated_dt = true;

    return _mb_bi_reader_register_format(bir,
                                         ctx,
                                         MB_BI_FORMAT_ANDROID,
                                         MB_BI_FORMAT_NAME_ANDROID,
                                         &android_reader_bid,
                                         &android_reader_set_option,
                                         &android_reader_read_header,
                                         &android_reader_read_entry,
                                         &android_reader_read_data,
                                         &android_reader_free);
}

MB_END_C_DECLS
