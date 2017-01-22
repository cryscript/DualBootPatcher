/*
 * Copyright (C) 2016  Andrew Gunnerson <andrewgunnerson@gmail.com>
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

#pragma once

#include "mbbootimg/guard_p.h"

#include <cstdint>

#define MB_BI_HEADER_FIELD_KERNEL_ADDRESS       (1ULL << 1)
#define MB_BI_HEADER_FIELD_RAMDISK_ADDRESS      (1ULL << 2)
#define MB_BI_HEADER_FIELD_SECONDBOOT_ADDRESS   (1ULL << 3)
#define MB_BI_HEADER_FIELD_KERNEL_TAGS_ADDRESS  (1ULL << 4)
#define MB_BI_HEADER_FIELD_SONY_IPL_ADDRESS     (1ULL << 5)
#define MB_BI_HEADER_FIELD_SONY_RPM_ADDRESS     (1ULL << 6)
#define MB_BI_HEADER_FIELD_SONY_APPSBL_ADDRESS  (1ULL << 7)
#define MB_BI_HEADER_FIELD_PAGE_SIZE            (1ULL << 8)
#define MB_BI_HEADER_FIELD_BOARD_NAME           (1ULL << 9)
#define MB_BI_HEADER_FIELD_KERNEL_CMDLINE       (1ULL << 10)

// Raw header fields
// TODO TODO TODO
#define MB_BI_HEADER_FIELD_KERNEL_SIZE          (1ULL << 11)
#define MB_BI_HEADER_FIELD_RAMDISK_SIZE         (1ULL << 12)
#define MB_BI_HEADER_FIELD_SECONDBOOT_SIZE      (1ULL << 13)
#define MB_BI_HEADER_FIELD_DEVICE_TREE_SIZE     (1ULL << 14)
#define MB_BI_HEADER_FIELD_UNUSED               (1ULL << 15)
#define MB_BI_HEADER_FIELD_ID                   (1ULL << 16)
#define MB_BI_HEADER_FIELD_ENTRYPOINT           (1ULL << 17)
// TODO TODO TODO

struct MbBiHeader
{
    // Bitmap of fields that are supported
    uint64_t fields_supported;

    // Bitmap of fields that are set
    uint64_t fields_set;

    struct {
        // Used in:                    | Android | Loki | Bump | Mtk | Sony |
        uint32_t kernel_addr;       // | X       | X    | X    | X   | X    |
        uint32_t ramdisk_addr;      // | X       | X    | X    | X   | X    |
        uint32_t second_addr;       // | X       | X    | X    | X   |      |
        uint32_t tags_addr;         // | X       | X    | X    | X   |      |
        uint32_t ipl_addr;          // |         |      |      |     | X    |
        uint32_t rpm_addr;          // |         |      |      |     | X    |
        uint32_t appsbl_addr;       // |         |      |      |     | X    |
        uint32_t page_size;         // | X       | X    | X    | X   |      |
        char *board_name;           // | X       | X    | X    | X   |      |
        char *cmdline;              // | X       | X    | X    | X   |      |
        // Raw header values           |---------|------|------|-----|------|

        // TODO TODO TODO
        uint32_t hdr_kernel_size;   // | X       | X    | X    | X   |      |
        uint32_t hdr_ramdisk_size;  // | X       | X    | X    | X   |      |
        uint32_t hdr_second_size;   // | X       | X    | X    | X   |      |
        uint32_t hdr_dt_size;       // | X       | X    | X    | X   |      |
        uint32_t hdr_unused;        // | X       | X    | X    | X   |      |
        uint32_t hdr_id[8];         // | X       | X    | X    | X   |      |
        uint32_t hdr_entrypoint;    // |         |      |      |     | X    |
        // TODO TODO TODO
    } field;
};
