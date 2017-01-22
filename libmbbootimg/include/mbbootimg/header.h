/*
 * Copyright (C) 2017  Andrew Gunnerson <andrewgunnerson@gmail.com>
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

#ifdef __cplusplus
#  include <cstdint>
#else
#  include <stdint.h>
#endif

#include "mbcommon/common.h"

MB_BEGIN_C_DECLS

struct MbBiHeader;

// Basic object manipulation

MB_EXPORT struct MbBiHeader * mb_bi_header_new();
MB_EXPORT void mb_bi_header_free(struct MbBiHeader *header);
MB_EXPORT void mb_bi_header_clear(struct MbBiHeader *header);
MB_EXPORT struct MbBiHeader * mb_bi_header_clone(struct MbBiHeader *header);

// Fields

// Board name field

MB_EXPORT const char * mb_bi_header_board_name(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_board_name(struct MbBiHeader *header,
                                          const char *name);

// Kernel cmdline field

MB_EXPORT const char * mb_bi_header_kernel_cmdline(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_kernel_cmdline(struct MbBiHeader *header,
                                              const char *cmdline);

// Page size field

MB_EXPORT int mb_bi_header_page_size_is_set(struct MbBiHeader *header);
MB_EXPORT uint32_t mb_bi_header_page_size(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_page_size(struct MbBiHeader *header,
                                         uint32_t page_size);
MB_EXPORT int mb_bi_header_unset_page_size(struct MbBiHeader *header);

// Kernel address field

MB_EXPORT int mb_bi_header_kernel_address_is_set(struct MbBiHeader *header);
MB_EXPORT uint32_t mb_bi_header_kernel_address(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_kernel_address(struct MbBiHeader *header,
                                              uint32_t address);
MB_EXPORT int mb_bi_header_unset_kernel_address(struct MbBiHeader *header);

// Ramdisk address field

MB_EXPORT int mb_bi_header_ramdisk_address_is_set(struct MbBiHeader *header);
MB_EXPORT uint32_t mb_bi_header_ramdisk_address(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_ramdisk_address(struct MbBiHeader *header,
                                               uint32_t address);
MB_EXPORT int mb_bi_header_unset_ramdisk_address(struct MbBiHeader *header);

// Second bootloader address field

MB_EXPORT int mb_bi_header_secondboot_address_is_set(struct MbBiHeader *header);
MB_EXPORT uint32_t mb_bi_header_secondboot_address(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_secondboot_address(struct MbBiHeader *header,
                                                  uint32_t address);
MB_EXPORT int mb_bi_header_unset_secondboot_address(struct MbBiHeader *header);

// Kernel tags address field

MB_EXPORT int mb_bi_header_kernel_tags_address_is_set(struct MbBiHeader *header);
MB_EXPORT uint32_t mb_bi_header_kernel_tags_address(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_kernel_tags_address(struct MbBiHeader *header,
                                                   uint32_t address);
MB_EXPORT int mb_bi_header_unset_kernel_tags_address(struct MbBiHeader *header);

// Sony IPL address field

MB_EXPORT int mb_bi_header_sony_ipl_address_is_set(struct MbBiHeader *header);
MB_EXPORT uint32_t mb_bi_header_sony_ipl_address(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_sony_ipl_address(struct MbBiHeader *header,
                                                uint32_t address);
MB_EXPORT int mb_bi_header_unset_sony_ipl_address(struct MbBiHeader *header);

// Sony RPM address field

MB_EXPORT int mb_bi_header_sony_rpm_address_is_set(struct MbBiHeader *header);
MB_EXPORT uint32_t mb_bi_header_sony_rpm_address(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_sony_rpm_address(struct MbBiHeader *header,
                                                uint32_t address);
MB_EXPORT int mb_bi_header_unset_sony_rpm_address(struct MbBiHeader *header);

// Sony APPSBL address field

MB_EXPORT int mb_bi_header_sony_appsbl_address_is_set(struct MbBiHeader *header);
MB_EXPORT uint32_t mb_bi_header_sony_appsbl_address(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_sony_appsbl_address(struct MbBiHeader *header,
                                                   uint32_t address);
MB_EXPORT int mb_bi_header_unset_sony_appsbl_address(struct MbBiHeader *header);

// Entrypoint address field

MB_EXPORT int mb_bi_header_entrypoint_address_is_set(struct MbBiHeader *header);
MB_EXPORT uint32_t mb_bi_header_entrypoint_address(struct MbBiHeader *header);
MB_EXPORT int mb_bi_header_set_entrypoint_address(struct MbBiHeader *header,
                                                  uint32_t address);
MB_EXPORT int mb_bi_header_unset_entrypoint_address(struct MbBiHeader *header);

MB_END_C_DECLS
