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

#include "mbbootimg/file_p.h"

#include "mbcommon/file.h"

MB_BEGIN_C_DECLS

int _mb_bi_read_fully(MbFile *file, void *buf, size_t size,
                      size_t *bytes_read)
{
    size_t total = 0;
    size_t n;
    int ret;

    while (total < size) {
        ret = mb_file_read(file, static_cast<char *>(buf) + total,
                           size - total, &n);
        if (ret == MB_FILE_RETRY) {
            continue;
        } else if (ret < 0) {
            return ret;
        } else if (n == 0) {
            break;
        }

        total += n;
    }

    *bytes_read = total;
    return MB_FILE_OK;
}

int _mb_bi_write_fully(MbFile *file, const void *buf, size_t size,
                       size_t *bytes_written)
{
    size_t total = 0;
    size_t n;
    int ret;

    while (total < size) {
        ret = mb_file_write(file, static_cast<const char *>(buf) + total,
                            size - total, &n);
        if (ret == MB_FILE_RETRY) {
            continue;
        } else if (ret < 0) {
            return ret;
        } else if (n == 0) {
            break;
        }

        total += n;
    }

    *bytes_written = total;
    return MB_FILE_OK;
}

MB_END_C_DECLS
