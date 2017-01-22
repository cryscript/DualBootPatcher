/*
 * Copyright (C) TODO  Andrew Gunnerson <andrewgunnerson@gmail.com>
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

#include "mbbootimg/writer.h"
#include "mbbootimg/writer_p.h"

MB_BEGIN_C_DECLS

int mb_bi_writer_set_format_sony_elf(MbBiWriter *biw)
{
    mb_bi_writer_set_error(biw, MB_BI_ERROR_UNSUPPORTED, "Not supported");
    return MB_BI_OK;
}

MB_END_C_DECLS
