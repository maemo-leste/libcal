/**
   @file cal.h

   @brief Maemo Configuration Access Library

   Copyright (C) 2012 Ivaylo Dimitrov <freemangordon@abv.bg>

   This file is part of libcal.

   this library is free software;
   you can redistribute it and/or modify it under the terms of the
   GNU Lesser General Public License version 2.1 as published by the
   Free Software Foundation.

   libcal is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with osso-systemui-powerkeymenu.
   If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef CAL_H
#define CAL_H

#define CAL_MAX_NAME_LEN	16
#define CAL_FLAG_USER		0x0001
#define CAL_FLAG_WRITE_ONCE	0x0002

#ifdef __cplusplus
extern "C" {
#endif

struct cal;

extern void (* cal_debug_log)(int level, const char *str);
extern void (* cal_error_log)(const char *str);

int  cal_init(struct cal** cal_out);
void cal_finish(struct cal* cal);

int  cal_read_block(struct cal*    cal,
                    const char*    name,
                    void**         ptr,
                    unsigned long* len,
                    unsigned long  flags);
int  cal_write_block(struct cal*   cal,
                     const char*   name,
                     const void*   data,
                     unsigned long data_len,
                     unsigned long flags);

int  cal_lock_otp_area(struct cal* cal, unsigned int flag);

#ifdef __cplusplus
}
#endif

#endif
