/*
 *
 *  seeld - Secure Element Manager
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

int seel_manager_se_add(uint32_t se_idx, uint8_t ctrl_idx,
			uint8_t se_type, uint8_t ctrl_type);

int seel_manager_se_remove(uint32_t se_idx, uint8_t ctrl_idx,
			   uint8_t ctrl_type);
