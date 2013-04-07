/* Exit status related declarations.
   Copyright (C) 2009, 2010, 2011, 2012 Free Software Foundation, Inc.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

GNU Wget is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wget.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef WGET_EXITS_H
#define WGET_EXITS_H

#include "wget.h"


void inform_exit_status (uerr_t err);

int get_exit_status (void);

/* Final exit code possibilities. Exit codes 1 and 2 are reserved
 * for situations that lead to direct exits from Wget, not using the
 * value of final_exit_status. */
enum
  {
    WGET_EXIT_SUCCESS = 0,

    WGET_EXIT_MINIMUM = 3,
    WGET_EXIT_IO_FAIL = WGET_EXIT_MINIMUM,
    WGET_EXIT_NETWORK_FAIL = 4,
    WGET_EXIT_SSL_AUTH_FAIL = 5,
    WGET_EXIT_SERVER_AUTH_FAIL = 6,
    WGET_EXIT_PROTOCOL_ERROR = 7,
    WGET_EXIT_SERVER_ERROR = 8,

    WGET_EXIT_UNKNOWN
  };


#endif /* WGET_EXITS_H */
