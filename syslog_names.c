/*
 * v2syslogd: syslog daemon for virtualsquare
 * Copyright (C) 2022  Renzo Davoli, Virtualsquare University of Bologna
 *
 * v2syslogd is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define SYSLOG_NAMES
#include <stdio.h>
#include <string.h>
#include <syslog.h>

const char *syslog_prioname(int prio) {
  CODE *this;
  for (this = prioritynames; this->c_name != NULL; this++) {
    if (this->c_val == prio)
      return this->c_name;
  }
  return "unknown";
}

const char *syslog_facname(int facility) {
  CODE *this;
  facility <<= 3;
  for (this = facilitynames; this->c_name != NULL; this++) {
    if (this->c_val == facility)
      return this->c_name;
  }
  return "unknown";
}

int syslog_prion(const char *s) {
  for (CODE *item = prioritynames;
      item->c_name != NULL;
      item++) {
    if (strcmp(s, item->c_name) == 0)
      return item->c_val;
  }
  return -1;
}

int syslog_facn(const char *s) {
  for (CODE *item = facilitynames;
      item->c_name != NULL;
      item++) {
    if (strcmp(s, item->c_name) == 0)
      return item->c_val >> 3;
  }
  return -1;
}

