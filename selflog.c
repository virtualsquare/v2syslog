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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog_names.h>

char *logfile;
int fdcwd;
extern char* __progname;

void set_selflog(int dirfd, char *selflogfile) {
	fdcwd = dirfd;
	logfile = selflogfile;
}

void selflog(int priority, const char *format, ...) {
  va_list arg;
	int err = 0;
	char *buf;
	size_t bufsize;
  va_start (arg, format);
	FILE *f = open_memstream(&buf, &bufsize);
	fprintf(f, "%s %s: ", __progname, syslog_prioname(priority));
	vfprintf(f, format, arg);
	fprintf(f, "\n");
	fclose(f);
	va_end (arg);
	
	if (logfile != NULL) {
		int fd = openat(fdcwd, logfile, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
		if (fd < 0)
			err = 1;
		else {
			if (write(fd, buf, bufsize) < 0)
				err = 1;
			close(fd);
		}
	}
	if (logfile == NULL || err)
		fprintf(stderr, "%s", buf);
}
