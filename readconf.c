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
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <v2syslog_const.h>
#include <selflog.h>
#include <logset.h>
#include <stropt.h>

struct logconf {
	struct logconf *next;
	struct logset set;
	char *path;
	char *format;
	int fd;
};

struct logconf *current_conf;

typedef void (*confcb) (char *path, char *format, int *fd, void *arg);
void confscan(int pri, confcb cb, void *arg) {
	for (struct logconf *scan = current_conf; scan != NULL; scan = scan->next) {
		if (pri == -1 || logsetok(&scan->set, pri))
				cb(scan->path, scan->format, &scan->fd, arg);
	}
}

static void free_logconf(struct logconf *head) {
	struct logconf *next;
	for (struct logconf *scan = head; scan != NULL; scan = next) {
		next = scan->next;
		if (scan->fd >= 0) {
			close(scan->fd);
			scan->fd = -1;
		}
		free(scan);
	}
}

int readfconf(FILE * f, const char *path) {
	char *line = NULL;
	size_t linelen = 0;
	int lineno = 0;
	int err = 0;
	struct logconf *head = NULL;
	struct logconf *tail = NULL;
	for (;;) {
		lineno++;
		if (getline(&line, &linelen, f) < 0)
			break;
		char *input = line;
		int tagc = stroptx(input, "\'\"\\#\n", "\t ", 0,
			 	NULL, NULL, NULL);
		if (tagc > 1) {
			if (tagc == 3 || tagc == 4) {
				char *tags[tagc];
				stroptx(input, "\'\"\\#\n", "\t ", 0,
						tags, NULL, input);
				struct logset set = {.set = {0}};
				if (logstr2set(tags[0], &set) < 0) 
					selflog(LOG_ERR, "conf %s: syntax error in line %d", path, lineno), err++;
				else {
					char *path = tags[1];
					char *format = (tagc == 4) ? tags[2] : NULL;
					char *home = "";
					if (path[0] == '~') {
						home = secure_getenv("HOME");
						if (home == NULL) {
							selflog(LOG_ERR, "conf %s: home dir error in line %d", path, lineno), err++;
							break;
						} else {
							if (path[1] == '\0')
								path = USER_SYSLOG_DEFAULT_PATH;
							else if (path[1] == '/')
								path++;
							else {
								selflog(LOG_ERR, "conf %s: filename error in line %d", path, lineno), err++;
								break;
							}
						}
					}
					struct logconf *new = malloc(sizeof(*new) + strlen(home) + strlen(path) + 1 +
							((format == NULL) ? 0 : (strlen(format) + 1)));
					new->next = NULL;
					new->set = set;
					new->path = (char *)(new + 1);
					strcpy(new->path, home);
					strcpy(new->path + strlen(home), path);
					if (tagc == 4) {
						new->format = new->path + strlen(home) + strlen(path) + 1;
						strcpy(new->format, format);
					} else
						new->format = NULL;
					new->fd = -1;
					if (head == NULL)
						head = tail = new;
					else
						tail->next = new, tail = new;
				}
			} else
				selflog(LOG_ERR, "conf %s: syntax error in line %d", path, lineno), err++;
		}
	}
	if (err > 0) {
		free_logconf(head);
		fclose(f);
		return -1;
	} else {
		free_logconf(current_conf);
		current_conf = head;
#if 0
		for (struct logconf *scan = current_conf; scan != NULL; scan = scan->next) {
			for (int i = 0; i < LOG_NFACILITIES; i++)
				printf("%02x.", scan->set.set[i]);
			printf(" + %s |%s|\n", scan->path, scan->format);
		}
#endif
		fclose(f);
		return 0;
	}
}

int readconf(int dirfd, char *path) {
	int fd = openat(dirfd, path, O_RDONLY);
	FILE *f;
	if (fd < 0) {
		selflog(LOG_ERR, "cannot open conf file %s", path);
		return -1;
	}
	f = fdopen(fd, "r");
	if (f == NULL) {
		selflog(LOG_ERR, "cannot open conf file %s", path);
		return -1;
	}
	return readfconf(f, path);
}

#if 0
int main(int argc, char *argv[]) {
	readconf(AT_FDCWD, argv[1]);
	for (struct logconf *scan = current_conf; scan != NULL; scan = scan->next) {
		for (int i = 0; i < LOG_NFACILITIES; i++)
			printf("%02x.", scan->set.set[i]);
		printf(" + %s |%s|\n", scan->path, scan->format);
	}
}
#endif
