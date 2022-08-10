/*
 * v2syslog: syslog library for virtualsquare
 * Copyright (C) 2022  Renzo Davoli Virtualsquare University of Bologna
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program;
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <syslog.h>
#include <ioth.h>

#include <v2syslog_const.h>
#include <v2syslog.h>

#define PID_STR_SIZE (((sizeof(pid_t) * 8  + 2) / 3) + 1)

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
extern char *__progname;
static const char *syslog_ident;
static int syslog_option;
static int syslog_facility = LOG_USER;
static int syslog_fd = -1;
static int syslog_type = SOCK_DGRAM;
static char *syslog_procid;
static char *syslog_hostname;
static struct ioth *syslog_stack;
static union {
	struct sockaddr addr;
	struct sockaddr_un un;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
} syslog_sock;

static socklen_t addrlen(void) {
	switch(syslog_sock.addr.sa_family) {
		case AF_UNIX:
		default: return sizeof(syslog_sock.un);
		case AF_INET: return sizeof(syslog_sock.in);
		case AF_INET6: return sizeof(syslog_sock.in6);
	}
}

static struct sockaddr *addr(void) {
	return &syslog_sock.addr;
}

static int family(void) {
	if (syslog_sock.addr.sa_family == AF_UNSPEC) {
		syslog_sock.un.sun_family = AF_UNIX;
		snprintf(syslog_sock.un.sun_path, sizeof(syslog_sock.un.sun_path), "%s", LOG_DEFAULT_PATH);
	}
	return syslog_sock.addr.sa_family;
}

static int change_syslog_type(void) {
	switch (syslog_type) {
		case SOCK_DGRAM:
			if (syslog_option & LOG_ONLY) return -1;
			syslog_type = SOCK_STREAM;
			break;
		case SOCK_STREAM:
			if (syslog_option & LOG_ONLY) return -1;
			syslog_type = SOCK_DGRAM;
			break;
	}
	return 0;
}

/* open and connect a socket */
static int __openlog(void) {
	syslog_fd = ioth_msocket(syslog_stack, family(), syslog_type | SOCK_CLOEXEC, 0);
	if (syslog_fd == -1)
		return -1;
	if (ioth_connect(syslog_fd, addr(), addrlen()) == -1) {
		int saved_errno = errno;
		ioth_close(syslog_fd);
		syslog_fd = -1;
		return errno = saved_errno, -1;
	}
	return 0;
}

#define strdup_update(X, Y) do { \
	if ((X) != NULL) free(X); \
	(X) = ((Y) == NULL || (Y)[0] == 0) ? NULL : strdup(Y); \
} while (0);

void v2setlog(struct ioth *stack,struct v2syslog_server server,
    const char *hostname, const char *procid) {
	pthread_mutex_lock(&mutex);
	syslog_stack = stack;
	if (syslog_fd != -1) ioth_close(syslog_fd);
	syslog_fd = -1;

	if (server.port == 0) server.port = LOG_DEFAULT_PORT;
	memset(&syslog_sock, 0, sizeof(syslog_sock));
	switch(server.af) {
		case AF_UNIX:
		default:
			syslog_sock.un.sun_family = AF_UNIX;
			if (server.addr == NULL) server.addr = LOG_DEFAULT_PATH;
			snprintf(syslog_sock.un.sun_path, sizeof(syslog_sock.un.sun_path), "%s", server.straddr);
			if (syslog_sock.un.sun_path[0] == '~') {
				char *home = secure_getenv("HOME");
				if (home == NULL) home = "/";
				if (syslog_sock.un.sun_path[1] == 0)
					snprintf(syslog_sock.un.sun_path, sizeof(syslog_sock.un.sun_path),
							"%s" USER_LOG_DEFAULT_PATH, home);
				else
					snprintf(syslog_sock.un.sun_path, sizeof(syslog_sock.un.sun_path),
							"%s/%s", home, server.straddr);
			}
			break;
		case AF_INET:
			syslog_sock.in.sin_family = AF_INET;
			syslog_sock.in.sin_addr = *((struct in_addr *) server.addr);
			syslog_sock.in.sin_port = htons(server.port);
			break;
		case AF_INET6:
			syslog_sock.in6.sin6_family = AF_INET6;
			syslog_sock.in6.sin6_addr = *((struct in6_addr *) server.addr);
			syslog_sock.in6.sin6_port = htons(server.port);
			break;
	}
	strdup_update(syslog_hostname, hostname);
	strdup_update(syslog_procid, procid);
	pthread_mutex_unlock(&mutex);
}

void v2openlog(const char *ident, int option, int facility) {
	pthread_mutex_lock(&mutex);
	syslog_ident = (ident != NULL) ? ident : __progname;
	syslog_option = option;
	facility &= LOG_FACMASK;
	syslog_facility = (facility > 0 && LOG_FAC(facility) < LOG_NFACILITIES) ? facility : LOG_USER;
	syslog_type = (syslog_option & LOG_STREAM) ? SOCK_STREAM : SOCK_DGRAM;
	if (syslog_hostname == NULL) {
		struct utsname uts;
		uname(&uts);
		syslog_hostname = strdup(uts.nodename);
	}
	if (option & LOG_NDELAY) {
		if (__openlog() < 0 && (change_syslog_type() < 0 || __openlog() < 0)) {
			syslog_fd = -1;
			if (syslog_option & LOG_CONS)
				fprintf(stderr, "log server is unreachable\n");
		}
	}
	pthread_mutex_unlock(&mutex);
}

void v2closelog(void) {
	pthread_mutex_lock(&mutex);
	if (syslog_fd != -1) ioth_close(syslog_fd);
	syslog_fd = -1;
	pthread_mutex_unlock(&mutex);
}

static const char *get_syslog_pid(char *buf) {
	if (syslog_procid != NULL)
		return syslog_procid;
	snprintf(buf, PID_STR_SIZE, "%d",
#ifdef _GNU_SOURCE
			(syslog_option & LOG_USE_TID) ? gettid() : getpid()
#else
			getpid()
#endif
			);
	return buf;
}

/* avoid locale translation of monthes, setlocale would have affected the entire process */
static char *no_locale_months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static void header_3164(FILE *f, int priority) {
	fprintf (f, "<%d>", syslog_facility + priority);
	char timestr[13];
	time_t now;
	struct tm tmbuf;
	time(&now);
	if (syslog_ident == NULL) syslog_ident = __progname;
	localtime_r(&now, &tmbuf);
	strftime(timestr, 13, " %e %T", localtime_r(&now, &tmbuf));
	fprintf(f, "%s%s ", no_locale_months[tmbuf.tm_mon], timestr);
	if (syslog_hostname != NULL && (syslog_option & LOG_3164)) // 3164 requires id
		fprintf(f, "%s ", syslog_hostname);
	fprintf(f, "%s", syslog_ident);
	char pid_str_buf[PID_STR_SIZE];
	if (syslog_option & LOG_PID)
		fprintf(f, "[%s]: ", get_syslog_pid(pid_str_buf));
	else
		fprintf(f, ": ");
}

static void header_5424(FILE *f, int priority, const char *msg_id, const char *struct_data) {
	fprintf (f, "<%d>1 ", syslog_facility + priority);
	char timestr[21];
	struct timeval now;
	gettimeofday(&now, NULL);
	struct tm tmbuf;
	if (syslog_ident == NULL) syslog_ident = __progname;
	strftime(timestr, 21, "%Y-%m-%dT%H:%M:%S.", gmtime_r(&now.tv_sec, &tmbuf));
	char pid_str_buf[PID_STR_SIZE];
	fprintf(f, "%s%06ldZ %s %s %s %s %s ", timestr, now.tv_usec,
			(syslog_hostname != NULL) ? syslog_hostname : "-",
			syslog_ident,
			(syslog_option & LOG_PID) ? get_syslog_pid(pid_str_buf) : "-",
			(msg_id != NULL) ? msg_id : "-",
			(struct_data != NULL) ? struct_data : "-");
}

static int v2syslog_send(char *buf, size_t bufsize) {
	if (syslog_type == SOCK_DGRAM)
		return ioth_send(syslog_fd, buf, bufsize, 0);
	else {
		if (syslog_option & LOG_FRAMING_COUNT) {
			size_t lenlen = snprintf(NULL, 0, "%ld ", bufsize);
			char lenbuf[lenlen];
			snprintf(lenbuf, lenlen, "%ld ", bufsize);
			struct iovec iov[] = {{lenbuf, lenlen}, {buf, bufsize}};
			return ioth_writev(syslog_fd, iov, 2);
		} else
			return ioth_send(syslog_fd, buf, bufsize + 1, 0);
	}
}

static int v2syslog_stderr(char *buf, size_t bufsize) {
	char nl[]="\n";
	struct iovec iov[] = {{buf, bufsize}, {nl, 1}};
	return writev(STDERR_FILENO, iov, 2);
}

void v2vsyslogx(int priority, const char *msg_id, const char *struct_data,
		const char *format, va_list ap) {
	char *buf = 0;
	size_t bufsize = 0;
	int failure = 0;
	FILE *f = open_memstream(&buf, &bufsize);
	pthread_mutex_lock(&mutex);
	priority &= LOG_PRIMASK;
	if (syslog_option & LOG_5424)
		header_5424(f, priority, msg_id, struct_data);
	else
		header_3164(f, priority);
	long msg_offset = ftell(f);
	vfprintf(f, format, ap);
	fclose(f);
	if (syslog_fd == -1) {
		family(); // set to AF_UNIX if it is AF_UNSPEC
		if (__openlog() < 0 && (change_syslog_type() < 0 || __openlog() < 0))
			syslog_fd = -1, failure = 1;
	}
	if (syslog_fd != -1) {
		if (v2syslog_send(buf, bufsize) < 0) {
			ioth_close(syslog_fd);
			if (__openlog() < 0 && (change_syslog_type() < 0 || __openlog() < 0))
				syslog_fd = -1, failure = 1;
			else
				v2syslog_send(buf, bufsize);
		}
	}
	if (syslog_option & LOG_PERROR ||
			((syslog_option & LOG_CONS) && failure))
		v2syslog_stderr(buf + msg_offset, bufsize - msg_offset);
	pthread_mutex_unlock(&mutex);
}

void v2vsyslog(int priority, const char *format, va_list ap) {
	v2vsyslogx(priority, NULL, NULL, format, ap);
}

void v2syslogx(int priority, const char *msg_id, const char *struct_data, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	v2vsyslogx(priority, msg_id, struct_data, format, ap);
	va_end(ap);
}

void v2syslog(int priority, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	v2vsyslog(priority, format, ap);
	va_end(ap);
}
