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
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <strcase.h>
#include <ioth.h>
#include <iothconf.h>
#include <fdprintf.h>
#include <readconf.h>
#include <syslog_names.h>
#include <selflog.h>

/* standard log format, BSD alike */
#define STDFMT  "%T %H %a%[: %m"
static int verbose;
static int fdcwd = -1;
static pid_t mypid;
static struct utsname my_uname;
static int reload = 0;
static char *conffile = NULL;
static char default_conf[] = "*.* /dev/stderr\n";

// self logging!
//#define selflog(X, F, ...) fprintf(stderr, F "\n", ##__VA_ARGS__)
#define LOG_DEFAULT_PATH "/dev/log"
#define USER_LOG_DEFAULT_PATH ".log"
#define LOG_DEFAULT_PORT 514

struct ioth *syslog_stack = NULL;
static int syslog_type = SOCK_DGRAM;
int port = LOG_DEFAULT_PORT;
static union sockaddr_any {
	struct sockaddr addr;
	struct sockaddr_un un;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
} syslog_sock;

/* unified log data item. */
struct logitem {
	int prio;
	struct timeval dtime; //daemon time
	struct timeval ltime; //logger time
	union sockaddr_any sender;
	char *host;
	char *appl;
	char *pid;
	char *msgid;
	char *structured;
	char *msg;
};
static char *nullval = "-";

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

/* month string -> tm_mon conversion (avoid locale defs) */
static int amon(char *month) {
	switch (strcase(month)) {
		case STRCASE(J,a,n) : return 0;
		case STRCASE(F,e,b) : return 1;
		case STRCASE(M,a,r) : return 2;
		case STRCASE(A,p,r) : return 3;
		case STRCASE(M,a,y) : return 4;
		case STRCASE(J,u,n) : return 5;
		case STRCASE(J,u,l) : return 6;
		case STRCASE(A,u,g) : return 7;
		case STRCASE(S,e,p) : return 8;
		case STRCASE(O,c,t) : return 9;
		case STRCASE(N,o,v) : return 10;
		case STRCASE(D,e,c) : return 11;
	}
	return -1;
}

/* month tm_mon -> str conversion (avoid locale defs) */
static char *amonth[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/* parse RFC3164 log messages */
/* 365.25 * 24 * 3600 / 2 */
#define HALF_YEAR_SECS 15778800
#define TOLERANCE_SECS (24L * 60 * 60)
void parse3164(char *msg, struct logitem *item) {
	struct tm tm = {0};
	struct tm localtime;
	char month[4];
	memset(&tm, 0, sizeof(tm));
	sscanf(msg, "%3s", month);
	if ((tm.tm_mon = amon(month)) < 0)
		goto msg_exit;
	if (sscanf(msg + 4,"%2d %2d:%2d:%2d",
				&tm.tm_mday,
				&tm.tm_hour,
				&tm.tm_min,
				&tm.tm_sec) != 4)
		goto msg_exit;
	localtime_r(&item->dtime.tv_sec, &localtime);
	tm.tm_year = localtime.tm_year;
	item->ltime.tv_sec = timegm(&tm);
	item->ltime.tv_sec -= localtime.tm_gmtoff;
	/* guess year */
	if ((item->dtime.tv_sec - item->ltime.tv_sec) > HALF_YEAR_SECS) {
		tm.tm_year = localtime.tm_year + 1;
		time_t newtime = timegm(&tm);
		if (labs(newtime - item->ltime.tv_sec) < TOLERANCE_SECS)
			item->ltime.tv_sec = newtime;
	} else if ((item->ltime.tv_sec - item->dtime.tv_sec) > HALF_YEAR_SECS) {
		tm.tm_year = localtime.tm_year - 1;
		time_t newtime = timegm(&tm);
		if (labs(newtime - item->ltime.tv_sec) < TOLERANCE_SECS)
			item->ltime.tv_sec = newtime;
	}
	msg += 15;
	if (*msg != ' ') goto msg_exit;
	char *space;
	while (*msg == ' ') msg++;
	space = strchr(msg, ' ');
	if (space == NULL) goto msg_exit;
	if (space[-1] == ':')	{ // app: or app[pid]:
		space[-1] = 0; item->appl = msg, msg = space + 1;
	} else {
		char *secondspace = strchr(space + 1, ' ');
		if (secondspace == NULL) goto msg_exit;
		if (secondspace[-1] == ':')	{ // hostname app: or hostname app[pid]:
			*space = 0; item->host = msg, msg = space + 1;
			secondspace[-1] = 0; item->appl = msg, msg = secondspace + 1;
		} else goto msg_exit;
	}
	char *pidopen = strchr(item->appl, '[');
	char *pidclose = strchr(item->appl, ']');
	if (pidopen != NULL && pidclose != NULL && pidopen > item->appl &&
			pidclose > pidopen && pidclose[1] == '\0') {
		*pidopen = *pidclose = 0;
		item->pid = pidopen + 1;
	}
msg_exit:
	item->msg = msg;
	return;
}

/* parse RFC5424 log messages */
char *skip_structured(char *s) {
	if (s[0] == '-' && s[1] == ' ')
		return s + 1;
	while (s[0] == '[') {
		char *close = strchr(s, ']');
		if (close == NULL) return NULL;
		s = close + 1;
	}
	return (*s == ' ') ? s : NULL;
}

void parse5424(char *msg, struct logitem *item) {
	struct tm tm = {0};
	struct timeval tv;
	char *tztail;
	if (sscanf(msg,"%04d-%02d-%02dT%02d:%02d:%02d",
				&tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
		goto msg_exit;
	tm.tm_mon -= 1;
	tm.tm_year -= 1900;
	tv.tv_sec = timegm(&tm);
	//printf(" %d %d %d %s\n",tm.tm_hour, tm.tm_min, tm.tm_sec, msg);
	tztail = msg + 19;
	if (tztail[0] == '.') {
		static int umul[] = {100000, 10000, 1000, 100, 10, 1};
		char *frac = tztail + 1;
		char *tail;
		tv.tv_usec = strtoul(frac, &tail, 10);
		int ndigit = tail - frac;
		if (ndigit == 0 || ndigit > 6)
			goto msg_exit;
		tv.tv_usec *= umul[ndigit - 1];
		tztail = frac + ndigit;
	}
	if (tztail[0] == 'Z')
		msg = tztail + 1;
	else if (tztail[0] == '+' || tztail[0] == '-') {
		int h, m;
		if (sscanf(tztail + 1,"%2d:%2d", &h, &m) < 2)
			goto msg_exit;
		time_t timediff = (h * 3600 + m * 60) * ((tztail[0] == '+') ? -1 : 1);
		tv.tv_sec += timediff;
		msg = tztail + 6;
	} else
		goto msg_exit;
	item->ltime = tv;
	if (*msg != ' ') goto msg_exit;
	char *space;
	while (*msg == ' ') msg++;
	space = strchr(msg, ' ');
	if (space == NULL) goto msg_exit;
	*space = 0; item->host = msg, msg = space + 1;
	while (*msg == ' ') msg++;
	space = strchr(msg, ' ');
	if (space == NULL) goto msg_exit;
	*space = 0; item->appl = msg, msg = space + 1;
	while (*msg == ' ') msg++;
	space = strchr(msg, ' ');
	if (space == NULL) goto msg_exit;
	*space = 0; item->pid = msg, msg = space + 1;
	while (*msg == ' ') msg++;
	space = strchr(msg, ' ');
	if (space == NULL) goto msg_exit;
	*space = 0; item->msgid = msg, msg = space + 1;
	while (*msg == ' ') msg++;
	space = skip_structured(msg);
	if (space == NULL) goto msg_exit;
	*space = 0; item->structured = msg, msg = space + 1;
msg_exit:
	item->msg = msg;
	return;
}

/* pretty printing and format management */
void strftimezone(FILE *f, long gmtoff) {
	long abs_gmtoff = (gmtoff >= 0) ? gmtoff : -gmtoff;
	int m = abs_gmtoff / 60;
	int h = m / 60;
	m %= 60;
	fprintf(f, "%c%02d:%02d", (gmtoff >= 0) ? '+' : '-', h, m);
}

void strfaddr(FILE *f, union sockaddr_any *addr, int add_port) {
	char buf[INET6_ADDRSTRLEN];
	switch (addr->addr.sa_family) {
		case AF_INET:
			fprintf(f, "%s",
					inet_ntop(AF_INET, &addr->in.sin_addr, buf, INET6_ADDRSTRLEN));
			if (add_port)
				fprintf(f, "/%d",
						ntohs(addr->in.sin_port));
			break;
		case AF_INET6:
			fprintf(f, "%s",
					inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, INET6_ADDRSTRLEN));
			if (add_port)
				fprintf(f, "/%d",
						ntohs(addr->in6.sin6_port));
			break;
		default: fprintf(f,"-");
	}
}

char *strflog(struct logitem *item, char *format) {
	char *out = NULL;
	size_t outlen = 0;
	FILE *f = open_memstream(&out, &outlen);
	char timestr[20];
	struct tm tm;
	int percent = 0;
	for (; *format != 0; format++) {
		if (percent == 0) {
			if (*format == '%')
				percent = 1;
			else
				putc(*format, f);
		} else {
			switch (*format) {
				case '%': putc('%', f); break;
				case 'P': fprintf(f, "%-7s", syslog_prioname(LOG_PRI(item->prio))); break;
				case 'F': fprintf(f, "%-8s", syslog_facname(LOG_FAC(item->prio))); break;
				case 't': localtime_r(&item->dtime.tv_sec, &tm);
									strftime(timestr, 20, "%Y-%m-%dT%H:%M:%S", &tm);
									fprintf(f, "%s.%06ld", timestr, item->dtime.tv_usec);
									strftimezone(f, tm.tm_gmtoff);
									break;
				case 'T': // legacy time (/var/log/syslog style)
									localtime_r(&item->dtime.tv_sec, &tm);
									strftime(timestr, 20, "%d %H:%M:%S", &tm);
									fprintf(f, "%s %s", amonth[tm.tm_mon], timestr);
									break;
				case 'U': gmtime_r(&item->ltime.tv_sec, &tm);
									strftime(timestr, 20, "%Y-%m-%dT%H:%M:%S", &tm);
									fprintf(f, "%s.%06ldZ", timestr, item->ltime.tv_usec);
									break;
				case 'I': strfaddr(f, &item->sender, 1);
									break; //sender
				case 'i': strfaddr(f, &item->sender, 0);
									break; //sender
				case 'h': fprintf(f, "%s", item->host); break;
				case 'H': // hostname OR IP addr OR nodename
									if (item->host != NULL && item->host[0] != 0 &&
											strcmp(item->host, nullval) != 0)
										fprintf(f, "%s", item->host);
									else if (item->sender.addr.sa_family == AF_INET ||
											item->sender.addr.sa_family == AF_INET6)
										strfaddr(f, &item->sender, 0);
									else
										fprintf(f, "%s", my_uname.nodename);
									break;
				case 'K': // IP addr or nodename
									if (item->sender.addr.sa_family == AF_INET ||
											item->sender.addr.sa_family == AF_INET6)
										strfaddr(f, &item->sender, 0);
									else
										fprintf(f, "%s", my_uname.nodename);
									break;
				case 'a': fprintf(f, "%s", item->appl); break;
				case 'p': fprintf(f, "%s", item->pid); break;
				case '[': // [pid] if pid is not null
									if (item->pid != NULL && item->pid[0] != 0 &&
											strcmp(item->pid, nullval) != 0)
										fprintf(f, "[%s]", item->pid);
									break;
				case 'M': fprintf(f, "%s", item->msgid); break;
				case 's': fprintf(f, "%s", item->structured); break;
				case 'm': fprintf(f, "%s", item->msg); break;
				default: fprintf(f, "%%%c", *format);
			}
			percent = 0;
		}
	}
	fclose(f);
	return out;
}

/* set snv var for management scripts */
static void syslog2env(struct logitem *item) {
  char buf[INET6_ADDRSTRLEN];
	setenv("SL_PRIO",  syslog_prioname(LOG_PRI(item->prio)), 1);
	setenv("SL_FAC", syslog_facname(LOG_FAC(item->prio)), 1);
	snprintf(buf, INET6_ADDRSTRLEN, "%"PRIu64, (uint64_t) item->dtime.tv_sec);
	setenv("SL_DTIME", buf, 1);
	snprintf(buf, INET6_ADDRSTRLEN, "%"PRIu64, (uint64_t) item->ltime.tv_sec);
	setenv("SL_LTIME", buf, 1);
  switch (item->sender.addr.sa_family) {
    case AF_INET:
			setenv("SL_SENDER",
					inet_ntop(AF_INET, &item->sender.in.sin_addr, buf, INET6_ADDRSTRLEN), 1);
			snprintf(buf, INET6_ADDRSTRLEN, "%u", ntohs(item->sender.in.sin_port));
			setenv("SL_SENDPORT", buf, 1);
      break;
    case AF_INET6:
			setenv("SL_SENDER",
					inet_ntop(AF_INET6, &item->sender.in6.sin6_addr, buf, INET6_ADDRSTRLEN), 1);
			snprintf(buf, INET6_ADDRSTRLEN, "%u", ntohs(item->sender.in6.sin6_port));
			setenv("SL_SENDPORT", buf, 1);
      break;
    default:
			setenv("SL_SENDER", "-", 1);
			setenv("SL_SENDPORT", "-", 1);
			break;
  }
	setenv("SL_HOST", item->host, 1);
	setenv("SL_APPL", item->appl, 1);
	setenv("SL_PID", item->pid, 1);
	setenv("SL_MSGID", item->msgid, 1);
	setenv("SL_MSG", item->msg, 1);
}

void syslogd_cb(char *path, char *format, int *fd, void *arg) {
	struct logitem *item = arg;
	char nl[] = {'\n'};
	if (path[0] == '!') {
		switch (fork()) {
			case 0:
				syslog2env(item);
				execl(path + 1, path + 1, NULL);
				selflog(LOG_ERR, "error running file %s", path + 1);
				exit(1);
			default:
				break;
			case -1:
				selflog(LOG_ERR, "error forking file %s", path + 1);
				break;
		}
		return;
	}
	char *fmt = (format == NULL) ? STDFMT : format;
	if (*fd < 0)
		*fd = openat(fdcwd, path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (*fd < 0)
		selflog(LOG_ERR, "error opening file %s", path);
	else {
		char *logline = strflog(item, fmt);
		struct iovec iov[] = {{logline, strlen(logline)},{nl, 1}};
		if (writev(*fd, iov, 2) < 0) {
			selflog(LOG_ERR, "error writing logfile %s", path);
		}
		free(logline);
	}
}

void touch_cb(char *path, char *format, int *fd, void *arg) {
	(void) format;
	(void) arg;
	if (path[0] == '!')
		return;
	if (*fd >= 0)
		close(*fd);
	*fd = openat(fdcwd, path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (*fd < 0)
    selflog(LOG_ERR, "error touching file %s", path);
  else
		close(*fd);
	*fd = -1;
}

int reloadconf(char *conffile) {
	if (conffile != NULL) {
		if (readconf(fdcwd, conffile) < 0) {
			selflog(LOG_ERR, "error loading conf file %s", conffile);
			return -1;
		}
	}
	confscan(-1, touch_cb, NULL);
	return 0;
}

void mainloop(int syslog_fd) {
	for (;;) {
		struct pollfd fds[] = {{syslog_fd, POLLIN, 0}};
		int pollout = poll(fds, 1, 1000);
		if (reload) {
			reload = 0;
			reloadconf(conffile);
		}
		if (pollout == 0) continue;
		if (pollout < 0) {
			if (errno == EINTR)
				continue;
			else
				break;
		}
		struct logitem item;
		int n = ioth_recvfrom(syslog_fd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, 0);
		if (n <= 0)
			return; //reopen
		char buf[n + 1]; //2048?
		socklen_t senderlen = sizeof(item.sender);
		item.sender.addr.sa_family = AF_UNSPEC;
		ioth_recvfrom(syslog_fd, buf, n, 0, (void *)&item.sender, &senderlen);
		buf[n] = 0;
		gettimeofday(&item.dtime, NULL);
		item.ltime = (struct timeval) {0, 0};
		/* default values */
		item.host = item.appl = item.pid = item.msgid = item.structured = item.msg = nullval;
		item.prio = LOG_MAKEPRI(LOG_USER, LOG_INFO);
		char *msg;
		if (buf[0] == '<' && (msg = strchr(buf, '>')) != NULL) {
			msg++;
			int prio = strtol(buf + 1, NULL, 10);
			item.prio = prio;
			if (*msg == '1')
				parse5424(msg + 2, &item);
			else
				parse3164(msg, &item);

			confscan(item.prio, syslogd_cb, &item);
		}
	}
}

/* signal handling */
static void terminate(int signum) {
	pid_t pid = getpid();
	if (pid == mypid)
		selflog(LOG_INFO, "(%d) leaving on signal %d", pid, signum);
	exit(0);
}

static void cont_handler(int signum) {
	switch (signum) {
		case SIGHUP: reload = 1; break;
		case SIGCHLD: wait(NULL); break;
	}
}

static void setsignals(void) {
	struct sigaction action = {
		.sa_handler = terminate
	};
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	struct sigaction cont = {
		.sa_handler = cont_handler,
		.sa_flags = SA_RESTART
	};
	sigaction(SIGHUP, &cont, NULL);
	sigaction(SIGCHLD, &cont, NULL);
}

void save_pidfile(char *pidfile, int fdcwd)
{
	int fd = openat(fdcwd, pidfile,
			O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		selflog(LOG_ERR, "error saving pidfile %s", pidfile);
		exit(1);
	}
	fdprintf(fd, "%ld\n", (long int)mypid);
	close(fd);
}

/* Main and command line args management */
void usage(char *progname)
{
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\t-f, --rcfile <conffile>  configuration file\n"
			"\t-d, --daemon             daemon mone\n"
			"\t-p, --pidfile <pidfile>  save daemon's pid\n"
			"\t-P, --port <portno>      use this port for udp or tcp\n"
			"\t-T, --tcp                use TCP (not yet implemented)\n"
			"\t-U, --udp                use UDP (default)\n"
			"\t-u, --socket <socket>    use this unix socket\n"
			"\t-l, --selflog <path>     define the path to log v2syslogd errs\n"
			"\t-s, --stack <ioth stack conf>\n"
			"\t-4, --ipv4               use IPv4 only\n"
			"\t-v, --verbose            verbose mode\n"
			"\t-h, --help\n",
			progname);
	exit(1);
}

static char *short_options = "hdvf:p:P:Uu:tl:s:4";
static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"daemon", 0, 0, 'd'},
	{"verbose", 0, 0, 'v'},
	{"rcfile", 1, 0, 'f'},
	{"pidfile", 1, 0, 'p'},
	{"port", 1, 0, 'P'},
	{"udp", 0, 0, 'U'},
	{"tcp", 0, 0, 't'},
	{"socket", 1, 0, 'u'},
	{"selflog", 1, 0, 'l'},
	{"stack", 1, 0, 's'},
	{"ipv4", 0, 0, '4'},
	{0,0,0,0}
};

static char *arg_tags = "dvpPUtuls4";
static union {
	struct {
		char *daemon;
		char *verbose;
		char *pidfile;
		char *port;
		char *udp;
		char *tcp;
		char *unixsock;
		char *selflog;
		char *stack;
		char *ipv4;
	};
	char *argv[sizeof(arg_tags)];
} args;

#ifndef _GNU_SOURCE
static inline char *strchrnul(const char *s, int c) {
	while (*s && *s != c)
		s++;
	return (char *) s;
}
#endif

static inline int argindex(char tag) {
	return strchrnul(arg_tags, tag) - arg_tags;
}

int main(int argc, char *argv[]) {
	char *progname = basename(argv[0]);
	int option_index;
	while(1) {
		int c;
		if ((c = getopt_long (argc, argv, short_options,
						long_options, &option_index)) < 0)
			break;
		switch (c) {
			case 'f':
				conffile = optarg;
				break;
			case -1:
			case '?':
			case 'h': usage(progname); break;
			default: {
								 int index = argindex(c);
								 if (args.argv[index] == NULL)
									 args.argv[index] = optarg ? optarg : "";
							 }
								break;
		}
	}
	if (argc != optind)
		usage(progname);

	mypid = getpid();
	/* saves current path in cwd, because otherwise with daemon() we
	 * forget it */
	if((fdcwd = open(".", O_PATH)) < 0) {
		selflog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}

	if (conffile) {
		if (reloadconf(conffile) < 0)
			exit(1);
	} else {
		FILE *f = fmemopen(default_conf, sizeof(default_conf), "r");
		if (readfconf(f, "default") < 0)
			exit(1);
	}

	if (args.verbose) verbose = 1;

	/* set syslog_sock fields */
	if (args.port)
		port = strtol(args.port, NULL, 10);
	if (args.unixsock) {
		struct stat sbuf;
		syslog_sock.addr.sa_family = AF_UNIX;
		if (args.unixsock[0] == '\0')
			snprintf(syslog_sock.un.sun_path, 108, "%s", LOG_DEFAULT_PATH);
		else if (args.unixsock[0] == '~') {
			char *home = getenv("HOME");
			if (home == NULL) home = "/";
			if (args.unixsock[1] == 0)
				snprintf(syslog_sock.un.sun_path, sizeof(syslog_sock.un.sun_path),
						"%s/" USER_LOG_DEFAULT_PATH, home);
			else
				snprintf(syslog_sock.un.sun_path, sizeof(syslog_sock.un.sun_path),
						"%s/%s", home, args.unixsock+1);
		} else
			snprintf(syslog_sock.un.sun_path, 108, "%s", args.unixsock);
		if (stat(syslog_sock.un.sun_path, &sbuf) == 0 &&
          S_ISSOCK(sbuf.st_mode))
        unlink(syslog_sock.un.sun_path);
	} else if (args.tcp) {
		syslog_sock.addr.sa_family = AF_INET6;
		syslog_type = SOCK_STREAM;
		selflog(LOG_ERR, "TCP support is still unimplemented");
		exit(1);
	} else { // -d is by default
		syslog_sock.addr.sa_family = AF_INET6;
	}
	if (args.ipv4 && syslog_sock.addr.sa_family == AF_INET6)
		syslog_sock.addr.sa_family = AF_INET;

	if (syslog_sock.addr.sa_family == AF_UNIX) {
		if (args.unixsock) {
			struct stat sbuf;
			syslog_sock.addr.sa_family = AF_UNIX;
			if (*args.unixsock == 0)
				args.unixsock = LOG_DEFAULT_PATH;
			snprintf(syslog_sock.un.sun_path, 108, "%s", args.unixsock);
			if (stat(syslog_sock.un.sun_path, &sbuf) == 0 &&
					S_ISSOCK(sbuf.st_mode))
				unlink(syslog_sock.un.sun_path);
		}
	} else {
		if (syslog_sock.addr.sa_family == AF_INET6)
			syslog_sock.in6.sin6_port = htons(port);
		else if (syslog_sock.addr.sa_family == AF_INET)
			syslog_sock.in.sin_port = htons(port);
		else {
			selflog(LOG_ERR, "address family error");
			exit(1);
		}
	}

	uname(&my_uname);

	if(args.stack) {
		syslog_stack=ioth_newstackc(args.stack);
		if (syslog_stack == NULL) {
			selflog(LOG_ERR, "Stack configuration error");
			exit(1);
		}
	}

	int syslog_fd;
	syslog_fd = ioth_msocket(syslog_stack, syslog_sock.addr.sa_family, syslog_type, 0);

	if (syslog_fd == -1) {
		selflog(LOG_ERR, "open socket error");
		return -1;
	}
	if (ioth_bind(syslog_fd, addr(), addrlen()) == -1) {
		selflog(LOG_ERR, "socket bind error");
		return -1; 
	}

	setsignals();
	if (args.daemon && daemon(0, 0)) {
		selflog(LOG_ERR,"daemon: %s", strerror(errno));
		exit(1);
	}

	if (args.selflog)
		set_selflog(fdcwd, args.selflog);

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(args.pidfile) save_pidfile(args.pidfile, fdcwd);

	mainloop(syslog_fd);
}

