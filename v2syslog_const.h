#ifndef V2SYSLOG_CONST_H
#define V2SYSLOG_CONST_H

/* default UNIX socket for syslog */
#define LOG_DEFAULT_PATH "/dev/log"

/* default port number for UDP/TCP */
#define LOG_DEFAULT_PORT 514

/* UNIX socket '~' means $HOME/.log */
#define USER_LOG_DEFAULT_PATH "/.log"

/* log file pathname '~' in v2syslogd conf file means $HOME/.syslog */
#define USER_SYSLOG_DEFAULT_PATH "/.syslog"

/* v2syslogd default conf contents if -f/--rcfile option is missing */
#define V2SYSLOG_DEFAULT_CONF "*.* /dev/stderr\n"

/* v2syslogd default output format if format is missing in a conf rule */
/* This format is BSD style, the output is similar to /var/log/syslog */
#define V2SYSLOG_DEFAULT_FORMAT "%T %H %a%[: %m"

#endif
