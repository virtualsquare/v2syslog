<!--
.\" Copyright (C) 2022 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->

# NAME

v2openlog, v2closelog, v2syslog, v2vsyslog, v2setlog, v2syslogx, v2vsyslogx - send messages to a local or networked logger

# SYNOPSIS

`#include <v2syslog.h>`

`void v2openlog(const char *` _ident_`, int ` _option,_` int ` _facility_`);`

`void v2closelog(void);`

`void v2syslog(int ` _priority_`, const char *` _format_`, ...);`

`void v2vsyslog(int ` _priority_`, const char *` _format_`, va_list ` _ap_`);`

`void v2setlog(struct ioth *` _stack_`, struct v2syslog_server ` _server_`, const char *` _hostname_`, const char *` _procid_`);`

`void v2syslogx(int ` _priority_`, const char *` _msg_id_`, const char *` _struct_data_`, const char *` _format_`, ...);`

`void v2vsyslogx(int ` _priority_`, const char *` _msg_id_`, const char *` _struct_data_`, const char *` _format_`, va_list ` _ap_`);`

# DESCRIPTION

`v2syslog` is a library which enables daemon processes to route their log messages to local or networked logging services.

It is an extension of `syslog`(3). `v2syslog` has been designed for Virtualsquare processes:

* Internet of Threads (IoTh) processes are network nodes, having their own personality on the network (IP address, independent TCP-IP stack). The physical host (e.g. Linux box) they are currently running on is merely incidental. The local syslogd has no roles in this architecture.

* By VUOS users can run their own daemons in user space, using user privileges. All VUOS modules create specific execution environments for processes, likewise if they were some sort of user level implemented namespaces: neither root access nor specific capabilities are required. Using the currently available syslog implementation users can run their daemons but root access is required to read the log messsages (e.g. read the /var/log/syslog file) or configure syslog to store or process log messages elsewhere (e.g. by editing /etc/syslog.conf file)

This library provides the following functions:

  `v2openlog()`
: `v2openlog()` opens a connection to the system logger for a program. The arguments are the same of `openlog`(3).
: The values that may be specified for _option_ are described below.

  `v2closelog()`
: `v2closelog()` closes the file descriptor being used to write to the system logger.  The use of closelog() is optional.

  `v2syslog()`, `v2vsyslog()`
: `v2syslog()`  generates  and send a  log  message that can be processed by `syslogd`(8) or `v2syslogd`(1) or any other
: logger using the protocols defined by RFC 3124 or RFC 5424.
: The arguments are the same of `syslog`(3) or `vsyslog`(3).

  `v2setlog()`
: `v2setlog()` defines the logging service to use. _stack_ is the Internet of Thread stack to use (the kernel provided stack
: is used if _stack_ is NULL).
: > _server_ defines the logging server address. Some convenient macros are provided to set this argument:

: >> `v2syslog_UNIX(`_PATH_`)`: the deamon is reachable at the UNIX socket _PATH_.

: >> `v2syslog_INET(`_ADDR_`, `_PORT_`)`: the daemon is available at the IPv4 address _ADDR_, the port is _PORT_. _ADDR_ is a pointer to a _struct in_addr_ (in network byte order).

: >> `v2syslog_INET6(`_ADDR_`, ` _PORT_`)`: the daemon is available at the IPv6 address _ADDR_, the port is _PORT_. _ADDR_ is a pointer to a _struct in6_addr_ (in network byte order).

: > _hostname_ defines the hostname value included in log messages (_nodename_ returned by `uname(2)` is used if _hostname_ is NULL)

: > _procid_ defines the procid value for the log messages (the output of `getpid`(2) or `gettid`(2) is used if this argment is NULL).

  `v2syslogx()`, `v2vsyslogx()`
: These functions extend `v2syslog()` and `v2vsyslog()` respectively. Two further arguments are provided:

: _msg_id_ define the message id (6.2.7 of RFC 5424),

: _struct_data_ define the structured-date (6.3 of RFC 5424).

  Values for _option_:
: The _option_ argument to `v2openlog()` is a bit mask. Its value is the bitwise-or of the values defined for `openlog`(3)
: and the following values:

: > `LOG_STREAM` try to send log messages using stream sockets (TCP or UNIX-STREAM)

: > `LOG_STREAM_ONLY` send log messages using stream sockets (TCP or UNIX-STREAM) only

: > `LOG_DGRAM_ONLY` send log messages using datagram sockets (UDP or UNIX-DGRAM) only

: > `LOG_3164` use the protocol defined in RFC 3164

: > `LOG_5424` use the protocol defined in RFC 5424

: > `LOG_FRAMING_COUNT` use the octet counting (3.1.1 of RFC 6587)

: > `LOG_USE_TID` send tid (thread id) instead of pid

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli
