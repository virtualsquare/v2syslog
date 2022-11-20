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
v2syslogd(1) -- syslog server

# SYNOPSIS

`v2syslogd` [*options*]

# DESCRIPTION
`v2syslogd` is a syslog server implementation.i It can be configured to bind a UNIX datagram or a
UDP socket. It supports IPv6 and IPv4 and can run as a Internet of Threads process (IoTH).

# OPTIONS
  `-f` *conffile*, `--rcfile` *conffile*
: define the configuration file. The syntax is similar to syslog.conf. It is described here below in the next section. When omitted v2syslogd simply prints the log messages received on standard error.

  `-d`, `--daemon`
: run in daemon mode.

  `-p` *pidfile*, `--pidfile` *pidfile*
: set the pathname of the file to save daemon's pid.

  `-P` *portno*, `--port` *portno*
: use this port for UDP or TCP.

  `-T`, `--tcp`
: use TCP (not yet implemented).

  `-U`, `--udp`
: use UDP (default).

  `-u` *socket*, `--socket` *socket*
: use this UNIX socket.

  `-l` *path*, `--selflog` *path*
: set the pathname to file v2syslogd errors as syslog deamon errors cannot be managed by syslog itself. Errors are printed on standard error if not set.

  `-s` *ioth stack conf*, `--stack` *ioth stack conf*
: start v2syslogd as a Internet of Threads (IoTh) process, the parameter is the IoTh configuration string as supported by iothconf.

  `-4`, `--ipv4`
: use IPv4 only (th default behavior is to use IPv6 (and IPv4 in backwards compatibility mode if supported by the network stack).

# SEE ALSO
v2syslog(3), v2sysslog.conf(5)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli.
