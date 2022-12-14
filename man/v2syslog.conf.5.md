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

v2syslog.conf -- `v2syslogd`(1) configuration file

# DESCRIPTION

The syntax is similar to `syslog.conf`(5): "Every rule consists of two fields, a selector field and an action field. These two fields are separated by one or more spaces or tabs. The selector field specifies a pattern of facilities and priorities belonging to the specified action."

Lines beginning by # are comments.

The syntax of selectors is the same described in `syslog.conf`(5).

The action can be the pathname of a file or the pathname of a script/program prefixed by `!`. In the former case (file) all log messages matching the selector are added (in append mode) to the named file. It is possible to add a format string at the end of the line. The format string is similar to printf or strftime format strings: all the characters of the format are verbtim copied to the output except for the following conversion specifications:

  `%%`
: a percent symbol.

  `%P`
: the priority name.

  `%F`
: the facility name

  `%t`
: the local time of the reception of the message by v2syslogd, using the format of the Example 4, RFC 5424, section 6.2.3.1.

  `%T`
: the local time of the reception of the message by v2syslogd, using the BSD legacy format (RFC 3164 compliant)

  `%U`
: the timestamp got by the sender (the logging process). It is provided in the format of RFC5424 UTC

  `%I`
: the IP address and port of the sender process

  `%i`
: the IP address of the sender process

  `%h`
: the hostname

  `%H`
: the hostname if specified otherwise the IP address if defined otherwise the nodename

  `%K`
: the IP address if defined otherwise the nodename

  `%a`
: the application

  `%p`
: the process id

  `%[`
: returns [pid]  if the process id is defined, an empty string otherwise

  `%M`
: the message id

  `%s`
: the structured data

  `%m`
: the log message

When not specified, the default format is `"%T %H %a%[: %m"`: it is the same format used in /var/log/syslog. e.g.

Aug 09 17:40:41 eipi10 renzo: test message
Aug 09 17:40:54 deamonhost mydaemon[367407]: second test

a quite complete output can be obtained using the format "%F %P %t %U %I %h %a %p %M %s %m":

```
user     notice  2022-08-09T17:49:33.343428+02:00 2022-08-09T15:49:33.343073Z ::ffff:10.0.0.101/57507 eipi10 renzo - - test message
```

If the action field begins by exclamative mark ! v2syslog starts an instance of the script/program for each received message matching the selector. All the fields of the log item are provided to the script/program as environment variables:

  `SL_PRIO`
: priority name

  `SL_FAC`
: facility name

  `SL_DTIME`
: daemon time (UTC seconds from the epoch)

  `SL_LTIME`
: logging/sender time (UTC seconds from the epoch)

  `SL_SENDER`
: IP address of the sender

  `SL_SENDPORT`
: IP port of the sender

  `SL_HOST`
: hostname

  `SL_APPL`
: application

  `SL_PID`
: pricess id/thread id

  `SL_MSGID`
: message id

  `SL_MSG`
: the log message

# Examples:

A simple example:

```
  *.crit * *   /dev/stderr
  *.* * *      /tmp/testlog   "%F %P %t %U %I %h %a %p %M %s %m"
  user.notice  ~
```

all the log messages are appended to /tmp/syslog, the log messages of level critical or above are also printed on the standard error file. Log messages whose faicility is user and level notice or above are also appended to the default user syslog file: $HOME/.syslog (where $HOME is the pathname of the user's home directory, retrieved from the HOME env variable).

# SEE ALSO
v2syslogd(1)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli.
