# v2syslog
Syslog library and deamon for virtualsquare projects

# Motivation

Syslog is a service for deamon processes to provide feedback about their
operational status.

Initially created for sendmail it is de facto (and de jure) standard for logging.
Syslog *standard* has been defined by RFC 3164 and then by RFC 5424.

The implementation provided by glibc and the syslog deamons currently available in
Linux distributions is based on a two/three tiers architecture:

* `syslog(3)` facility included in glibc provides functions to send log messages
to a local daemon running on the same host (it uses a `AF_UNIX`)

* `syslogd` (nowadays often provided by a systemd metastasis) is a local server which collects
the log messages from local deamon and dispatches them to log file archives and/or
to syslog centralized servers (using the UDP or TCP services defined in the RFCs).

* Site, institution centralized `syslog` servers collectioning all the relevant log messages.
Sysadms can monitor the status of a large number of hosts by examining or processing the
log messages managed by these servers.

This implementation design is unfit for virtualsquare projects:
* Internet of Threads (IoTh) processes **are** network nodes, having their own personality on
the network. The physical host (e.g. Linux box) they are currently running on is merely
incidental. The *local* syslogd has no roles in this architecture.
* By VUOS users can run their own daemons in user space, using user privileges.
All VUOS modules create specific execution environments for processes, likewise user
implemented namespaces: neither root access nor specific capabilities are required.
Using the currently available syslog implementation users can run their daemons but
root access is required to read the log messsages (e.g. read the `/var/log/syslog` file)
or configure syslog to store or process log messages elseway (e.g. by editing `/etc/syslog.conf`
file)

`v2syslog` provides a library which enables daemon processes to route their log messages to
networked logging services.
A syslog server deamon named `v2syslogd` is included. This syslog daemon can run as an
IoTh process.

# `v2syslog`
The API of `v2syslog` is a backwards compatible extension of `syslog(3)`.

```C
void v2openlog(const char *ident, int option, int facility);
void v2closelog(void);
void v2syslog(int priority, const char *format, ...);
void v2vsyslog(int priority, const char *format, va_list ap);
```

The signature and the meaning of the arguments is the same of their counterparts in `syslog(3)`
(without the `v2` prefix). The library should work as drop-in replacement of syslog functions:
any program using `syslog(3)` can use `v2*log` functions instead of `*log` with no appreciable
changes in its behavior.

`v2syslog` provides extended functionnalities.

### `v2setlog`

The function `v2setlog` defines the local or remote syslog deamon where log messages will be routed to.
```C
void v2setlog(struct ioth *stack, struct v2syslog_server server,
    const char *hostname, const char *procid);
```

* `stack` is the IoTh stack to use (see [libioth](https://github.com/virtualsquare/libioth)). The kernel provided TCP-IP stack is used when the argument `stack` is `NULL`.
* `server` is the address of the syslog deamon to use. Some convenient macros are provided to
define this argument.
    - `v2syslog_UNIX(path)`: the deamon is reachable at the UNIX socket `path`.
    - `v2syslog_INET(addr, port)`: the daemon is available at the `port` at the IPv4 address `addr`.
    - `v2syslog_INET6(addr, port)`: the daemon is available at the `port` at the IPv6 address `addr`.
* `hostname` is the host name to appear in the log messages (`nodename` returned by `uname(2)` is used if `hostname` is NULL)
* `procid` is the process id for log messages (`getpid` or `gettid` output is used if this arg is `NULL`

Examples:

* use `/tmp/service/.log` instead of `/dev/log`:
```C
        v2setlog(NULL, v2syslog_UNIX("/tmp/service/.log", NULL, NULL)
```

* use `.mylog` in the home directory instead of `/dev/log`:
```C
        v2setlog(NULL, v2syslog_UNIX("~/.mylog", NULL, NULL)
```

* use `.log` in the home directory (the default user path) instead of `/dev/log`:
```C
        v2setlog(NULL, v2syslog_UNIX("~", NULL, NULL)
```

* send logs to a server running at 192.168.1.1 at port 5140.
```C
        struct in_addr ip4addr;
        inet_pton(AF_INET, "192.168.1.1", &ip4addr);
        v2setlog(NULL, v2syslog_INET(&ip4addr, 5140), NULL, NULL);
```

* send logs to a server running at 10.0.0.1 using a IoTh stack (vxvde, localaddr=10.0.0.100):
```C
        struct ioth *stack = ioth_newstackc(
           "stack=vdestack,vnl=vxvde://234.0.0.1,eth,ip=10.0.0.100/24");
        struct in_addr ip4addr;
        inet_pton(AF_INET, "10.0.0.1", &ip4addr);
        v2setlog(stack, v2syslog_INET(&ip4addr, 514), "magicdaemon", NULL);
```


### `v2openlog` new options

`v2openlog` supports more options than `openlog`.

* `LOG_STREAM`: try to send log messages using stream sockets (TCP or UNIX-stream)
* `LOG_STREAM_ONLY`: send log messages using stream sockets (TCP or UNIX-STREAM) only
* `LOG_DGRAM_ONLY`: send log messages using datagram sockets (UDP or UNIX-DGRAM) only
* `LOG_3164`: use the protocol defined in RFC 3164
* `LOG_5424`: use the protocol defined in RFC 5424
* `LOG_FRAMING_COUNT`: use the octet counting (3.1.1 of RFC 6587)
* `LOG_USE_TID`: send tid (thread id) instead of pid

(When both `LOG_3164` and `LOG_5424` are not set, the default protocol of `syslog(3)` is used.
It is like RFC 3164 but no hostname is added. It is the legacy BSD protocol).

### `v2syslogx` and `v2vsyslogx`

`v2syslogx` and `v2vsyslogx` are extended versions of `v2syslog` and `v2vsyslog` providing
two further arguments:

* `msg_id`: define message id (6.2.7 of RFC 5424),
* `struct_data`: set structured data (6.3 of RFC 5424).

# `v2syslogd`

`v2syslogd` is a syslog daemon. It currently supports UNIX datagram and UDP.

The main command line options are:

* `-f <conffile>` or `--rcfile <conffile>`: define the configuration file. The syntax is
similar to syslog.conf. It is described here below in the next section. When omitted `v2syslogd` simply
prints the log messages received on standard error.
* `-d` or `--daemon`: run `v2syslogd` in background as a daemon. This option is often used together
with `-p <pidfile>` of `--pidfile <pidfile>` to store the actual process id of the deamon (to terminate
it by a SIGTERM message or to reload the configuration file using a SIGHUP message).
* `-P <portno>` or `--port <portno>`: define the port (default value 514).
* `-U` or `--udp`: use UDP (can be omitted, UDP is the default configration).
* `-u <socket>` or `--socket <socket>`: use a UNIX socket bound at the specified pathname.
* `-l <path>` or `--selflog <path>`: set the pathname to file v2syslogd errors as syslog deamon errors
cannot be managed by syslog itself! Errors are printed on standard error if not set.
* `-s <ioth stack configuration>` or `--stack <ioth stack configuration>`: start v2syslogd as a IoTh process, the parameter is the IoTh configuration string as supported by [iothconf](https://github.com/virtualsquare/iothconf).
* `-4` or `--ipv4`: use IPv4 only (th default behavior is to use IPv4 and IPv6.

### v2syslog configuration file

The syntax is similar to [syslog.conf](https://linux.die.net/man/5/syslog.conf):
"Every rule consists of two fields, a selector field and an action field. These
two fields are separated by one or more spaces or tabs. The selector field
specifies a pattern of facilities and priorities belonging to the specified
action."

Lines beginning by `#` are comments.

The syntax of selectors is the same described in [syslog.conf](https://linux.die.net/man/5/syslog.conf).

The action can be the pathname of a file or the pathname of a script/program prefixed by `!`.
In the former case (file) all log messages matching the selector are added (in append mode) to the
named file. It is possible to add a format string at the end of the line.
The format string is similar to printf or strftime format strings: all the characters of the
format are verbtim copied to the output except for the following conversion specifications:

* `%%`: a percent symbol
* `%P`: the priority name
* `%F`: the facility name
* `%t`: the local time of the reception of the message by `v2syslogd`, using the format of the Example 4,
RFC 5424, section 6.2.3.1.
* `%T`: the local time of the reception of the message by `v2syslogd`, using the BSD legacy format (RFC 3164
compliant)
* `%U`: the timestamp got by the sender (the logging process). It is provided in the format of RFC5424 UTC
* `%I`: the IP address and port of the sender process
* `%i`: the IP address of the sender process
* `%h`: the hostname
* `%H`: the hostname if specified otherwise the IP address if defined otherwise the nodename
* `%K`: the IP address if defined otherwise the nodename
* `%a`: the application
* `%p`: the process id
* `%[`: returns `[pid]`	 if the process id is defined, an empty string otherwise
* `%M`: the message id
* `%s`: the structured data
* `%m`: the log message

When not specified the default format is `"%T %H %a%[: %m"`: it is the same format used in /var/log/syslog.
e.g.
```
Aug 09 17:40:41 eipi10 renzo: test message
Aug 09 17:40:54 deamonhost mydaemon[367407]: second test
```
a quite complete output can be obtained using the format `"%F %P %t %U %I %h %a %p %M %s %m"`:
```
user     notice  2022-08-09T17:49:33.343428+02:00 2022-08-09T15:49:33.343073Z ::ffff:10.0.0.101/57507 eipi10 renzo - - test message
```

If the action field begins by exclamative mark `!` `v2syslog` starts an instance of the script/program
for each received message matching the selector. All the fields of the log item are provided to
the script/program as environment variables:

* `SL_PRIO`: priority name
* `SL_FAC`: facility name
* `SL_DTIME`: daemon time (UTC seconds from teh epoch)
* `SL_LTIME`: logging/sender time (UTC seconds from teh epoch)
* `SL_SENDER`: IP address of the sender
* `SL_SENDPORT`: IP port of the sender
* `SL_HOST`: hostname
* `SL_APPL`: application
* `SL_PID`: pricess id/thread id
* `SL_MSGID`: message id
* `SL_MSG`: the log message

### v2syslog configuration file example:

```
*.crit    /dev/stderr
*.*       /tmp/syslog "%F %P %t %U %I %h %a %p %M %s %m"
```

all the log messages are appended to /tmp/syslog, the log messages of level critical or above are also
printed on the standard error file.
