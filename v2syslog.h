#ifndef V2SYSLOG_H
#define V2SYSLOG_H
#include <stdint.h>
#include <syslog.h>
struct ioth;

void v2openlog(const char *ident, int option, int facility);
void v2closelog(void);

#define LOG_STREAM           (1 << 24)
#define LOG_ONLY             (1 << 25)
#define LOG_DGRAM_ONLY       LOG_ONLY
#define LOG_STREAM_ONLY      (LOG_STREAM | LOG_ONLY)
// LOG_3164==0 && LOG_5424==0 means old BSD, no hostname
#define LOG_3164             (1 << 26)   // RFC 3164
#define LOG_5424             (1 << 27)   // RFC 5424
#define LOG_OLDPROTO         LOG_3164
#define LOG_NEWPROTO         LOG_5424
#define LOG_FRAMING_COUNT    (1 << 28)   // RFC 6587
#define LOG_USE_TID          (1 << 29)

void v2syslog(int priority, const char *format, ...);
void v2vsyslog(int priority, const char *format, va_list ap);

void v2syslogx(int priority, const char *msg_id, const char *struct_data, const char *format, ...);
void v2vsyslogx(int priority, const char *msg_id, const char *struct_data,
		const char *format, va_list ap);

struct v2syslog_server {
  int af;
	union {
		void *addr;
		char *straddr;
	};
  uint16_t port;
};

#define v2syslog_UNIX(PATH) ((struct v2syslog_server) \
      { .af = AF_UNIX, .straddr = PATH})
#define v2syslog_INET(ADDR, PORT) ((struct v2syslog_server) \
      { .af = AF_INET, .addr = ADDR, .port = PORT})
#define v2syslog_INET6(ADDR, PORT) ((struct v2syslog_server) \
      { .af = AF_INET6, .addr = ADDR, .port = PORT})

void v2setlog(struct ioth *stack, struct v2syslog_server server,
		const char *hostname, const char *procid);

#endif
