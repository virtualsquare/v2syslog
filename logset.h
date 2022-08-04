#ifndef LOGSET_H
#define LOGSET_H
#include <stdint.h>
#include <sys/syslog.h>

struct logset {
	uint8_t set[LOG_NFACILITIES];
};

int logsetok(struct logset *set, int prival);

int logstr2set(const char *str, struct logset *set);

#endif
