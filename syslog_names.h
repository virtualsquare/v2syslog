#ifndef SYSLOG_NAMES_H
#define SYSLOG_NAMES_H
const char *syslog_prioname(int prio);
const char *syslog_facname(int facility);
int syslog_prion(const char *s);
int syslog_facn(const char *s);
#endif
