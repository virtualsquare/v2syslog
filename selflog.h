#ifndef SELFLOG_H
#define SELFLOG_H
void set_selflog(int dirfd, char *selflogfile);
void selflog(int priority, const char *format, ...);
#endif
