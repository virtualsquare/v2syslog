#ifndef READCONF_H
#define READCONF_H
typedef void (*confcb) (char *path, char *format, int *fd, void *arg);
void confscan(int pri, confcb cb, void *arg);
int readfconf(FILE *f, char *path);
int readconf(int dirfd, char *path);
#endif
