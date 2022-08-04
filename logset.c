/*
 * v2syslogd: syslog daemon for virtualsquare
 * Copyright (C) 2022  Renzo Davoli, Virtualsquare University of Bologna
 *
 * v2syslogd is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/syslog.h>
#include <logset.h>
#include <syslog_names.h>

int logsetok(struct logset *set, int prival) {
	return !!(set->set[LOG_FAC(prival)] & (1 << LOG_PRI(prival)));
}

int logstr2set(const char *str, struct logset *set) {
	size_t buflen = strlen(str) + 1;
	char buf[buflen];
	snprintf(buf, buflen, "%s", str);
	char *tscan, *stscan, *term;
	for (tscan = buf;
			(term = strtok_r(tscan, ";", &stscan)) != NULL;
			tscan = NULL) {
		char *prio = strchr(term, '.');
		if (prio == NULL) return -1;
		*prio = 0;
		prio++;
		uint64_t facset = 0;
		char *fscan, *sfscan, *fac;
		for (fscan = term;
				(fac = strtok_r(fscan, ",", &sfscan)) != NULL;
				fscan = NULL) {
			if (strcmp(fac, "*") == 0)
				facset = ~0LL;
			else {
				int n = syslog_facn(fac);
				if (n < 0 || n >= (int) (sizeof(facset) * 8))
					return -1;
				facset |= (1 << n);
			}
		}
		uint8_t prioset = 0;
		char *pscan, *spscan, *prit;
		for (pscan = prio;
				(prit = strtok_r(pscan, ",", &spscan)) != NULL;
				pscan = NULL) {
			int not = 0;
			int eq = 0;
			if (strcmp(prit,"none") == 0) prit = "!*";
			if (prit[0] == '!') not = 1, prit++;
			if (prit[0] == '=') eq = 1, prit++;
			if (strcmp(prit, "*") == 0)
				prioset = 0xff;
			else {
				int n = syslog_prion(prit);
				if (n < 0 || n >= (int) (sizeof(prioset) * 8))
          return -1;
				if (eq)
					prioset |= (1 << n);
				else
					prioset |= ((1 << (n + 1)) - 1);
			}
			if (not) {
				for (int i = 0; i < LOG_NFACILITIES; i++) 
					if (facset & (1 << i))
						set->set[i] &= ~prioset;
			} else {
				for (int i = 0; i < LOG_NFACILITIES; i++) 
					if (facset & (1 << i))
						set->set[i] |= prioset;
			}
		}
	}
	return 0;
}

#ifdef LOGSET_TEST_MAIN

int main(int argc, char *argv[]) {
	struct logset out = {.set = {0}};

	int rv = logstr2set(argv[1], &out);

	printf("%-8s EACewnid\n", "");
	for (int i = 0; i < LOG_NFACILITIES; i++) {
		printf("%-8s ", syslog_facname(i));
		for (int j = 0; j < 8; j++) {
			printf("%c", logsetok(&out, LOG_MAKEPRI(i<<3, j)) ? 'v' : '.');
		}
		printf("\n");
	}
}
#endif
