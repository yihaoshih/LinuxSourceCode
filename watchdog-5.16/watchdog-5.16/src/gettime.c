#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include "gettime.h"

/*
 * Return current MONOTONIC time.
 * (like time(NULL), but monotonic)
 */
time_t gettime(void)
{
	struct timespec now = {};
	int rc = clock_gettime(CLOCK_MONOTONIC, &now);
	if (rc < 0) {
		return -1;
	}
	return now.tv_sec;
}
