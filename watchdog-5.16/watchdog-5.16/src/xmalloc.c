/* > xmalloc.c
 *
 * Versions of memory allocation that exit with error message if failure occurs.
 * Based on old sundries.c but with some minor improvements and the code
 * in it that was for mount.c/umount.c support removed.
 *
 * (c) 2013 Paul S. Crawford (psc@sat.dundee.ac.uk) licensed under GPL v2, based
 * on older code in sundries.c
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <time.h>

#include "xmalloc.h"
#include "logmessage.h"

void *xcalloc(size_t nmemb, size_t size)
{
	void *t;

	if (nmemb == 0 || size == 0)
		return NULL;

	t = calloc(nmemb, size);
	if (t == NULL)
		fatal_error(EX_SYSERR, "xcalloc failed for %lu x %lu bytes", (unsigned long)nmemb, (unsigned long)size);

	return t;
}

char *xstrdup(const char *s)
{
	char *t;

	if (s == NULL)
		return NULL;

	t = strdup(s);
	if (t == NULL)
		fatal_error(EX_SYSERR, "xstrdup failed for %lu byte string", (unsigned long)strlen(s));

	return t;
}

int xusleep(const long usec)
{
	const long US_PER_SEC = 1000000L;

	struct timespec req;
	struct timespec rem;
	ldiv_t d;

	/* Skip obvious error case. */
	if (usec < 0) {
		return EINVAL;
	}

	/* Convert microseconds in to seconds. */
	d = ldiv(usec, US_PER_SEC);
	req.tv_sec = d.quot;
	/* Convert remainder from microseconds to nanoseconds. */
	req.tv_nsec = d.rem * 1000L;
	/* Use more modern call safely for microsecond values > 1 second. */
	return nanosleep(&req, &rem);
}
