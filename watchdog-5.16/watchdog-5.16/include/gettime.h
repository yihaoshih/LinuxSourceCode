#ifndef _GETTIME_H_
#define _GETTIME_H_

#include <time.h>

time_t gettime(void);

static const long NSEC = 1000000000L; /* nanoseconds per second. */

/*
 * Alternatives to the BSD macros for Linux to manipulate 'struct timespec'.
 *
 * Note these *assume* the structures are normalised - that is the nanosecond
 * part is 0...999,999,999 otherwise the checks on the result of add/subtract
 * are insufficient to guarantee the result in normalised.
 */

#ifndef timespecadd
static inline void timespecadd(const struct timespec *a, const struct timespec *b, struct timespec *res)
{
	res->tv_sec = a->tv_sec + b->tv_sec;
	res->tv_nsec = a->tv_nsec + b->tv_nsec;
	if (res->tv_nsec >= NSEC) {
		res->tv_nsec -= NSEC;
		res->tv_sec ++;
	}
}
#endif /* timespecadd */

#ifndef timespecsub
static inline void timespecsub(const struct timespec *a, const struct timespec *b, struct timespec *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (res->tv_nsec < 0) {
		res->tv_nsec += NSEC;
		res->tv_sec --;
	}
}
#endif /* timespecsub */

/*
 * Return negative, zero, positive for a<b, a=b, a>b cases.
 * Used for a robust working version of timespeccmp() macro
 * in gettime.h
 *
 * NOTE: This assumes a & b are normalised!
 */

static inline int ts_cmp(const struct timespec *a, const struct timespec *b)
{
	if(a->tv_sec > b->tv_sec) {
		return 1;
	} else if(a->tv_sec < b->tv_sec) {
		return -1;
	}

	/* Whole seconds identical, compare fractional part. */
	if(a->tv_nsec > b->tv_nsec) {
		return 1;
	} else if(a->tv_nsec < b->tv_nsec) {
		return -1;
	}

	/* Get here if identical. */
return 0;
}

/*
 * The timespeccmp() macro compares a to b using the comparison operator given
 * in CMP (one of <, <=, ==, !=, >=, or >). The result of the comparison
 * is returned based on the function ts_cmp().
 *
 * This allows the equivalent of "if(a >= b)" to be coded as "if(timespeccmp(a, b, >=))"
 * for these structures.
 */

#ifndef timespeccmp
#define timespeccmp(a, b, CMP) (ts_cmp((a), (b)) CMP 0)
#endif /* timespeccmp */

#endif /* _GETTIME_H_ */
