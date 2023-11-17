/* > memory.c
 *
 * Code for periodically checking the 'free' memory in the system. Added in the
 * functions open_memcheck() and close_memcheck() based on stuff from old watchdog.c
 * and shutdown.c to make it more self-contained.
 *
 * TO DO:
 * Should we have separate configuration for checking swap use?
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mman.h>
#ifdef __linux__
#include <linux/param.h>
#endif

#include "extern.h"
#include "watch_err.h"

#define FREEMEM		"MemFree:"
#define FREESWAP	"SwapFree:"
#define TOTALSWAP	"SwapTotal:"
#define USED_BUFFER	"Buffers:"
#define USED_CACHE	"Cached:"

static int mem_fd = -1;
static const char mem_name[] = "/proc/meminfo";

/*
 * Read values such as:
 *
 * "MemFree:        27337188 kB"
 *
 * From the the file to retrun 27337188 in this case.
 * Return is 0 for failure to parse.
 */

static long read_svalue(const char *buf, const char *var)
{
	long res = 0;
	char *ptr = NULL;

	if (buf != NULL && var != NULL) {
		ptr = strstr(buf, var);
	}

	if (ptr != NULL) {
		res = atol(ptr + strlen(var));
	} else if (verbose > 1) {
		/*
		 * Report error in parsing, but this could be due to older
		 * kernel so don't make it an error or too verbose.
		 */
		log_message(LOG_DEBUG, "Failed to parse %s for %s", mem_name, var);
	}

	return res;
}

static long kb_per_page(int pages)
{
	return pages * (long)(EXEC_PAGESIZE / 1024);
}

/*
 * Open the memory information file if such as test is configured.
 */

int open_memcheck(void)
{
	int rv = -1;

	close_memcheck();

	if (minpages > 0 || maxswap > 0) {
		/* open the memory info file */
		mem_fd = open(mem_name, O_RDONLY);
		if (mem_fd == -1) {
			int err = errno;
			log_message(LOG_ERR, "cannot open %s (errno = %d = '%s')", mem_name, err, strerror(err));
		} else {
			rv = 0;
		}
	}

	return rv;
}

/*
 * Read and check the contents of the memory information file.
 */

int check_memory(void)
{
	char buf[2048];
	long free, freemem, freeswap, used_buffer, used_cache, totalswap, used;
	int n;
	int ret = ENOERR;

	/* is the memory file open? */
	if (mem_fd == -1)
		return (ENOERR);

	/* position pointer at start of file */
	if (lseek(mem_fd, 0, SEEK_SET) < 0) {
		int err = errno;
		log_message(LOG_ERR, "lseek %s gave errno = %d = '%s'", mem_name, err, strerror(err));
		return (err);
	}

	/* read the file */
	if ((n = read(mem_fd, buf, sizeof(buf)-1)) < 0) {
		int err = errno;
		log_message(LOG_ERR, "read %s gave errno = %d = '%s'", mem_name, err, strerror(err));
		return (err);
	}
	/* Force string to be nul-terminated. */
	buf[n] = 0;

	/* we only care about integer values */
	freemem  = read_svalue(buf, FREEMEM);
	freeswap = read_svalue(buf, FREESWAP);
	totalswap = read_svalue(buf, TOTALSWAP);
	used_buffer = read_svalue(buf, USED_BUFFER);
	used_cache  = read_svalue(buf, USED_CACHE);

	/*
	 * Compute "free memnory" from what is reported as free, the buffers and
	 * cache use. When pressed, the kernel will free up buffers & cache for
	 * other use, but as a result if this measure of "free" gets below a few
	 * tens of MB then the machine is going to be pretty sick.
	 */
	free = freemem + used_buffer + used_cache;
	used = totalswap - freeswap;

	if (verbose && logtick && ticker == 1) {
		log_message(LOG_DEBUG, "currently there are %ld kB usable memory and %ld of %ld swap used", free, used, freeswap);
	}

	if (minpages && (free < kb_per_page(minpages))) {
		log_message(LOG_ERR, "memory available %ld kB is less than %d pages", free, minpages);
		ret = ENOMEM;
	}

	if (maxswap && (used > kb_per_page(maxswap))) {
		log_message(LOG_ERR, "swap used %ld kB is more than %d pages", used, maxswap);
		ret = ENOMEM;
	}

	return ret;
}

/*
 * Close the special memory data file (if open).
 */

int close_memcheck(void)
{
	int rv = 0;

	if (mem_fd != -1 && close(mem_fd) == -1) {
		log_message(LOG_ALERT, "cannot close %s (errno = %d)", mem_name, errno);
		rv = -1;
	}

	mem_fd = -1;
	return rv;
}

int check_allocatable(void)
{
	char *mem;
	size_t len = EXEC_PAGESIZE * (size_t)minalloc;

	if (minalloc <= 0)
		return 0;

	/*
	 * Map and fault in the pages
	 */
	mem = mmap(NULL, len, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, 0, 0);
	if (mem == MAP_FAILED) {
		int err = errno;
		log_message(LOG_ALERT, "cannot allocate %lu bytes (errno = %d = '%s')",
			    (unsigned long)len, err, strerror(err));
		return err;
	}

	munmap(mem, len);
	return 0;
}
