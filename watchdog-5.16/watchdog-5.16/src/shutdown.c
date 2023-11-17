#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _XOPEN_SOURCE 500	/* for getsid(2) */
#define _BSD_SOURCE		/* for acct(2) */
#define _DEFAULT_SOURCE	/* To stop complaints with gcc >= 2.19 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <netdb.h>
#include <paths.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <utmp.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h> /* For MNT_FORCE  */
#include <sys/swap.h> /* for swapoff() */
#include <unistd.h>
#include <time.h>

#include "watch_err.h"
#include "extern.h"
#include "ext2_mnt.h"

#if defined __GLIBC__
#include <sys/quota.h>
#include <sys/swap.h>
#include <sys/reboot.h>
#else				/* __GLIBC__ */
#include <linux/quota.h>
#endif				/* __GLIBC__ */

#include <unistd.h>

#ifndef NSIG
#define NSIG _NSIG
#endif

#ifndef __GLIBC__
#ifndef RB_AUTOBOOT
#define RB_AUTOBOOT	0xfee1dead,672274793,0x01234567 /* Perform a hard reset now.  */
#define RB_ENABLE_CAD	0xfee1dead,672274793,0x89abcdef /* Enable reboot using Ctrl-Alt-Delete keystroke.  */
#define RB_HALT_SYSTEM	0xfee1dead,672274793,0xcdef0123 /* Halt the system.  */
#define RB_POWER_OFF	0xfee1dead,672274793,0x4321fedc /* Stop system and switch power off if possible.  */
#endif /*RB_AUTOBOOT*/
#endif /* !__GLIBC__ */

/*
 * Close all the device except for the watchdog.
 */

static void close_all_but_watchdog(void)
{
	close_loadcheck();
	close_memcheck();
	close_tempcheck();
	close_heartbeat();
	close_netcheck(target_list);

	free_process();		/* What check_bin() was waiting to report. */
	free_all_lists();	/* Memory used by read_config() */
}

/* on exit we close the device and log that we stop */
void terminate(int ecode)
{
	log_message(LOG_NOTICE, "stopping daemon (%d.%d)", MAJOR_VERSION, MINOR_VERSION);
	unlock_our_memory();
	close_all_but_watchdog();
	close_watchdog();
	remove_pid_file();
	close_logging();
	xusleep(100000);		/* 0.1s to make sure log is written */
	exit(ecode);
}

/* panic: we're still alive but shouldn't */
static void panic(void)
{
	/*
	 * Okay we should never reach this point,
	 * but if we do we will cause the hard reset
	 */
	open_logging(NULL, MSG_TO_STDERR | MSG_TO_SYSLOG);
	log_message(LOG_ALERT, "WATCHDOG PANIC: failed to reboot, trying hard-reset");
	sleep(dev_timeout * 4);

	/* if we are still alive, we just exit */
	log_message(LOG_ALERT, "WATCHDOG PANIC: still alive after sleeping %d seconds", 4 * dev_timeout);
	close_all_but_watchdog();
	close_logging();
	exit(1);
}

/*
 * Test for virtual file systems that we need not unmount.
 */
static int ignore_fs(const struct mntent *mnt)
{
	int ii;

	const char *temp[] = {
		"devfs", "proc", "sysfs", "ramfs",
		"tmpfs", "devpts", "devtmpfs", "tracefs",
		"squashfs"
	};
	const int num_temp = ARRAY_SIZE(temp);

	const char *ignore[] = {
		"/run/", "/sys/", "/proc/", "/dev/"
	};
	const int num_ignore = ARRAY_SIZE(ignore);

	/*
	 * Check for known temporary file systems
	 */
	for(ii = 0; ii < num_temp; ii++) {
		const char *str = temp[ii];
		if(!strcmp(mnt->mnt_type, str)) {
			return -1;
		}
	}

	/*
	 * Check for known virtual file systems, these
	 * often also feature sub-directories hence the
	 * length-limited test for a path start.
	 */
	for(ii = 0; ii < num_ignore; ii++) {
		const char *str = ignore[ii];
		if(!strncmp(mnt->mnt_dir, str, strlen(str))) {
			return -1;
		}
	}

return 0;
}

/*
 * Unmount file ourselves, this code adapted from util-linux-2.17.2/login-utils/shutdown.c
 * However, they also try running the 'umount' binary first, as it might be smarter.
 */

#define NUM_MNTLIST 128

static void mnt_off(void)
{
	FILE *fp;
	struct mntent *mnt;
	char *mntlist[NUM_MNTLIST];
	const char *fname = _PATH_MOUNTED;
	int n = 0;
	int i;

	keep_alive();
	/* Could this hang the system? Hardware watchdog will kick in, but might be
	 * better to try fork() and idle for a while before forcing unmounts?
	 */
	sync();
	keep_alive();

	if (!(fp = setmntent(fname, "r"))) {
		log_message(LOG_ERR, "could not open %s (%s)", fname, strerror(errno));
		return;
	}

	/* in some rare cases fp might be NULL so be careful */
	while (n < NUM_MNTLIST && (mnt = getmntent(fp)) != NULL) {
		/* First check if swap */
		if (!strcmp(mnt->mnt_type, MNTTYPE_SWAP)) {
			if (swapoff(mnt->mnt_fsname) < 0)
				log_message(LOG_ERR, "could not swap-off %s (%s)", mnt->mnt_fsname, strerror(errno));
		} else {
			/* quota only if mounted at boot time && filesytem=ext2 */
			if (!hasmntopt(mnt, MNTOPT_NOAUTO) && !strcmp(mnt->mnt_type, MNTTYPE_EXT2)) {
				/* group quota? */
				if (hasmntopt(mnt, MNTOPT_GRPQUOTA)) {
					if (quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), mnt->mnt_fsname, 0, (caddr_t) 0) < 0) {
						log_message(LOG_ERR, "could not stop group quota %s (%s)", mnt->mnt_fsname, strerror(errno));
					}
				}

				/* user quota */
				if (hasmntopt(mnt, MNTOPT_USRQUOTA)) {
					if (quotactl(QCMD(Q_QUOTAOFF, USRQUOTA), mnt->mnt_fsname, 0, (caddr_t) 0) < 0) {
						log_message(LOG_ERR, "could not stop user quota %s (%s)", mnt->mnt_fsname, strerror(errno));
					}
				}
			}

			/*
			 * Neil Phillips: trying to unmount temporary / kernel
			 * filesystems is pointless and may cause error messages;
			 * /dev can be a ramfs managed by udev.
			 */
			if (ignore_fs(mnt)) {
				log_message(LOG_DEBUG, "skip %s %s type %s", mnt->mnt_fsname, mnt->mnt_dir, mnt->mnt_type);
			} else {
				log_message(LOG_DEBUG, "listing %s %s type %s", mnt->mnt_fsname, mnt->mnt_dir, mnt->mnt_type);
				mntlist[n++] = strdup(mnt->mnt_dir);
			}
		}
	}

	/* Close our file pointer. */
	endmntent(fp);

	/*
	 * We are careful to do this in reverse order of the mtab file.
	 *
	 * NOTE: We do not update the mount point list, so this is really
	 * only good for a final shutdown!
	 *
	 */
	for (i = n - 1; i >= 0; i--) {
		char *filesys = mntlist[i];

		/* Treat root file system as unmountable - make readonly instead. */
		if(!strcmp(filesys, "/")) {
			log_message(LOG_DEBUG, "remounting read-only %s", filesys);
			keep_alive();

			if(mount(filesys, filesys, "", MS_REMOUNT | MS_RDONLY, "") < 0) {
				log_message(LOG_ERR, "could not remount %s (%s)", filesys, strerror(errno));
			}
		} else {
			log_message(LOG_DEBUG, "unmounting %s", filesys);
			keep_alive();

#if defined( MNT_FORCE )
			if (umount2(filesys, MNT_FORCE) < 0) {
#else
			if (umount(filesys) < 0) {
#endif /*!MNT_FORCE*/
				log_message(LOG_ERR, "could not unmount %s (%s)", filesys, strerror(errno));
			}
		}
	}
}

/*
 * Kill everything, but depending on 'aflag' spare kernel/privileged
 * processes. Do this twice in case we have out-of-memory problems.
 *
 * The value of 'stime' is the delay from 2nd SIGTERM to SIGKILL but
 * the SIGKILL is only used when 'aflag' is true as things really bad then!
 */

static void kill_everything_else(int aflag, int stime)
{
	int ii;

	/* Ignore all signals (except children, so run_func_as_child() works as expected). */
	for (ii = 1; ii < NSIG; ii++) {
		if (ii != SIGCHLD) {
			signal(ii, SIG_IGN);
		}
	}

	/* Stop init; it is insensitive to the signals sent by the kernel. */
	kill(1, SIGTSTP);

	/* Try to terminate processes the 'nice' way. */
	killall5(SIGTERM, aflag);
	safe_sleep(1);
	/* Do this twice in case we have out-of-memory problems. */
	killall5(SIGTERM, aflag);

	/* Now wait for most processes to exit as intended. */
	safe_sleep(stime);

	if (aflag) {
		/* In case that fails, send them the non-ignorable kill signal. */
		killall5(SIGKILL, aflag);
		keep_alive();
		/* Out-of-memory safeguard again. */
		killall5(SIGKILL, aflag);
		keep_alive();
	}
}

/*
 * Record the system shut-down.
 */

static void write_wtmp(void)
{
	time_t t;
	struct utmp wtmp;
	const char *fname = _PATH_WTMP;
	int fd;

	if ((fd = open(fname, O_WRONLY | O_APPEND)) >= 0) {
		memset(&wtmp, 0, sizeof(wtmp));
		time(&t);
		strcpy(wtmp.ut_user, "shutdown");
		strcpy(wtmp.ut_line, "~");
		strcpy(wtmp.ut_id, "~~");
		wtmp.ut_pid = 0;
		wtmp.ut_type = RUN_LVL;
		wtmp.ut_time = t;
		if (write(fd, (char *)&wtmp, sizeof(wtmp)) < 0)
			log_message(LOG_ERR, "failed writing wtmp (%s)", strerror(errno));
		close(fd);
	}
}

/*
 * Save the random seed if a save location exists.
 * Don't worry about error messages, we react here anyway
 */

static void save_urandom(void)
{
	const char *seedbck = RANDOM_SEED;
	int fd_seed, fd_bck;
	char buf[512];

	if (strlen(seedbck) != 0) {
		if ((fd_seed = open("/dev/urandom", O_RDONLY)) >= 0) {
			if ((fd_bck = creat(seedbck, S_IRUSR | S_IWUSR)) >= 0) {
				if (read(fd_seed, buf, sizeof(buf)) == sizeof(buf)) {
					if (write(fd_bck, buf, sizeof(buf)) < 0) {
						log_message(LOG_ERR, "failed writing urandom (%s)", strerror(errno));
					}
				}
				close(fd_bck);
			}
			close(fd_seed);
		}
	}
}

/* part that tries to shut down the system cleanly */
static void try_clean_shutdown(int errorcode)
{
	/* soft-boot the system */
	/* do not close open files here, they will be closed later anyway */

	/* if we will halt the system we should try to tell a sysadmin */
	if (admin != NULL) {
		run_func_as_child(60, send_email, errorcode, NULL);
	}

	open_logging(NULL, MSG_TO_STDERR); /* Without 'MSG_TO_SYSLOG' this closes syslog. */
	safe_sleep(1);		/* make sure log is written (send_email now has its own wait). */

	/* We cannot start shutdown, since init might not be able to fork. */
	/* That would stop the reboot process. So we try rebooting the system */
	/* ourselves. Note, that it is very likely we cannot start any rc */
	/* script either, so we do it all here. */

	/* Close all files except the watchdog device. */
	close_all_but_watchdog();

	kill_everything_else(TRUE, sigterm_delay-1);

	/* Remove our PID file, as nothing should be capable of starting a 2nd daemon now. */
	remove_pid_file();

	/* Record the fact that we're going down */
	write_wtmp();

	/* save the random seed if a save location exists */
	save_urandom();

	/* Turn off accounting */
	if (acct(NULL) < 0)
		log_message(LOG_ERR, "failed stopping acct() (%s)", strerror(errno));

	keep_alive();

	/* Turn off quota and swap */
	mnt_off();

}

/* shut down the system */
void do_shutdown(int errorcode)
{
	/* tell syslog what's happening */
	log_message(LOG_ALERT, "shutting down the system because of error %d = '%s'", errorcode, wd_strerror(errorcode));

	if(errorcode != ERESET)	{
		try_clean_shutdown(errorcode);
	} else {
		/* We have been asked to hard-reset, make basic attempt at clean filesystem
		 * but don't try stopping anything, etc, then used device (below) to do reset
		 * action.
		 */
		sync();
		sleep(1);
	}

	/* finally reboot */
	if (errorcode != ETOOHOT) {
		if (get_watchdog_fd() != -1) {
			/* We have a hardware timer, try using that for a quick reboot first. */
			set_watchdog_timeout(1);
			sleep(dev_timeout * 4);
		}
		/* That failed, or was not possible, ask kernel to do it for us. */
		reboot(RB_AUTOBOOT);
	} else {
		if (temp_poweroff) {
			/* Tell system to power off if possible. */
			reboot(RB_POWER_OFF);
		} else {
			/* Turn on hard reboot, CTRL-ALT-DEL will reboot now. */
			reboot(RB_ENABLE_CAD);
			/* And perform the `halt' system call. */
			reboot(RB_HALT_SYSTEM);
		}
	}

	/* unbelievable: we're still alive */
	panic();
}
