sbin_PROGRAMS = watchdog wd_keepalive wd_identify

watchdog_SOURCES = file_stat.c file_table.c iface.c gettime.c keep_alive.c \
			load.c memory.c net.c \
			pidfile.c shutdown.c \
			temp.c test_binary.c watchdog.c \
			logmessage.c xmalloc.c heartbeat.c lock_mem.c daemon-pid.c configfile.c \
			errorcodes.c read-conf.c sigterm.c reopenstd.c killall5.c send-email.c \
			run-as-child.c

# for glibc before 2.17 due to clock_gettime()
watchdog_LDADD = -lrt

wd_keepalive_SOURCES = wd_keepalive.c logmessage.c lock_mem.c daemon-pid.c xmalloc.c \
			configfile.c keep_alive.c read-conf.c sigterm.c

wd_keepalive_LDADD = -lrt

wd_identify_SOURCES = wd_identify.c logmessage.c xmalloc.c configfile.c read-conf.c

wd_identify_LDADD = -lrt

AM_CPPFLAGS = -I@top_srcdir@/include

distclean-depend:
	rm -rf .deps
