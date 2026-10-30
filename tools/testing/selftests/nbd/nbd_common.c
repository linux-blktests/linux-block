// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 KylinSoft Co., Ltd. All rights reserved.
 *
 * Exercise the nbd_start_device() config_lock window introduced by
 * 8b428f42f3ed ("nbd: fix lockdep deadlock warning"). Prime the hardware
 * queue count before each race so the update cannot take its no-op path.
 * A passing stress run means that no regression was observed in that run;
 * scheduling alone cannot guarantee that both callers entered the window.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/nbd.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest.h"
#include "nbd_common.h"

#define MAX_DEVICES	32

static int devices[MAX_DEVICES];
static int nr_devices;

long long nbd_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int read_timeout(int fd, void *buf, size_t len, int timeout)
{
	long long end = nbd_now_ms() + timeout;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	size_t done = 0;

	while (done < len) {
		long long left = end - nbd_now_ms();
		ssize_t n;
		int ret;

		ret = poll(&pfd, 1, left > 0 ? left : 0);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return ret ? -errno : -ETIMEDOUT;
		n = read(fd, (char *)buf + done, len - done);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return n ? -errno : -EPIPE;
		done += n;
	}
	return 0;
}

static void close_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
	*fd = -1;
}

/* An absent pid attribute denotes an unstarted device, not a read error. */
int nbd_device_pid(int index)
{
	char path[64], buf[32], *end;
	long pid;
	int fd, error;
	ssize_t n;

	snprintf(path, sizeof(path), "/sys/block/nbd%d/pid", index);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? 0 : -errno;
	do {
		n = read(fd, buf, sizeof(buf) - 1);
	} while (n < 0 && errno == EINTR);
	error = errno;
	close(fd);
	if (n <= 0) {
		/* Only a removed attribute confirms that the device has stopped. */
		if (access(path, F_OK) < 0 && errno == ENOENT)
			return 0;
		return n < 0 ? -error : -EIO;
	}
	buf[n] = '\0';
	errno = 0;
	pid = strtol(buf, &end, 10);
	if (errno || end == buf || (*end && *end != '\n') ||
	    pid <= 0 || pid > INT_MAX)
		return -EPROTO;
	return pid;
}

static int open_unused(int index)
{
	char path[64];
	int fd, pid;

	snprintf(path, sizeof(path), "/dev/nbd%d", index);
	fd = open(path, O_RDWR | O_EXCL | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	pid = nbd_device_pid(index);
	if (pid) {
		close(fd);
		return pid < 0 ? pid : -EBUSY;
	}
	return fd;
}

static int find_device(void)
{
	struct dirent *entry;
	DIR *dir;

	nr_devices = 0;
	dir = opendir("/sys/block");
	if (!dir)
		return -1;
	while ((entry = readdir(dir))) {
		char tail;
		int candidate, fd;

		if (sscanf(entry->d_name, "nbd%d%c", &candidate, &tail) != 1)
			continue;
		fd = open_unused(candidate);
		if (fd < 0)
			continue;
		close(fd);
		devices[nr_devices] = candidate;
		if (++nr_devices >= MAX_DEVICES)
			break;
	}
	closedir(dir);
	return nr_devices ? devices[0] : -1;
}

int nbd_session_open(struct session *s, int index, int connections,
		     unsigned long flags)
{
	int i;

	memset(s, 0, sizeof(*s));
	s->index = index;
	s->fd = -1;
	for (i = 0; i < 2; i++) {
		s->sockets[i][0] = -1;
		s->sockets[i][1] = -1;
		s->go[i] = -1;
		s->ready[i] = -1;
		s->result[i] = -1;
	}
	s->fd = open_unused(index);
	if (s->fd < 0) {
		ksft_print_msg("nbd%d: exclusive open: %s\n", index,
			       strerror(-s->fd));
		return s->fd;
	}
	for (i = 0; i < 2; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
			       s->sockets[i]))
			return -errno;
		if (i >= connections)
			continue;
		if (ioctl(s->fd, NBD_SET_SOCK, s->sockets[i][0])) {
			int error = errno;

			ksft_print_msg("nbd%d: set socket %d: %s\n", index, i,
				       strerror(error));
			return -error;
		}
		/* Never clear another setup task's sockets after -EBUSY. */
		s->owns_config = true;
	}
	if (ioctl(s->fd, NBD_SET_FLAGS, flags))
		return -errno;
	return 0;
}

int nbd_pick_device(int round)
{
	return devices[round % nr_devices];
}

int nbd_get_result(struct session *s, int timeout)
{
	struct result *r;
	int ret;

	if (s->nr_results >= s->nr_children)
		return -EINVAL;
	r = &s->results[s->nr_results];
	ret = read_timeout(s->result[0], r, sizeof(*r), timeout);
	if (!ret)
		s->nr_results++;
	return ret;
}

int nbd_launch(struct session *s, int children, struct options *o)
{
	char ready[2], go[2] = { 'g', 'g' };
	int i, ret;

	if (pipe2(s->go, O_CLOEXEC) || pipe2(s->ready, O_CLOEXEC) ||
	    pipe2(s->result, O_CLOEXEC))
		return -errno;
	for (i = 0; i < children; i++) {
		unsigned int spread = i ? o->spread_b : o->spread_a;
		unsigned int delay = spread ? rand_r(&o->seed) % spread : 0;
		pid_t child = fork();

		if (child < 0)
			return -errno;
		if (!child) {
			struct result r = { .pid = getpid() };
			char token;

			close(s->go[1]);
			close(s->ready[0]);
			close(s->result[0]);
			if (write(s->ready[1], "r", 1) != 1 ||
			    read(s->go[0], &token, 1) != 1)
				_exit(1);
			if (delay)
				usleep(delay);
			/* Use the inherited exclusive fd; DO_IT has no owner check. */
			if (ioctl(s->fd, NBD_DO_IT, 0))
				r.error = errno;
			if (write(s->result[1], &r, sizeof(r)) != sizeof(r))
				_exit(1);
			_exit(0);
		}
		s->children[s->nr_children++] = child;
	}
	close_fd(&s->go[0]);
	close_fd(&s->ready[1]);
	close_fd(&s->result[1]);
	ret = read_timeout(s->ready[0], ready, children, IO_TIMEOUT_MS);
	if (ret)
		return ret;
	if (write(s->go[1], go, children) != children)
		return -EIO;
	return 0;
}

static int reap_child(pid_t pid)
{
	long long end = nbd_now_ms() + IO_TIMEOUT_MS;
	int status;

	for (;;) {
		pid_t ret = waitpid(pid, &status, WNOHANG);

		if (ret == pid)
			return WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : -ECHILD;
		if (ret < 0 && errno != EINTR)
			return -errno;
		if (nbd_now_ms() >= end)
			break;
		usleep(1000);
	}
	kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return -ETIMEDOUT;
}

int nbd_session_close(struct session *s)
{
	int i, ret = 0;

	close_fd(&s->go[1]);
	close_fd(&s->ready[1]);
	close_fd(&s->result[1]);
	if (s->owns_config && ioctl(s->fd, NBD_CLEAR_SOCK, 0))
		ret = -errno;
	for (i = 0; i < 2; i++) {
		if (s->sockets[i][1] >= 0)
			shutdown(s->sockets[i][1], SHUT_RDWR);
	}
	for (i = 0; i < s->nr_children; i++) {
		int err = reap_child(s->children[i]);

		if (err && !ret)
			ret = err;
	}
	while (s->nr_results < s->nr_children) {
		int err = nbd_get_result(s, IO_TIMEOUT_MS);

		if (err) {
			if (!ret)
				ret = err;
			break;
		}
	}
	for (i = 0; i < 2; i++) {
		close_fd(&s->sockets[i][0]);
		close_fd(&s->sockets[i][1]);
		close_fd(&s->go[i]);
		close_fd(&s->ready[i]);
		close_fd(&s->result[i]);
	}
	close_fd(&s->fd);
	/* Last file release can be deferred; do not reuse its configuration. */
	if (s->owns_config) {
		long long end = nbd_now_ms() + IO_TIMEOUT_MS;
		int pid;

		while ((pid = nbd_device_pid(s->index)) > 0 && nbd_now_ms() < end)
			usleep(1000);
		if (pid && !ret)
			ret = pid < 0 ? pid : -ETIMEDOUT;
	}
	return ret;
}

/* Return 0 for an ioctl result and 1 once startup has published its PID. */
int nbd_wait_state(struct session *s)
{
	long long end = nbd_now_ms() + IO_TIMEOUT_MS;

	while (nbd_now_ms() < end) {
		int ret = nbd_get_result(s, 0);

		if (!ret)
			return 0;
		if (ret != -ETIMEDOUT)
			return ret;
		ret = nbd_device_pid(s->index);
		if (ret < 0)
			return ret;
		if (ret)
			return 1;
		usleep(1000);
	}
	return -ETIMEDOUT;
}

int nbd_prime(int index, int connections, struct options *o)
{
	struct session s;
	int ret, cleanup;

	ret = nbd_session_open(&s, index, connections,
			       connections > 1 ? NBD_FLAG_CAN_MULTI_CONN : 0);
	if (!ret)
		ret = nbd_launch(&s, 1, o);
	if (!ret)
		ret = nbd_wait_state(&s) == 1 ? 0 : -EIO;
	cleanup = nbd_session_close(&s);
	if (!ret)
		ret = cleanup;
	if (!ret && (s.nr_results != 1 || s.results[0].error))
		ret = -EIO;
	return ret;
}

static unsigned int parse_number(const char *arg, unsigned int limit)
{
	char *end;
	unsigned long value;

	errno = 0;
	value = strtoul(arg, &end, 0);
	if (errno || end == arg || *end || value > limit)
		ksft_exit_fail_msg("invalid numeric option: %s\n", arg);
	return value;
}

static void usage(const char *prog)
{
	printf("Usage: %s [options]\n", prog);
	printf("  -r, --rounds N     Race attempts (1..10000, default 20)\n");
	printf("  -a, --spread-a US  First operation delay (0..100000, default 0)\n");
	printf("  -b, --spread-b US  Second operation delay (0..100000, default 1000)\n");
	printf("  -s, --seed N       Random seed (default: time and PID)\n");
	printf("  -h, --help         Show this help\n");
	printf("NBD_START_RACE_ROUNDS overrides --rounds.\n");
	printf("Load nbd with nbds_max=4 max_part=0 before running.\n");
}

void nbd_parse_options(int argc, char **argv, struct options *o)
{
	const struct option options[] = {
		{ "rounds", required_argument, NULL, 'r' },
		{ "spread-a", required_argument, NULL, 'a' },
		{ "spread-b", required_argument, NULL, 'b' },
		{ "seed", required_argument, NULL, 's' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	const char *env;
	int option;

	*o = (struct options) { .rounds = 20, .spread_b = 1000 };
	while ((option = getopt_long(argc, argv, "r:a:b:s:h", options, NULL)) != -1) {
		switch (option) {
		case 'r':
			o->rounds = parse_number(optarg, 10000);
			break;
		case 'a':
			o->spread_a = parse_number(optarg, 100000);
			break;
		case 'b':
			o->spread_b = parse_number(optarg, 100000);
			break;
		case 's':
			o->seed = parse_number(optarg, UINT_MAX);
			break;
		case 'h':
			usage(argv[0]);
			exit(KSFT_PASS);
		default:
			usage(argv[0]);
			ksft_exit_fail_msg("invalid option\n");
		}
	}
	env = getenv("NBD_START_RACE_ROUNDS");
	if (env)
		o->rounds = parse_number(env, 10000);
	if (optind != argc || o->rounds < 1)
		ksft_exit_fail_msg("use --rounds 1..10000\n");
}

int nbd_init_test(struct options *o)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
	};
	struct __user_cap_data_struct caps[2];
	int index;

	if (syscall(SYS_capget, &header, caps) ||
	    !(caps[CAP_SYS_ADMIN / 32].effective & (1U << (CAP_SYS_ADMIN % 32))))
		ksft_exit_skip("CAP_SYS_ADMIN is required\n");
	if (sysconf(_SC_NPROCESSORS_ONLN) < 2)
		ksft_exit_skip("at least two CPUs are needed to change the queue count\n");
	index = find_device();
	if (index < 0)
		ksft_exit_skip("no unused NBD device; load nbd with nbds_max=4 max_part=0\n");
	if (!o->seed)
		o->seed = (unsigned int)time(NULL) ^ getpid();
	ksft_print_msg("nbd%d: rounds=%d seed=%u; scheduling stress, no instrumentation\n",
		       index, o->rounds, o->seed);
	signal(SIGPIPE, SIG_IGN);
	return index;
}
