#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <dirent.h>
#include <assert.h>
#include <libgen.h>
#include <stdarg.h>
#include <quobyte.h>

#define QUOBYTE_MAX_FD  255
#define QUOBYTE_MAX_DIR  32

#ifdef DEBUG
#define LD_QUOBYTE_DPRINTF(fmt,args...) do { fprintf(stderr,"ld_quobyte: ");fprintf(stderr, (fmt), ##args); fprintf(stderr,"\n"); } while (0);
#else
#define LD_QUOBYTE_DPRINTF(fmt,args...)
#endif

#define LD_DLSYM(rsym,sym,name) do { if (!rsym) { rsym = dlsym(RTLD_NEXT, name); if (rsym == NULL) {fprintf(stderr, "Failed to dlsym(%s)", name); exit(10); } } } while (0)

struct quobyte_fd_list {
       int fd;
       struct quobyte_fh* fh;
       off_t offset;
       off_t size;
};

struct quobyte_dir_list {
       DIR *dirp;
};

static struct quobyte_fd_list quobyte_fd_list[QUOBYTE_MAX_FD];
static struct quobyte_dir_list quobyte_dir_list[QUOBYTE_MAX_DIR];

static int init_called = 0;
static char *qRegistry = NULL;
static int qRefCnt = 0;

static void qDecRef(void) {
	assert(qDecRef > 0 && qRegistry);
	if (!--qRefCnt) {
		int _errno = errno;
		quobyte_destroy_adapter();
		free(qRegistry);
		qRegistry = NULL;
		errno = _errno;
	}
}

static int is_quobyte_path(const char *path, char **filename, int follow_symlink) {
	char *registry, *tmp;
	int ret = 0;
	if (strncmp(path, "quobyte://", 10) && strncmp(path, "quobyte:\\\\", 10)) {
		return 0;
	}
	registry = strdup(path + 10);
	tmp = strchr(registry, '/');
	if (!tmp) goto out;
	*filename = strdup(tmp);
	*tmp = 0;
	if (!qRegistry) {
		LD_QUOBYTE_DPRINTF("connecting to registry %s", registry);
		if (quobyte_create_adapter(registry)) goto out;
		qRegistry = strdup(registry);
	}
	ret = 1;
	qRefCnt++;
	if (follow_symlink) {
		char link[PATH_MAX];
		int ret2 = quobyte_readlink(*filename, &link[0], PATH_MAX);
		if (!ret2) {
			if (link[0] == '/') {
				free(*filename);
				*filename = strdup(&link[0]);
			} else {
				char rellink[PATH_MAX];
				snprintf(&rellink[0], PATH_MAX, "%s/%s", dirname(*filename), &link[0]);
				free(*filename);
				*filename = strdup(&rellink[0]);
			}
		}
	}
out:
    free(registry);
    return ret;
}

static void ld_quobyte_init(void) {
	int i;
	if (init_called) return;
	for (i = 0; i < QUOBYTE_MAX_FD; i++) quobyte_fd_list[i].fd = -1;
	for (i = 0; i < QUOBYTE_MAX_DIR; i++) quobyte_dir_list[i].dirp = NULL;
	init_called = 1;
}

static struct quobyte_fd_list *is_quobyte_fd(int fd) {
	int i;
	for (i = 0; i < QUOBYTE_MAX_FD; i++) {
		if (quobyte_fd_list[i].fd == fd) return &quobyte_fd_list[i];
	}
	return NULL;
}

static int is_quobyte_dh(DIR *dirp) {
	int i;
	for (i = 0; i < QUOBYTE_MAX_DIR; i++) {
		if (quobyte_dir_list[i].dirp == dirp) return 1;
	}
	return 0;
}

DIR *(*real_opendir)(const char *name) = NULL;
DIR *opendir(const char *name) {
	char *filename;
	DIR* ret;
	ld_quobyte_init();
	LD_DLSYM(real_opendir, opendir, "opendir");
	LD_QUOBYTE_DPRINTF("opendir name=%s", name);
	if (is_quobyte_path(name, &filename, 0)) {
		int i;
		DIR *dh = (DIR*) quobyte_opendir(filename);
		free(filename);
		if (!dh) {
			qDecRef();
			LD_QUOBYTE_DPRINTF("opendir ret=%p", NULL);
			return NULL;
		}
		for (i = 0; i < QUOBYTE_MAX_DIR; i++) {
			if (!quobyte_dir_list[i].dirp) {
				quobyte_dir_list[i].dirp = dh;
				break;
			}
		}
		assert(i < QUOBYTE_MAX_DIR);
		LD_QUOBYTE_DPRINTF("opendir ret=%p", dh);
		return dh;
	}
	ret = real_opendir(name);
	LD_QUOBYTE_DPRINTF("opendir ret=%p", ret);
	return ret;
}

long (*real_telldir)(DIR *dirp) = NULL;
long telldir(DIR *dirp) {
	LD_DLSYM(real_telldir, telldir, "telldir");
	LD_QUOBYTE_DPRINTF("telldir dirp=%p", dirp);
	if (is_quobyte_dh(dirp)) return quobyte_telldir((struct quobyte_dh*) dirp);
	return real_telldir(dirp);
}

void (*real_seekdir)(DIR *dirp, long loc) = NULL;
void seekdir(DIR *dirp, long loc) {
	LD_DLSYM(real_seekdir, seekdir, "seekdir");
	LD_QUOBYTE_DPRINTF("seekdir dirp=%p loc=%ld", dirp, loc);
	if (is_quobyte_dh(dirp)) return quobyte_seekdir((struct quobyte_dh*) dirp, loc);
	real_seekdir(dirp, loc);
}

struct dirent *(*real_readdir)(DIR *dirp) = NULL;
struct dirent *readdir(DIR *dirp) {
	LD_DLSYM(real_readdir, readdir, "readdir");
	LD_QUOBYTE_DPRINTF("readdir dirp=%p", dirp);
	if (is_quobyte_dh(dirp)) return quobyte_readdir((struct quobyte_dh*) dirp);
	return real_readdir(dirp);
}

int (*real_closedir)(DIR *dirp) = NULL;
int closedir(DIR *dirp) {
	LD_DLSYM(real_closedir, closedir, "closedir");
	LD_QUOBYTE_DPRINTF("closedir dirp=%p", dirp);
	if (is_quobyte_dh(dirp)) {
		int i;
		int ret = quobyte_closedir((struct quobyte_dh*) dirp);
		for (i = 0; i < QUOBYTE_MAX_DIR; i++) {
			if (quobyte_dir_list[i].dirp == dirp) {
				quobyte_dir_list[i].dirp = NULL;
			}
		}
		qDecRef();
		return ret;
	}
	return real_closedir(dirp);
}

int (*real_xstat)(int ver, const char *path, struct stat *buf) = NULL;
int __xstat(int ver, const char *path, struct stat *buf) {
	LD_DLSYM(real_xstat, __xstat, "__xstat");
	LD_QUOBYTE_DPRINTF("__xstat ver=%d path=%s buf=%p", ver, path, buf);
	char *filename;
	if (is_quobyte_path(path, &filename, 1)) {
		int ret = quobyte_getattr(filename, buf);
		free(filename);
		qDecRef();
		return ret;
	}
	return real_xstat(ver, path, buf);
}

int (*real_fxstat)(int ver, int fd, struct stat *buf) = NULL;
int __fxstat(int ver, int fd, struct stat *buf) {
	LD_DLSYM(real_fxstat, __fxstat, "__fxstat");
	LD_QUOBYTE_DPRINTF("__fxstat ver=%d fd=%d buf=%p", ver, fd, buf);
	struct quobyte_fd_list *e = is_quobyte_fd(fd);
	if (e) {
		return quobyte_fstat(e->fh, buf);
	}
	return real_fxstat(ver, fd, buf);
}

int (*real_lxstat)(int ver, const char *path, struct stat *buf) = NULL;
int __lxstat(int ver, const char *path, struct stat *buf) {
	LD_DLSYM(real_lxstat, __lstat, "__lxstat");
	LD_QUOBYTE_DPRINTF("__lxstat ver=%d path=%s buf=%p", ver, path, buf);
	char *filename;
	if (is_quobyte_path(path, &filename, 0)) {
		int ret = quobyte_getattr(filename, buf);
		free(filename);
		qDecRef();
		return ret;
	}
	return real_lxstat(ver, path, buf);
}

ssize_t (*real_readlink)(const char *path, char *buf, size_t bufsiz) = NULL;
ssize_t readlink(const char *path, char *buf, size_t bufsiz) {
	char *filename;
	LD_DLSYM(real_readlink, readlink, "readlink");
	LD_QUOBYTE_DPRINTF("readlink path=%s buf=%p bufsiz=%d", path, buf, (int) bufsiz);
	if (is_quobyte_path(path, &filename, 0)) {
		int ret = quobyte_readlink(filename, buf, bufsiz);
		free(filename);
		qDecRef();
		return ret;
	}
	return real_readlink(path, buf, bufsiz);
}

ssize_t (*real_getxattr)(const char *path, const char *name, void *value, size_t size) = NULL;
ssize_t getxattr(const char *path, const char *name,
                 void *value, size_t size) {
    LD_DLSYM(real_getxattr, getxattr, "getxattr");
    LD_QUOBYTE_DPRINTF("getxattr called %s %s", path, name);
	char *filename;
	if (is_quobyte_path(path, &filename, 1)) {
		int ret = quobyte_getxattr(filename, name, value, size);
		free(filename);
		qDecRef();
		return ret;
	}
    return real_getxattr(path, name, value, size);
}

ssize_t (*real_lgetxattr)(const char *path, const char *name, void *value, size_t size) = NULL;
ssize_t lgetxattr(const char *path, const char *name,
                  void *value, size_t size) {
    LD_DLSYM(real_lgetxattr, lgetxattr, "lgetxattr");
    LD_QUOBYTE_DPRINTF("lgetxattr path=%s name=%s", path, name);
	char *filename;
	if (is_quobyte_path(path, &filename, 0)) {
		int ret = quobyte_getxattr(filename, name, value, size);
		free(filename);
		qDecRef();
		return ret;
	}
    return real_lgetxattr(path, name, value, size);
}

int (*real_open)(__const char *path, int flags, ...);
int open(const char *path, int flags, ...)
{
    LD_DLSYM(real_open, open, "open");
    char *filename;
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    LD_QUOBYTE_DPRINTF("open path=%s flags=%d mode=0%o", path, flags, mode);
    ld_quobyte_init();
    if (is_quobyte_path(path, &filename, 0)) {
		int i, fd;
		struct quobyte_fh* fh = quobyte_open(filename, flags, mode);
		free(filename);
		if (!fh) {
			qDecRef();
			return -1;
		}
		for (i = 0; i < QUOBYTE_MAX_FD; i++) {
			if (quobyte_fd_list[i].fd == -1) {
				fd = open("/dev/zero", O_RDONLY);
				assert(fd >= 0);
				LD_QUOBYTE_DPRINTF("assigning fake fd = %d for quobyte fh %p", fd, fh);
				quobyte_fd_list[i].fd = fd;
				quobyte_fd_list[i].fh = fh;
				quobyte_fd_list[i].offset = 0;
				struct stat statbuf;
				quobyte_fstat(fh, &statbuf);
				quobyte_fd_list[i].size = statbuf.st_size;
				break;
			}
		}
		assert(i < QUOBYTE_MAX_FD);
		return fd;
	}
	return real_open(path, flags, mode);
}

int (*real_dup2)(int oldfd, int newfd);
int dup2(int oldfd, int newfd)
{
	LD_DLSYM(real_dup2, dup2, "dup2");
	LD_QUOBYTE_DPRINTF("dup2 oldfd=%d newfd=%d", oldfd, newfd);
	struct quobyte_fd_list *e = is_quobyte_fd(oldfd);
	if (e) e->fd = newfd;
	return real_dup2(oldfd, newfd);
}

ssize_t (*real_read)(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {
	LD_DLSYM(real_read, read, "read");
	LD_QUOBYTE_DPRINTF("read fd=%d buf=%p count=%d", fd, buf, (int) count);
	struct quobyte_fd_list *e = is_quobyte_fd(fd);
	if (e) {
		int ret = quobyte_read(e->fh, buf, e->offset, count);
		if (ret > 0) e->offset += ret;
		return ret;
	}
	return real_read(fd, buf, count);
}

off_t (*real_lseek)(int fd, off_t offset, int whence);
off_t lseek(int fd, off_t offset, int whence) {
	LD_DLSYM(real_lseek, lseek, "lseek");
	LD_QUOBYTE_DPRINTF("lseek fd=%d offset=%lu whence=%d", fd, offset, whence);
	struct quobyte_fd_list *e = is_quobyte_fd(fd);
	if (e) {
		off_t new_offset;
		off_t size = e->size;
		switch (whence) {
			case SEEK_SET:
				new_offset = offset;
				break;
			case SEEK_CUR:
				new_offset = e->offset + offset;
				break;
			case SEEK_END:
				new_offset = size + offset;
				break;
			default:
				errno = EINVAL;
				return -1;
		}
		if (new_offset < 0 || new_offset > size) {
			errno = EINVAL;
			return -1;
		}
		e->offset = new_offset;
		return e->offset;
	}
	return real_lseek(fd, offset, whence);
}

ssize_t (*real_write)(int fd, const void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count)
{
	LD_DLSYM(real_write, write, "write");
	LD_QUOBYTE_DPRINTF("write fd=%d buf=%p count=%d", fd, buf, (int) count);
	struct quobyte_fd_list *e = is_quobyte_fd(fd);
	if (e) {
		int ret = quobyte_write(e->fh, buf, e->offset, count, 0);
		if (ret > 0) {
			e->offset += ret;
			if (e->offset > e->size) e->size = e->offset;
		}
		return ret;
	}
	return real_write(fd, buf, count);
}

int (*real_fsync)(int fd) = NULL;
int fsync(int fd) {
	LD_DLSYM(real_fsync, fsync, "fsync");
	LD_QUOBYTE_DPRINTF("fsync fd=%d", fd);
	struct quobyte_fd_list *e = is_quobyte_fd(fd);
	if (e) {
		return quobyte_fsync(e->fh);
	}
	return real_fsync(fd);
}

int (*real_fdatasync)(int fd) = NULL;
int fdatasync(int fd) {
	LD_DLSYM(real_fdatasync, fdatasync, "fdatasync");
	LD_QUOBYTE_DPRINTF("fdatasync fd=%d", fd);
	struct quobyte_fd_list *e = is_quobyte_fd(fd);
	if (e) {
		return quobyte_fsync(e->fh);
	}
	return real_fdatasync(fd);
}

int (*real_close)(int fd);
int close(int fd)
{
	LD_DLSYM(real_close, close, "close");
	LD_QUOBYTE_DPRINTF("close fd=%d", fd);
	struct quobyte_fd_list *e = is_quobyte_fd(fd);
	if (e) {
		int ret;
		e->fd = -1;
		LD_QUOBYTE_DPRINTF("quobyte_close %p", e->fh);
		close(fd);
		ret = quobyte_close(e->fh);
		qDecRef();
		return ret;
	}
	return real_close(fd);
}

int (*real_access)(const char *pathname, int mode);
int access(const char *pathname, int mode)
{
	LD_DLSYM(real_access, access, "access");
	LD_QUOBYTE_DPRINTF("access called %s %d", pathname, mode);
	char *filename;
	if (is_quobyte_path(pathname, &filename, 1)) {
		int ret = quobyte_access(filename, mode);
		free(filename);
		qDecRef();
		return ret;
	}
    return real_access(pathname, mode);
}

int (*real_dirfd)(DIR *dirp);
int dirfd(DIR *dirp)
{
	LD_DLSYM(real_dirfd, dirfd, "dirfd");
	LD_QUOBYTE_DPRINTF("dirfd called %p", dirp);
	if (is_quobyte_dh(dirp)) {
		errno = ENOTSUP;
		return -1;
	}
	return real_dirfd(dirp);
}
