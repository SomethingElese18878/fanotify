#include <linux/fcntl.h>
#include <linux/limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <unistd.h>

void print_path(const struct fanotify_event_metadata *metadata)
{
	int path_len;
	char path[PATH_MAX];

	printf("FAN_ACCESS: ");
	sprintf(path, "/proc/self/fd/%d", metadata->fd);
	path_len = readlink(path, path, sizeof (path) - 1);	//read content of symbolic link

	if (path_len > 0)
	{
		path[path_len] = 0x00;
		printf("File %s", path);
	}
}

/**
  * This functions blocks an file-access.
  *	block_fa: 1: true, 0: false
  */
void block_file_access(int fd, const struct fanotify_event_metadata *metadata, int block_fa)
{
	struct fanotify_response response;

	if (block_fa)
	{
		printf("\nBlock FA");
		response.fd = metadata->fd;
		response.response = FAN_DENY;
		write(fd, &response, sizeof(struct fanotify_response));
	}else{
		printf("\nFREE FA");
		response.fd = metadata->fd;
		response.response = FAN_ALLOW;
		write(fd, &response, sizeof(struct fanotify_response));
	}
}


static void *run(void *data)
{
	char buf[4096];
	int fd;
	int len;
	const struct fanotify_event_metadata *metadata;
	static uint64_t event_mask = (	FAN_ACCESS |
									FAN_MODIFY |
									FAN_OPEN |
									FAN_CLOSE |
									FAN_ONDIR |
									FAN_EVENT_ON_CHILD);

	pid_t ignored_pid;
	ignored_pid = getpid();
	printf("getPID: %d \n", ignored_pid);

	if (-1 == (fd = fanotify_init( FAN_CLOEXEC | FAN_CLASS_CONTENT,
								   O_RDONLY | O_LARGEFILE)))
	{
		perror("Cannot init");
		return NULL;
	}

	/*Add specific folder - AT_FDCWD / FAN_NOFD */
	if (-1 == (fanotify_mark(fd,
						FAN_MARK_ADD | FAN_MARK_MOUNT,
						event_mask,
						AT_FDCWD,
						"."))) //"/home/norman/secure-folder"
	{
		perror("Cannot mark");
		close(fd);
		return NULL;
	}

	while (-1 != (len = read(fd, (void *) &buf, sizeof (buf))))
	{
		metadata = (struct fanotify_event_metadata *) buf;
		while (FAN_EVENT_OK(metadata, len))
		{
			if (metadata->fd != FAN_NOFD)	//queue overflow occured
			{
				if (metadata->fd >= 0)
				{
					if (metadata->mask & event_mask)	//file accessed
					{
						print_path(metadata);
						block_file_access(fd, metadata, 0);
					}
					close(metadata->fd);
				}
				printf("\n");
			}
			metadata = FAN_EVENT_NEXT(metadata, len);
		}
 	}
	close(fd);
	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_attr_t attr;
	pthread_t thread;
	void *result;

	if (pthread_attr_init(&attr))
	{
		return EXIT_FAILURE;
	}

	if (pthread_create(&thread, &attr, run, NULL))
	{
		return EXIT_FAILURE;
	}

	printf("Press any key to terminate\n");
	getchar();
	
	if (0 != pthread_kill(thread, SIGUSR1))
	{
		return EXIT_FAILURE;
	}

	pthread_join(thread, &result);
	
	return EXIT_SUCCESS;
}
