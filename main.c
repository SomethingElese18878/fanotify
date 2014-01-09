#include <linux/fcntl.h>
#include <linux/limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <unistd.h>

#define MAX_PATH 10

void monitor_path(int fd, char *path, uint64_t event_mask)
{
	/*Add specific folder - AT_FDCWD / FAN_NOFD */
	if (-1 == (fanotify_mark(fd,
						FAN_MARK_ADD,
						event_mask,
						AT_FDCWD,
						path)))
	{
		perror("Cannot mark");
		close(fd);
		return;
	}
}

void print_path(const struct fanotify_event_metadata *metadata)
{
	int path_len;
	char path[PATH_MAX];

	sprintf(path, "/proc/self/fd/%d", metadata->fd);
	path_len = readlink(path, path, sizeof (path) - 1);	//read content of symbolic link

	if (path_len > 0)
	{
		path[path_len] = 0x00;
		printf("File %s", path);
	}

	// Print the kind of access at the end of the line.
	if (metadata->mask & FAN_ACCESS) printf(" -> FAN_ACCESS <-");
	if (metadata->mask & FAN_MODIFY) printf(" -> FAN_MODIFY <-");
	if (metadata->mask & FAN_OPEN) printf(" -> FAN_OPEN <-");
	if (metadata->mask & FAN_CLOSE) printf(" -> FAN_CLOSE <-");
	if (metadata->mask & FAN_ONDIR) printf(" -> FAN_ONDIR <-");
	if (metadata->mask & FAN_EVENT_ON_CHILD) printf(" -> FAN_EVENT_ON_CHILD <-");
}

/**
  * This functions blocks or allows a file-access.
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
	char *monitored_folder[MAX_PATH] = {	"/home/norman/secure-folder/bla",
											"/home/norman/secure-folder/blubb",
											"/home/norman/secure-folder/c"};
	int fd;
	int len;
	const struct fanotify_event_metadata *metadata;
	static uint64_t event_mask = (	FAN_ACCESS |
									FAN_MODIFY |
									FAN_OPEN |
									FAN_CLOSE |
									FAN_ONDIR |
									FAN_EVENT_ON_CHILD);

	printf("getPID: %d \n", getpid());
	printf("getPPID: %d \n", getppid());

	if (-1 == (fd = fanotify_init( FAN_CLOEXEC | FAN_CLASS_CONTENT,
								   O_RDONLY | O_LARGEFILE)))
	{
		perror("Cannot init");
		return NULL;
	}

	monitor_path(fd, monitored_folder[0], event_mask);
	monitor_path(fd, monitored_folder[1], event_mask);

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
						block_file_access(fd, metadata, 1); // block filehandle
						print_path(metadata);
						block_file_access(fd, metadata, 0); // free filehandle after proved
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
