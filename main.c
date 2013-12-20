#include <linux/fcntl.h>
#include <linux/limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <unistd.h>

static void *run(void *data)
{
	char buf[4096];
	int fd;
	const struct fanotify_event_metadata *metadata;
	int len;
	char path[PATH_MAX];
	int path_len;
	struct fanotify_response response;


	if (-1 == (fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT, O_RDONLY | O_LARGEFILE)))
	{
		perror("Cannot init");
		return NULL;
	}

	if (-1 == (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_ACCESS, FAN_NOFD, "/")))
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
			if (metadata->fd != FAN_NOFD)
			{
				if (metadata->fd >= 0)
				{
					if (metadata->mask & FAN_ACCESS)
					{
						printf("FAN_ACCESS: ");
						response.fd = metadata->fd;
						response.response = FAN_ALLOW;
						write(fd, &response, sizeof(struct fanotify_response));

						sprintf(path, "/proc/self/fd/%d", metadata->fd);
						path_len = readlink(path, path, sizeof (path) - 1);
					
						if (path_len > 0)
						{
							path[path_len] = 0x00;
		                			printf("File %s", path);
		            			}

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
