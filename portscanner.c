#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <getopt.h>

/**
 * Structure representing a scanning task for a single port.
 */
typedef struct {
    char ip[64];        // Target IP address
    int port;           // Port number to scan
    int timeout_sec;    // Timeout for connection attempt in seconds
    int verbose;        // Verbosity flag to enable detailed output
} scan_task_t;

// Named semaphore pointer for concurrency control
sem_t *semaphore = NULL;
const char *SEM_NAME = "/portscanner_sem";

/**
 * Attempts to connect to a TCP port on a given IP within a specified timeout.
 *
 * @param ip The IP address to scan
 * @param port The port number to scan
 * @param timeout_sec Connection timeout in seconds
 * @param verbose Whether to print verbose output
 * @return 1 if port is open, 0 otherwise
 */
int scan_port(const char *ip, int port, int timeout_sec, int verbose) {
    int sockfd;
    struct sockaddr_in addr;
    fd_set fdset;
    struct timeval tv;
    int flags, res, error;
    socklen_t len;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        if (verbose) perror("socket");
        return 0;
    }

    flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    res = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (res < 0) {
        if (errno == EINPROGRESS) {
            FD_ZERO(&fdset);
            FD_SET(sockfd, &fdset);
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;

            res = select(sockfd + 1, NULL, &fdset, NULL, &tv);
            if (res > 0) {
                len = sizeof(error);
                getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
                if (error == 0) {
                    close(sockfd);
                    if (verbose) printf("Port %d open\n", port);
                    return 1;
                }
            }
        }
        close(sockfd);
        if (verbose) printf("Port %d closed or timeout\n", port);
        return 0;
    }
    close(sockfd);
    if (verbose) printf("Port %d open\n", port);
    return 1;
}

/**
 * Worker thread function to scan a single port.
 * Releases semaphore permit upon completion.
 *
 * @param arg Pointer to scan_task_t struct
 * @return NULL
 */
void* worker(void *arg) {
    scan_task_t *task = (scan_task_t*)arg;
    scan_port(task->ip, task->port, task->timeout_sec, task->verbose);
    sem_post(semaphore); // Release named semaphore permit
    free(task);
    return NULL;
}

/**
 * Main entry point of the port scanner CLI tool.
 * Parses command line arguments, manages concurrency, and spawns scan threads.
 *
 * Supported options:
 *   -h <ip>           Target IP address (default 127.0.0.1)
 *   -s <start_port>   Start of port range (default 1)
 *   -e <end_port>     End of port range (default 1024)
 *   -t <timeout>      Timeout seconds per port (default 1)
 *   -c <concurrency>  Number of concurrent threads (default 50)
 *   -v                Verbose output
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @return Exit status (0 on success)
 */
int main(int argc, char **argv) {
    char ip[64] = "127.0.0.1";
    int start_port = 1;
    int end_port = 1024;
    int timeout_sec = 1;
    int concurrency = 50;
    int verbose = 0;

    int opt;
    while ((opt = getopt(argc, argv, "h:s:e:t:c:v")) != -1) {
        switch (opt) {
            case 'h':
                strncpy(ip, optarg, sizeof(ip) - 1);
                ip[sizeof(ip) - 1] = '\0';
                break;
            case 's':
                start_port = atoi(optarg);
                break;
            case 'e':
                end_port = atoi(optarg);
                break;
            case 't':
                timeout_sec = atoi(optarg);
                break;
            case 'c':
                concurrency = atoi(optarg);
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s -h ip -s start_port -e end_port -t timeout_sec -c concurrency -v\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (start_port > end_port || start_port < 1 || end_port > 65535) {
        fprintf(stderr, "Invalid port range\n");
        exit(EXIT_FAILURE);
    }

    // Open a named semaphore for concurrency control
    sem_unlink(SEM_NAME); // Remove existing semaphore if any
    semaphore = sem_open(SEM_NAME, O_CREAT | O_EXCL, 0644, concurrency);
    if (semaphore == SEM_FAILED) {
        perror("sem_open");
        exit(EXIT_FAILURE);
    }

    pthread_t thread_id;
    for (int port = start_port; port <= end_port; port++) {
        sem_wait(semaphore); // Acquire a semaphore permit

        scan_task_t *task = malloc(sizeof(scan_task_t));
        if (!task) {
            perror("malloc");
            sem_post(semaphore);
            continue;
        }
        strncpy(task->ip, ip, sizeof(task->ip) - 1);
        task->ip[sizeof(task->ip) - 1] = '\0';
        task->port = port;
        task->timeout_sec = timeout_sec;
        task->verbose = verbose;

        if (pthread_create(&thread_id, NULL, worker, task) != 0) {
            perror("pthread_create");
            sem_post(semaphore);
            free(task);
        } else {
            pthread_detach(thread_id);
        }
    }

    // Wait for all threads to complete by acquiring all permits
    for (int i = 0; i < concurrency; i++) {
        sem_wait(semaphore);
    }

    sem_close(semaphore);
    sem_unlink(SEM_NAME);

    return 0;
}

