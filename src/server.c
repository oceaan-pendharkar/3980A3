#include "../include/server.h"
#include "../include/filter.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ERR_NONE 0
#define ERR_NO_DIGITS 1
#define ERR_OUT_OF_RANGE 2
#define ERR_INVALID_CHARS 3
#define PORT 8080
#define BACKLOG 5

static volatile sig_atomic_t exit_flag = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static int socket_bind_listen(const struct sockaddr_storage *addr, socklen_t addr_len, int backlog, volatile sig_atomic_t *err);

int open_network_socket_server(const char *address, in_port_t port, int backlog, volatile sig_atomic_t *err)
{
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    int                     client_fd;
    printf("opening network socket\n");

    setup_network_address(&addr, &addr_len, address, port, err);

    if(*err != 0)
    {
        client_fd = -1;
        goto done;
    }

    client_fd = socket_bind_listen(&addr, addr_len, backlog, err);

done:
    return client_fd;
}

static int socket_bind_listen(const struct sockaddr_storage *addr, socklen_t addr_len, int backlog, volatile sig_atomic_t *err)
{
    int server_fd;
    int result;

    server_fd = socket(addr->ss_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)

    if(server_fd == -1)
    {
        *err = errno;
        return server_fd;
    }

    result = bind(server_fd, (const struct sockaddr *)addr, addr_len);

    if(result == -1)
    {
        *err = errno;
        close(server_fd);
        return -1;
    }

    result = listen(server_fd, backlog);

    if(result == -1)
    {
        *err = errno;
        close(server_fd);
        return -1;
    }

    return server_fd;
}

void setup_network_address(struct sockaddr_storage *addr, socklen_t *addr_len, const char *address, in_port_t port, volatile sig_atomic_t *err)
{
    in_port_t net_port;

    *addr_len = 0;
    net_port  = htons(port);
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        addr->ss_family     = AF_INET;
        ipv4_addr->sin_port = net_port;
        *addr_len           = sizeof(struct sockaddr_in);
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        addr->ss_family      = AF_INET6;
        ipv6_addr->sin6_port = net_port;
        *addr_len            = sizeof(struct sockaddr_in6);
    }
    else
    {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
        *err = errno;
    }
}

char *get_message_content(const char *msg)
{
    const size_t length      = strlen(msg);
    char        *msg_content = (char *)malloc((length - 1) * sizeof(char));
    if(msg_content == NULL)
    {
        return NULL;
    }
    strncpy(msg_content, msg + 2, length - 2);
    msg_content[length - 2] = '\0';
    return msg_content;
}

char *get_denied_message(void)
{
    const long unsigned int length         = 8;
    char                   *denied_message = (char *)malloc((length) * sizeof(char));
    if(denied_message != NULL)
    {
        strlcpy(denied_message, "denied", length);
        denied_message[length - 1] = '\0';
    }
    return denied_message;
}

int process_client(int fd)
{
    const long unsigned int LIMIT = 100;
    char                   *output;
    char                   *input;
    ssize_t                 n_read;
    ssize_t                 n_wrote = -1;
    printf("processing client!!\n");
    if(fd < 0)
    {
        printf("Error opening network socket\n");
        return -3;
    }

    input = (char *)malloc(LIMIT * sizeof(char));
    if(input == NULL)
    {
        printf("Memory allocation failed\n");
        return -2;
    }
    n_read = read(fd, input, LIMIT);
    if(n_read == -1)
    {
        printf("reading failed\n");
        free(input);
        return -4;
    }
    input[n_read] = '\0';
    printf("input: %s\n", input);

    if(exit_flag == 0)
    {
        char *message_content = get_message_content(input);
        if(message_content == NULL)
        {
            free(input);
            return -2;
        }

        if(input[0] == 'u')
        {
            output = filter_string(message_content, strlen(message_content), &exit_flag, upper_filter);
        }
        else if(input[0] == 'l')
        {
            output = filter_string(message_content, strlen(message_content), &exit_flag, lower_filter);
        }
        else
        {
            output = filter_string(message_content, strlen(message_content), &exit_flag, null_filter);
        }
        free(message_content);
    }
    else
    {
        output = get_denied_message();
    }

    if(output != NULL)
    {
        printf("output from server: %s\n", output);
        n_wrote = write(fd, output, strlen(output));
    }

    if(!n_wrote || n_wrote < 0)
    {
        printf("writing failed\n");
        exit_flag = -4;
    }

    free(output);
    free(input);
    return exit_flag;
}

int parse_server_arguments(int argc, char *args[], server_data_t *data)
{
    int          opt;
    char *const *arguments   = args;
    const int    NUM_ARGS    = 5;
    const char  *arg1        = "-a";
    const char  *arg2        = "-p";
    const bool   HAS_ADDRESS = arguments[1] != (void *)0 && strcmp(arguments[1], arg1) == 0;
    const bool   HAS_PORT    = arguments[3] != (void *)0 && strcmp(arguments[3], arg2) == 0;
    data->ip_address         = "asdfasf";
    data->port_number        = PORT;
    while((opt = getopt(argc, arguments, "a:p:")) != -1)
    {
        switch(opt)
        {
            case 'a':
                data->ip_address = optarg;
                break;
            case 'p':
                data->port_number = convert_port(optarg, &exit_flag);
                break;
            default:
                fprintf(stderr, "Usage: %s -a <ip address> -p <port number>\n", arguments[0]);
                return -1;
        }
    }
    if(argc < NUM_ARGS || !HAS_ADDRESS || !HAS_PORT)
    {
        if(!HAS_ADDRESS || !HAS_PORT)
        {
            printf("You must specify an ip address and port number for your server.\n");
        }
        fprintf(stderr, "Usage: %s -a <ip address> -p <port number>\n", arguments[0]);
        return -1;
    }
    return 0;
}

void sigint_handler(int signum)
{
    exit_flag = signum;
}

/*
 * Author: D'Arcy Smith
 */
static void setup_signal_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    sa.sa_handler = sigint_handler;

    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

int process_clients_with_fork(server_data_t *data)
{
    pid_t pid;
    data->network_socket_fd = open_network_socket_server(data->ip_address, data->port_number, BACKLOG, &exit_flag);
    if(data->network_socket_fd == -1)
    {
        perror("opening network socket failed");
        data->network_socket_fd = -1;
        return -3;
    }
    printf("forking...\n");
    pid = fork();
    if(pid == -1)
    {
        perror("fork failed");
        exit_flag = EXIT_FAILURE;
        return exit_flag;
    }
    while(!exit_flag)
    {
        if(pid == 0)
        {
            int client_fd = accept(data->network_socket_fd, NULL, 0);
            if(client_fd == -1)
            {
                printf("accept failed!\n");
                exit_flag = errno;
                close(data->network_socket_fd);
                printf("closed network socket\n");
                return exit_flag;
            }
            printf("processing client...\n");
            exit_flag = process_client(client_fd);
            printf("processed child...\n");
            close(client_fd);
        }
    }
    close(data->network_socket_fd);
    return exit_flag;
}

in_port_t convert_port(const char *str, volatile sig_atomic_t *err)
{
    in_port_t port;
    char     *endptr;
    long      val;

    *err  = ERR_NONE;
    port  = 0;
    errno = 0;
    val   = strtol(str, &endptr, 10);    // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

    // Check if no digits were found
    if(endptr == str)
    {
        *err = ERR_NO_DIGITS;
        goto done;
    }

    // Check for out-of-range errors
    if(val < 0 || val > UINT16_MAX)
    {
        *err = ERR_OUT_OF_RANGE;
        goto done;
    }

    // Check for trailing invalid characters
    if(*endptr != '\0')
    {
        *err = ERR_INVALID_CHARS;
        goto done;
    }

    port = (in_port_t)val;

done:
    return port;
}

// exit flag values
//-1: parse args failed
//-2: memory allocation failed
//-3: error opening a fd
//-4: read/write failed
int main(int argc, char *argv[])
{
    server_data_t *data = (server_data_t *)malloc(sizeof(server_data_t));
    if(data == NULL)
    {
        printf("data memory allocation failed");
        return -2;
    }

    setup_signal_handler();
    exit_flag = parse_server_arguments(argc, argv, data);
    if(exit_flag == -1)
    {
        free(data);
        goto done;
    }

    while(!exit_flag)
    {
        printf("Processing clients...\n");
        process_clients_with_fork(data);
    }
    printf("freeing data\n");
    free(data);

done:
    return (int)exit_flag;
}
