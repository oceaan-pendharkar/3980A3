#include "../include/client.h"
#include "../include/server.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ERR_NONE 0
#define ERR_NO_DIGITS 1
#define ERR_OUT_OF_RANGE 2
#define ERR_INVALID_CHARS 3

#define DELIMITER '|'

int parse_arguments(int argc, char *args[], Client_Settings *settings)
{
    int          opt;
    char *const *arguments = args;
    settings->filter_type  = 'n';
    settings->message      = NULL;
    settings->port_number  = 0;
    settings->ip_address   = NULL;
    while((opt = getopt(argc, arguments, "a:p:s:lu")) != -1)
    {
        switch(opt)
        {
            case 'l':
            case 'u':
                settings->filter_type = (char)opt;
                break;
            case 's':
                settings->message = optarg;
                break;
            case 'a':
                settings->ip_address = optarg;
                break;
            case 'p':
                settings->port_number = convert_port(optarg, &settings->exit_flag);
                break;
            default:
                fprintf(stderr, "Usage: %s -a [<ip address>] -p [<port number>] -s [<the string>] [-u or -l (optional)]\n", arguments[0]);
                return -1;
        }
    }
    if(!settings->filter_type || !settings->message || settings->port_number == 0 || !settings->ip_address)
    {
        fprintf(stderr, "Usage: %s -a [<ip address>] -p [<port number>] -s [<the string>] [-u or -l (optional)]\n", arguments[0]);
        return -1;
    }
    return 0;
}

void write_string_to_fd(char *input, const int *fd, int *err)
{
    ssize_t n_wrote = write(*fd, input, strlen(input));
    if(n_wrote < 0)
    {
        *err = -4;
    }
    free(input);
}

void read_string_from_fd(const unsigned long length, const int *fd, int *err)
{
    unsigned long       length_to_set = length;
    char               *output;
    const unsigned long DENIED_LENGTH = 6;
    ssize_t             n_read;

    if(length_to_set < DENIED_LENGTH)
    {
        length_to_set = DENIED_LENGTH;
    }
    output = (char *)malloc((length_to_set + 2) * sizeof(char));
    n_read = read(*fd, output, length_to_set + 1);
    if(n_read < 0)
    {
        printf("n_read less than 0");
        *err = -4;
        close(*fd);
        free(output);
        return;
    }
    close(*fd);
    output[n_read] = '\0';
    printf("response from server: %s\n", output);
    free(output);
}

char *initialize_input_string(Client_Settings *settings)
{
    const unsigned long NUM_EXTRA_CHARS_PLUS_TERMINATOR = 4;
    char               *input                           = (char *)malloc((strlen(settings->message) + NUM_EXTRA_CHARS_PLUS_TERMINATOR) * sizeof(char));
    if(input == NULL)
    {
        printf("Memory allocation failed\n");
        settings->exit_flag = -2;
        return NULL;
    }
    input[0] = settings->filter_type;
    input[1] = DELIMITER;
    input[2] = '\0';
    strlcat(input, settings->message, strlen(settings->message) + 3);
    return input;
}

void cleanup(Client_Settings *settings)
{
    free(settings->server_input);
}

int connect_to_server(struct sockaddr_storage *addr, socklen_t addr_len, int *err)
{
    int fd;
    int result;

    fd = socket(addr->ss_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)

    if(fd == -1)
    {
        *err = errno;
        goto done;
    }

    result = connect(fd, (const struct sockaddr *)addr, addr_len);

    if(result == -1)
    {
        *err = errno;
        close(fd);
        fd = -1;
    }

done:
    return fd;
}

int open_network_socket_client(const char *address, in_port_t port, int *err)
{
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    int                     fd;

    setup_network_address(&addr, &addr_len, address, port, err);

    if(*err != 0)
    {
        fd = -1;
        goto done;
    }

    fd = connect_to_server(&addr, addr_len, err);

done:
    return fd;
}

void send_server_request(Client_Settings *settings)
{
    settings->fd = open_network_socket_client(settings->ip_address, settings->port_number, &settings->exit_flag);

    if(settings->fd < 0)
    {
        printf("Error opening socket to server\n");
        settings->exit_flag = -3;
        free(settings->server_input);
        return;
    }
    write_string_to_fd(settings->server_input, &settings->fd, &settings->exit_flag);
}

void receive_server_response(Client_Settings *settings)
{
    read_string_from_fd(strlen(settings->message), &settings->fd, &settings->exit_flag);
}

in_port_t convert_port(const char *str, int *err)
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

void setup_network_address(struct sockaddr_storage *addr, socklen_t *addr_len, const char *address, in_port_t port, int *err)
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

// exit values
//-1: parse args failed
//-2: memory allocation failed
//-3: error opening a resource
//-4: error reading or writing

int main(int argc, char *argv[])
{
    Client_Settings settings;

    settings.exit_flag = parse_arguments(argc, argv, &settings);
    if(settings.exit_flag != 0)
    {
        goto done;
    }

    settings.server_input = initialize_input_string(&settings);
    if(settings.exit_flag != 0)
    {
        cleanup(&settings);
        goto done;
    }

    send_server_request(&settings);
    if(settings.exit_flag != 0)
    {
        goto done;
    }

    receive_server_response(&settings);

done:
    return settings.exit_flag;
}
