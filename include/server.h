
#ifndef SERVER_H
#define SERVER_H

#include <signal.h>
#include <sys/socket.h>

typedef struct
{
    // cppcheck-suppress unusedStructMember
    const char *ip_address;
    // cppcheck-suppress unusedStructMember
    unsigned short port_number;
    // cppcheck-suppress unusedStructMember
    int network_socket_fd;

} server_data_t;

char     *get_message_content(const char *msg);
char     *get_denied_message(void);
int       process_client(int client_fd);
int       parse_server_arguments(int argc, char *args[], server_data_t *data);
void      sigint_handler(int signum);
int       process_clients_with_fork(server_data_t *data);
int       open_network_socket_server(const char *address, in_port_t port, int backlog, volatile sig_atomic_t *err);
void      setup_network_address(struct sockaddr_storage *addr, socklen_t *addr_len, const char *address, in_port_t port, volatile sig_atomic_t *err);
in_port_t convert_port(const char *str, volatile sig_atomic_t *err);

#endif    // SERVER_H
