//
// Created by op on 03/10/2024
//

#ifndef CLIENT_H
#define CLIENT_H
#include <netinet/in.h>
#include <sys/socket.h>

typedef struct
{
    // cppcheck-suppress unusedStructMember
    char filter_type;
    // cppcheck-suppress unusedStructMember
    char *message;
    // cppcheck-suppress unusedStructMember
    char *server_input;
    // cppcheck-suppress unusedStructMember
    const char *ip_address;
    // cppcheck-suppress unusedStructMember
    unsigned short port_number;
    // cppcheck-suppress unusedStructMember
    int fd;
    // cppcheck-suppress unusedStructMember
    int exit_flag;

} Client_Settings;

int   parse_arguments(int argc, char *args[], Client_Settings *settings);
void  write_string_to_fd(char *input, const int *fd, int *err);
void  read_string_from_fd(unsigned long length, const int *fd, int *err);
char *initialize_input_string(Client_Settings *settings);
void  send_server_request(Client_Settings *settings);
void  receive_server_response(Client_Settings *settings);
void  cleanup(Client_Settings *settings);
int   connect_to_server(struct sockaddr_storage *addr, socklen_t addr_len, int *err);
int   open_network_socket_client(const char *address, in_port_t port, int *err);

#endif    // CLIENT_H
