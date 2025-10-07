#include "ft_traceroute.h"

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
// https://www.geeksforgeeks.org/ping-in-c/

void FatalError(const char *message, ...) {
    va_list va;

    fprintf(stderr, "Error: ");
    va_start(va, message);
    vfprintf(stderr, message, va);
    va_end(va);
    fprintf(stderr, "\n");

    exit(1);
}

void FatalErrorErrno(const char *message, int err) {
    fprintf(stderr, "Error: %s: %s\n", message, strerror(err));
    exit(1);
}

void FatalErrorEAI(const char *message, int err) {
    fprintf(stderr, "Error: %s: %s\n", message, gai_strerror(err));
    exit(1);
}

static void PrintUsage() {
    fprintf(stderr, "Usage\n");
    fprintf(stderr, "  ft_traceroute <destination>\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  <destination>\t\tDNS name or IP address\n");
}

static void HandleProgramArguments(Context *ctx, int argc, char **argv) {
    char option = 0;
    for (int i = 1; i < argc; i += 1) {
        if (strcmp(argv[i], "--help") == 0) {
            PrintUsage();
            exit(0);
        } else if (argv[i][0] == '-') {
            FatalError("Unknown option '%s'", argv[i]);
        } else if (ctx->dest_hostname_arg) {
            FatalError("Only one destination address should be provided");
        } else {
            ctx->dest_hostname_arg = argv[i];
        }
    }

    if (!ctx->dest_hostname_arg) {
        FatalError("Destination address required");
    }
}

static void InitContext(Context *ctx) {
    // Create UDP socket
    ctx->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->socket_fd < 0) {
        FatalErrorErrno("socket(UDP)", errno);
    }

    int reuseaddr = 1;
    if (setsockopt(ctx->socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) < 0) {
        FatalErrorErrno("setsockopt(UDP, SO_REUSEADDR)", errno);
    }

    int reuseport = 1;
    if (setsockopt(ctx->socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(int)) < 0) {
        FatalErrorErrno("setsockopt(UDP, SO_REUSEPORT)", errno);
    }

    // Create ICMP socket
    ctx->icmp_socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ctx->icmp_socket_fd < 0) {
        FatalErrorErrno("socket(ICMP)", errno);
    }

    reuseaddr = 1;
    if (setsockopt(ctx->icmp_socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) < 0) {
        FatalErrorErrno("setsockopt(ICMP, SO_REUSEADDR)", errno);
    }

    reuseport = 1;
    if (setsockopt(ctx->icmp_socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(int)) < 0) {
        FatalErrorErrno("setsockopt(ICMP, SO_REUSEPORT)", errno);
    }

    // Lookup hostname
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *dest_addr_info = NULL;
    int res = getaddrinfo(ctx->dest_hostname_arg, NULL, &hints, &dest_addr_info);
    if (res != 0) {
        FatalErrorEAI("getaddrinfo", res);
    }

    if (dest_addr_info->ai_family != AF_INET) {
        freeaddrinfo(dest_addr_info);
        FatalError("Expected an IPV4 address");
    }

    if (dest_addr_info->ai_addrlen != sizeof(ctx->dest_addr)) {
        freeaddrinfo(dest_addr_info);
        FatalError("Expected an IPV4 address");
    }

    if (!inet_ntop(AF_INET, &dest_addr_info->ai_addr, ctx->dest_addr_str, sizeof(ctx->dest_addr_str))) {
        FatalErrorErrno("inet_ntop", errno);
    }

    memcpy(&ctx->dest_addr, dest_addr_info->ai_addr, sizeof(ctx->dest_addr));

    // Reverse DNS lookup
    res = getnameinfo((void *)&ctx->dest_addr, sizeof(ctx->dest_addr), ctx->dest_hostname, sizeof(ctx->dest_hostname), NULL, 0, 0);
    if (res != 0) {
        freeaddrinfo(dest_addr_info);
        FatalErrorEAI("getnameinfo", res);
    }

    freeaddrinfo(dest_addr_info);

    ctx->send_times = malloc(sizeof(struct timeval) * ctx->num_simultaneous_queries);
    memset(ctx->send_times, 0, sizeof(struct timeval) * ctx->num_simultaneous_queries);
}

static void DestroyContext(Context *ctx) {
    close(ctx->socket_fd);
    close(ctx->icmp_socket_fd);
    free(ctx->send_times);
}

static void TraceRouteLoop(Context *ctx) {
    char data[68];
    int ttl_num_digits = 1;
    {
        int x = ctx->max_ttl / 10;
        while (x > 0) {
            x /= 10;
            ttl_num_digits += 1;
        }
    }

    int max_total_queries = ctx->num_queries_per_hop * (ctx->max_ttl - ctx->first_ttl);
    int queries_sent = 0;
    while (queries_sent < max_total_queries) {
        int first_query = queries_sent;
        int query = 0;
        for (; queries_sent < max_total_queries && query < ctx->num_simultaneous_queries; query += 1) {
            int query_of_hop = queries_sent % ctx->num_queries_per_hop;
            int ttl = ctx->first_ttl + queries_sent / ctx->num_queries_per_hop;
            if (query_of_hop == 0) {
                if (setsockopt(ctx->socket_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
                    FatalErrorErrno("setsockopt(SO_REUSEADDR)", errno);
                }
            }

            struct sockaddr_in dest_addr = ctx->dest_addr;
            dest_addr.sin_port = htons(ctx->port + queries_sent);

            gettimeofday(&ctx->send_times[query], NULL);

            int sendto_result = sendto(ctx->socket_fd, data, sizeof(data), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (sendto_result < 0 && errno != ECONNRESET) {
                FatalErrorErrno("sendto", errno);
            }

            queries_sent += 1;
        }

        bool reached_dest = false;
        struct sockaddr_in last_addr = {0};
        for (int i = 0; i < query; i += 1) {
            int query_of_hop = (first_query + i) % ctx->num_queries_per_hop;
            int ttl = ctx->first_ttl + (first_query + i) / ctx->num_queries_per_hop;

            if (query_of_hop == 0) {
                last_addr = (struct sockaddr_in){0};
                dprintf(STDOUT_FILENO, "%*d", ttl_num_digits, ttl);
            }

            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(ctx->icmp_socket_fd, &read_fds);

            struct timeval timeout = {0};
            timeout.tv_sec = (time_t)ctx->max_wait_in_seconds;
            timeout.tv_usec = (time_t)((ctx->max_wait_in_seconds - (int)ctx->max_wait_in_seconds) * 1000000);

            int select_result = select(ctx->icmp_socket_fd + 1, &read_fds, NULL, NULL, &timeout);
            if (select_result < 0) {
                FatalErrorErrno("select", errno);
            } else if (FD_ISSET(ctx->icmp_socket_fd, &read_fds)) {
                struct sockaddr_in recv_addr = {0};
                socklen_t addr_len = sizeof(recv_addr);

                ssize_t received = recvfrom(ctx->icmp_socket_fd, data, sizeof(data), 0, (struct sockaddr *)&recv_addr, &addr_len);

                if (recv_addr.sin_addr.s_addr == ctx->dest_addr.sin_addr.s_addr) {
                    reached_dest = true;
                }

                if (received < 0) {
                    if (errno == EHOSTUNREACH) {
                        dprintf(STDOUT_FILENO, " * (no response)");
                    } else {
                        FatalErrorErrno("recvfrom", errno);
                    }
                } else if (received > 0) {
                    struct timeval send_time = ctx->send_times[i];
                    struct timeval recv_time = {0};
                    gettimeofday(&recv_time, NULL);

                    float round_trip_time = (recv_time.tv_sec - send_time.tv_sec) * 1000.0
                        + (recv_time.tv_usec - send_time.tv_usec) / 1000.0;

                    struct icmphdr *hdr = (struct icmphdr *)(data + sizeof(struct iphdr));

                    if (last_addr.sin_addr.s_addr != recv_addr.sin_addr.s_addr) {
						char *addr_str = inet_ntoa(recv_addr.sin_addr);
                        dprintf(STDOUT_FILENO, " %s", addr_str);
                        last_addr = recv_addr;
                    }

                    dprintf(STDOUT_FILENO, " %d %.3f ms", hdr->type, round_trip_time);
                } else {
                    dprintf(STDOUT_FILENO, " *");
                }
            } else {
                dprintf(STDOUT_FILENO, " **");
            }

            if (query_of_hop == ctx->num_queries_per_hop - 1) {
                dprintf(STDOUT_FILENO, "\n");
                if (reached_dest) {
                    return;
                }
            }
        }
    }
}

int main(int argc, char **argv) {
    Context ctx = {0};
    ctx.first_ttl = 1;
    ctx.max_ttl = 30;
    ctx.num_simultaneous_queries = 16;
    ctx.num_queries_per_hop = 3;
    ctx.port = 33333;
    ctx.max_wait_in_seconds = 1;
    ctx.here_wait_in_seconds = 3;
    ctx.near_wait_in_seconds = 10;

    HandleProgramArguments(&ctx, argc, argv);
    InitContext(&ctx);
    TraceRouteLoop(&ctx);
    DestroyContext(&ctx);
}
