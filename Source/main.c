#include "ft_traceroute.h"

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
// https://www.geeksforgeeks.org/ping-in-c/

struct timeval SecondsDoubleToTimeval(double seconds) {
    struct timeval time = {0};
    time.tv_sec = (time_t)seconds;
    time.tv_usec = (time_t)((seconds - (int)seconds) * 1000000);

    return time;
}

double TimevalToSecondsDouble(struct timeval time) {
    return (double)time.tv_sec + time.tv_usec / 1000000.0;
}

double GetTime() {
    struct timeval time = {0};
    gettimeofday(&time, NULL);

    return TimevalToSecondsDouble(time);
}

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
    fprintf(stderr, "  ft_traceroute [options*] <destination>\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -f <first_ttl>\t\tStart from the <first_ttl> hop (default is 1)\n");
    fprintf(stderr, "  -m <max_ttl>\t\t\tSet the maximum ttl (default is 30)\n");
    fprintf(stderr, "  -N <sim_queries>\t\tSet the number of simultaneous probes sent (default is 16)\n");
    fprintf(stderr, "  -q <num_probes>\t\tSet the number of probes to send per hop (default is 3)\n");
    fprintf(stderr, "  -w <max_wait>\t\t\tWait at most <max_wait> seconds for all pending packets to receive (default is 1 second)\n");
}

static long ParseInt(char *str) {
    char *end = str + strlen(str);
    long value = strtol(str, &end, 10);
    if (end != str + strlen(str)) {
        FatalError("Expected an integer (got '%s')", str);
    }

    return value;
}

static float ParseFloat(char *str) {
    char *end = str + strlen(str);
    float value = strtof(str, &end);
    if (end != str + strlen(str)) {
        FatalError("Expected a floating point value (got '%s')", str);
    }

    return value;
}

static void HandleProgramArguments(Context *ctx, int argc, char **argv) {
    char option = 0;
    for (int i = 1; i < argc; i += 1) {
        switch (option) {
        case 0:
            break;
        case 'f':
            ctx->first_ttl = ParseInt(argv[i]);
            if (ctx->first_ttl < 1) {
                FatalError("Invalid value for -f option (expected an integer >1)");
            }
            break;
        case 'm':
            ctx->max_ttl = ParseInt(argv[i]);
            if (ctx->max_ttl < 1) {
                FatalError("Invalid value for -m option (expected an integer >1)");
            }
            break;
        case 'N':
            ctx->num_simultaneous_queries = ParseInt(argv[i]);
            if (ctx->num_simultaneous_queries < 1) {
                FatalError("Invalid value for -N option (expected an integer >1)");
            }
            break;
        case 'q':
            ctx->num_queries_per_hop = ParseInt(argv[i]);
            if (ctx->num_queries_per_hop < 1) {
                FatalError("Invalid value for -q option (expected an integer >1)");
            }
            break;
        case 'p':
            long port = ParseInt(argv[i]);
            if (port < 0 || port > 0xffff) {
                FatalError("Invalid value for -p option (expected an unsigned 16 bit integer)");
            }
            ctx->port = (uint16_t)port;
            break;
        case 'w':
            ctx->max_wait_in_seconds = ParseFloat(argv[i]);
            if (ctx->max_wait_in_seconds <= 0) {
                FatalError("Invalid value for -w option (expected a positive floating point value)");
            }
            break;
        default:
            FatalError("Unknown option '%c'", option);
            break;
        }

        if (option != 0) {
            option = 0;
            continue;
        }

        if (strcmp(argv[i], "--help") == 0) {
            PrintUsage();
            exit(0);
        } else if (argv[i][0] == '-') {
            option = argv[i][1];
            if (argv[i][1] == 0 || argv[i][2] != 0) {
                FatalError("Unknown option '%s'", argv[i]);
            }
        } else if (ctx->dest_hostname_arg) {
            FatalError("Only one destination address should be provided");
        } else {
            ctx->dest_hostname_arg = argv[i];
        }
    }

    if (option != 0) {
        FatalError("No argument provided for option '%c'", option);
    }

    if (ctx->max_ttl < ctx->first_ttl) {
        FatalError("Invalid value for -m option (must be >= first ttl of %d)", ctx->first_ttl);
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

    ctx->source_port = (getpid() & 0xffff) | (1U << 15);

    struct sockaddr_in source_addr = {0};
    source_addr.sin_family = AF_INET;
    source_addr.sin_port = htons(ctx->source_port);
    bind(ctx->socket_fd, (struct sockaddr *)&source_addr, sizeof(source_addr));

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

    char *dest_addr_str = inet_ntoa(((struct sockaddr_in *)dest_addr_info->ai_addr)->sin_addr);
    strcpy(ctx->dest_addr_str, dest_addr_str);

    memcpy(&ctx->dest_addr, dest_addr_info->ai_addr, sizeof(ctx->dest_addr));

    // Reverse DNS lookup
    res = getnameinfo((void *)&ctx->dest_addr, sizeof(ctx->dest_addr), ctx->dest_hostname, sizeof(ctx->dest_hostname), NULL, 0, 0);
    if (res != 0) {
        freeaddrinfo(dest_addr_info);
        FatalErrorEAI("getnameinfo", res);
    }

    freeaddrinfo(dest_addr_info);

    ctx->probe_infos = malloc(sizeof(ProbeInfo) * (ctx->max_ttl - ctx->first_ttl + 1) * ctx->num_queries_per_hop);
    memset(ctx->probe_infos, 0, sizeof(ProbeInfo) * (ctx->max_ttl - ctx->first_ttl + 1) * ctx->num_queries_per_hop);

    ctx->ttl_num_digits = 1;
    {
        int x = ctx->max_ttl / 10;
        while (x > 0) {
            x /= 10;
            ctx->ttl_num_digits += 1;
        }
    }

    ctx->last_printed_query = -1;
}

static void DestroyContext(Context *ctx) {
    close(ctx->socket_fd);
    close(ctx->icmp_socket_fd);
    free(ctx->probe_infos);
}

int main(int argc, char **argv) {
    Context ctx = {0};
    ctx.first_ttl = 1;
    ctx.max_ttl = 30;
    ctx.num_simultaneous_queries = 16;
    ctx.num_queries_per_hop = 3;
    ctx.port = 33434;
    ctx.max_wait_in_seconds = 1;

    HandleProgramArguments(&ctx, argc, argv);
    InitContext(&ctx);
    TraceRoute(&ctx);
    DestroyContext(&ctx);
}
