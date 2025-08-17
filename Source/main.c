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
    ctx->socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ctx->socket_fd < 0) {
        FatalErrorErrno("socket", errno);
    }

    int reuseaddr = 1;
    if (setsockopt(ctx->socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) < 0) {
        FatalErrorErrno("setsockopt(SO_REUSEADDR)", errno);
    }

    int reuseport = 1;
    if (setsockopt(ctx->socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(int)) < 0) {
        FatalErrorErrno("setsockopt(SO_REUSEPORT)", errno);
    }

    // Lookup hostname
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

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
}

static void DestroyContext(Context *ctx) {
    close(ctx->socket_fd);
}

int main(int argc, char **argv) {
    Context ctx = {0};
    ctx.max_hops = 30;

    HandleProgramArguments(&ctx, argc, argv);
    InitContext(&ctx);
    TraceRoute(&ctx);
    DestroyContext(&ctx);
}
