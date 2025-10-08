#include "ft_traceroute.h"

void SendProbe(Context *ctx) {
    char buffer[1024] = {0};

    int probe_in_hop = ctx->total_queries_sent % ctx->num_queries_per_hop;
    int hop = ctx->first_ttl + ctx->total_queries_sent / ctx->num_queries_per_hop;

    if (probe_in_hop == 0) {
        if (setsockopt(ctx->socket_fd, IPPROTO_IP, IP_TTL, &hop, sizeof(hop)) < 0) {
            FatalErrorErrno("setsockopt(SO_REUSEADDR)", errno);
        }
    }

    struct sockaddr_in dest_addr = ctx->dest_addr;
    dest_addr.sin_port = htons(ctx->port + ctx->total_queries_sent);

    ctx->hop_infos[ctx->queries_sent_this_loop].send_time = GetTime();

    int sendto_result = sendto(ctx->socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sendto_result < 0) {
        FatalErrorErrno("sendto", errno);
    }

    ctx->queries_sent_this_loop += 1;
    ctx->total_queries_sent += 1;
}

void PrintPacket(Context *ctx, int query_index, HopInfo *hop_info) {
    int probe = query_index % ctx->num_queries_per_hop;
    int hop = ctx->first_ttl + query_index / ctx->num_queries_per_hop;

    if (probe == 0) {
        dprintf(STDOUT_FILENO, "%*d", ctx->ttl_num_digits, hop);
    }

    if (!hop_info->received) {
        dprintf(STDOUT_FILENO, " *");
    } else {
        double round_trip_time = hop_info->recv_time - hop_info->send_time;
        dprintf(STDOUT_FILENO, " %.3f ms", round_trip_time * 1000.0);
    }

    if (probe == ctx->num_queries_per_hop - 1) {
        dprintf(STDOUT_FILENO, "\n");

        if (ctx->final_dest_hop == hop) {
            exit(0);
        }
    }

    ctx->last_printed_query = query_index;
}

static void PrintRemainingPackets(Context *ctx, bool all_packets) {
    for (int i = ctx->last_printed_query + 1; i < ctx->first_query_this_loop + ctx->queries_sent_this_loop; i += 1) {
        HopInfo *hop_info = &ctx->hop_infos[i - ctx->first_query_this_loop];
        if (!all_packets && !hop_info->received) {
            break;
        }

        PrintPacket(ctx, i, hop_info);
    }
}

void ReceivePacket(Context *ctx, int i) {
    int query_index = ctx->first_query_this_loop + i;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(ctx->icmp_socket_fd, &read_fds);

    struct timeval timeout = SecondsDoubleToTimeval(ctx->max_wait_in_seconds);

    int select_result = select(ctx->icmp_socket_fd + 1, &read_fds, NULL, NULL, &timeout);
    if (select_result < 0) {
        FatalErrorErrno("select", errno);
    }

    if (FD_ISSET(ctx->icmp_socket_fd, &read_fds)) {
        char buffer[1024];

        struct sockaddr_in recv_addr = {0};
        socklen_t addr_len = sizeof(recv_addr);

        ssize_t received = recvfrom(ctx->icmp_socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);

        if (received > 0) {
            struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));
            struct iphdr *original_ip = (struct iphdr *)(icmp + 1);
            struct udphdr *original_udp = (struct udphdr *)(original_ip + 1);

            int recv_port = ntohs(original_udp->uh_dport);
            int recv_query = recv_port - ctx->port;
            int recv_index = recv_query - ctx->first_query_this_loop;
            if (recv_index >= 0 && recv_index < ctx->queries_sent_this_loop) {
                ctx->hop_infos[recv_index].received = true;
                ctx->hop_infos[recv_index].recv_time = GetTime();

                if (ctx->final_dest_hop == 0 && recv_addr.sin_addr.s_addr == ctx->dest_addr.sin_addr.s_addr) {
                    ctx->final_dest_hop = ctx->first_ttl + recv_query / ctx->num_queries_per_hop;
                }
            }
        }
    }
}

void TraceRoute(Context *ctx) {
    int max_total_queries = ctx->num_queries_per_hop * (ctx->max_ttl - ctx->first_ttl);
    while (ctx->total_queries_sent < max_total_queries) {
        memset(ctx->hop_infos, 0, sizeof(HopInfo) * ctx->num_simultaneous_queries);

        ctx->first_query_this_loop = ctx->total_queries_sent;
        ctx->queries_sent_this_loop = 0;

        while (ctx->total_queries_sent < max_total_queries && ctx->queries_sent_this_loop < ctx->num_simultaneous_queries) {
            SendProbe(ctx);
        }

        for (int i = 0; i < ctx->queries_sent_this_loop; i += 1) {
            ReceivePacket(ctx, i);
            PrintRemainingPackets(ctx, false);
        }

        PrintRemainingPackets(ctx, true);
    }
}
