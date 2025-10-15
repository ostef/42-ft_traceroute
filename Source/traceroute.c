#include "ft_traceroute.h"

void SendProbe(Context *ctx) {
    char buffer[Packet_Size] = {0};

    int probe_in_hop = ctx->total_queries_sent % ctx->num_queries_per_hop;
    int hop = ctx->first_ttl + ctx->total_queries_sent / ctx->num_queries_per_hop;

    if (probe_in_hop == 0) {
        if (setsockopt(ctx->socket_fd, IPPROTO_IP, IP_TTL, &hop, sizeof(hop)) < 0) {
            FatalErrorErrno("setsockopt(SO_REUSEADDR)", errno);
        }
    }

    struct sockaddr_in dest_addr = ctx->dest_addr;
    dest_addr.sin_port = htons(ctx->port + ctx->total_queries_sent);

    ctx->probe_infos[ctx->total_queries_sent].send_time = GetTime();

    Dbg("SendProbe:%d(%d) %u\n", hop, probe_in_hop, dest_addr.sin_port);
    int sendto_result = sendto(ctx->socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sendto_result <= 0) {
        FatalErrorErrno("sendto", errno);
    }

    ctx->queries_sent_this_loop += 1;
    ctx->total_queries_sent += 1;
}

static void PrintPacket(Context *ctx, int query_index) {
    int probe = query_index % ctx->num_queries_per_hop;
    int hop = ctx->first_ttl + query_index / ctx->num_queries_per_hop;
    ProbeInfo *probe_info = &ctx->probe_infos[query_index];

    if (probe == 0) {
        dprintf(STDOUT_FILENO, "%*d  ", ctx->ttl_num_digits, hop);
    }

    if (!probe_info->received) {
        dprintf(STDOUT_FILENO, "* ");
    } else {
        if (ctx->last_printed_addr.s_addr != probe_info->recv_addr.sin_addr.s_addr) {
            char *addr_str = inet_ntoa(probe_info->recv_addr.sin_addr);
            dprintf(STDOUT_FILENO, "%s (%s) ", addr_str, addr_str);
            ctx->last_printed_addr.s_addr = probe_info->recv_addr.sin_addr.s_addr;
        }

        double round_trip_time = probe_info->recv_time - probe_info->send_time;
        dprintf(STDOUT_FILENO, "%.3f ms ", round_trip_time * 1000.0);
    }

    if (probe == ctx->num_queries_per_hop - 1) {
        ctx->last_printed_addr = (struct in_addr){};

        dprintf(STDOUT_FILENO, "\n");

        if (ctx->final_dest_hop == hop) {
            exit(0);
        }
    }

    ctx->last_printed_query = query_index;
}

static void PrintRemainingPackets(Context *ctx, bool all_packets) {
    for (int i = ctx->last_printed_query + 1; i < ctx->first_query_this_loop + ctx->queries_sent_this_loop; i += 1) {
        ProbeInfo *probe_info = &ctx->probe_infos[i];
        if (!all_packets && !probe_info->received) {
            break;
        }

        PrintPacket(ctx, i);
    }
}

static bool WaitForPacket(Context *ctx) {
    fd_set read_fds;

    FD_ZERO(&read_fds);
    FD_SET(ctx->icmp_socket_fd, &read_fds);

    double timeout_seconds = ctx->max_wait_in_seconds - (GetTime() - ctx->receive_start_time);
    if (timeout_seconds <= 0) {
        return false;
    }

    struct timeval timeout = SecondsDoubleToTimeval(timeout_seconds);

    int select_result = select(ctx->icmp_socket_fd + 1, &read_fds, NULL, NULL, &timeout);
    if (select_result < 0) {
        FatalErrorErrno("select", errno);
    }

    if (!FD_ISSET(ctx->icmp_socket_fd, &read_fds)) {
        return false;
    }

    return true;
}

void ReceivePacket(Context *ctx) {
    if (!WaitForPacket(ctx)) {
        return;
    }

    char buffer[1024];

    struct sockaddr_in recv_addr = {0};
    socklen_t addr_len = sizeof(recv_addr);

    ssize_t received = recvfrom(ctx->icmp_socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);
    if (received <= 0) {
        Dbg("Recv %ld\n", received);
        return;
    }

    if (addr_len != sizeof(struct sockaddr_in)) {
        Dbg("Bad addr len(%u)\n", addr_len);
        return;
    }

    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));
    if (icmp->type != ICMP_TIME_EXCEEDED && icmp->type != ICMP_DEST_UNREACH) {
        return;
    }

    struct iphdr *original_ip = (struct iphdr *)(icmp + 1);
    if (original_ip->protocol != IPPROTO_UDP) {
        return;
    }

    struct udphdr *original_udp = (struct udphdr *)(original_ip + 1);

    uint16_t source_port = ntohs(original_udp->uh_sport);
    if (source_port != ctx->source_port) {
        return;
    }

    int recv_port = ntohs(original_udp->uh_dport);

    Dbg("TTL:%d\n", original_ip->ttl);
    Dbg("Check:%u\n", original_ip->check);
    Dbg("Port:%u\n", recv_port);

    int recv_query = recv_port - ctx->port;
    int recv_index = recv_query - ctx->first_query_this_loop;
    if (recv_index < 0 || recv_index >= ctx->queries_sent_this_loop) {
        return;
    }

    if (ctx->probe_infos[recv_query].received) {
        if (ctx->probe_infos[recv_query].recv_addr.sin_addr.s_addr != recv_addr.sin_addr.s_addr) {
            char *a = strdup(inet_ntoa(ctx->probe_infos[recv_query].recv_addr.sin_addr));
            char *b = strdup(inet_ntoa(recv_addr.sin_addr));
            Dbg("BADBAD %s != %s\n", a, b);
        }

        Dbg("Already received\n");
    } else {
        ctx->probe_infos[recv_query].icmp_type = icmp->type;
        ctx->probe_infos[recv_query].received = true;
        ctx->probe_infos[recv_query].recv_addr = recv_addr;
        ctx->probe_infos[recv_query].recv_time = GetTime();
    }

    int hop = ctx->first_ttl + recv_query / ctx->num_queries_per_hop;

    if (ctx->final_dest_hop == 0 && icmp->type == ICMP_DEST_UNREACH) {
        ctx->final_dest_hop = hop;
    }
}

static bool ReceivedAllPackets(Context *ctx) {
    for (int i = 0; i < ctx->queries_sent_this_loop; i += 1) {
        if (!ctx->probe_infos[ctx->first_query_this_loop + i].received) {
            return false;
        }
    }

    return true;
}

void TraceRoute(Context *ctx) {
    dprintf(STDOUT_FILENO, "traceroute to %s (%s), %d hops max, %d bytes packets\n", ctx->dest_hostname_arg, ctx->dest_addr_str, ctx->max_ttl, Packet_Size);

    int max_total_queries = ctx->num_queries_per_hop * (ctx->max_ttl - ctx->first_ttl + 1);
    while (ctx->total_queries_sent < max_total_queries) {
        ctx->first_query_this_loop = ctx->total_queries_sent;
        ctx->queries_sent_this_loop = 0;

        while (ctx->total_queries_sent < max_total_queries && ctx->queries_sent_this_loop < ctx->num_simultaneous_queries) {
            SendProbe(ctx);
        }

        ctx->receive_start_time = GetTime();

        while (!ReceivedAllPackets(ctx) && GetTime() < ctx->receive_start_time + ctx->max_wait_in_seconds) {
            ReceivePacket(ctx);
            PrintRemainingPackets(ctx, false);
        }

        PrintRemainingPackets(ctx, true);
    }
}
