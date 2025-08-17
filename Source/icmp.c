#include "ft_traceroute.h"

// https://en.wikipedia.org/wiki/Internet_checksum
static unsigned short CalculateIPv4Checksum(void *ptr, int size) {
    unsigned short *buf = ptr;
    unsigned int sum = 0;

    int i = 0;
    for (; size > 1; size -= 2) {
        sum += buf[i];
        i += 1;
    }

    if (size == 1) {
        sum += buf[i];
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
}

int SendICMPEchoPacket(Context *ctx, int ttl) {
    if (setsockopt(ctx->socket_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        FatalErrorErrno("setsockopt(IP_TTL)", errno);
    }

    PingPacket packet = {0};
    packet.header.type = ICMP_ECHO;
    packet.header.un.echo.id = getpid();
    packet.header.un.echo.sequence = 1;

    for (int i = 0; i < sizeof(packet.msg) - 1; i += 1) {
        packet.msg[i] = '0' + i;
    }

    packet.msg[sizeof(packet.msg) - 1] = 0;

    packet.header.checksum = CalculateIPv4Checksum(&packet, sizeof(packet));

    int sent = 0;
    while (true) {
        sent = sendto(
            ctx->socket_fd,
            &packet, sizeof(packet),
            MSG_DONTWAIT,
            (struct sockaddr *)&ctx->dest_addr, sizeof(ctx->dest_addr)
        );

        if (sent < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            } else {
                FatalErrorErrno("sendto", errno);
            }
        }

        if (sent == 0) {
            fprintf(stderr, "Socket closed\n");
            exit(1);
        }

        break;
    }

    return sent;
}

int ReceiveICMPPacket(Context *ctx, void *buff, int size) {
    int received = 0;
    while (true) {
        socklen_t addrlen = sizeof(ctx->dest_addr);
        received = recvfrom(
            ctx->socket_fd,
            buff, size,
            MSG_DONTWAIT,
            (struct sockaddr *)&ctx->dest_addr, &addrlen
        );

        if (received < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                continue;
            } else {
                FatalErrorErrno("recvfrom", errno);
            }
        }

        if (received == 0) {
            fprintf(stderr, "Socket closed\n");
            exit(1);
        }

        struct icmphdr *hdr = (struct icmphdr *)((char *)buff + sizeof(struct iphdr));
        if (hdr->type != ICMP_ECHO) {
            break;
        }
    }

    return received;
}

void PrintICMPPacket(Context *ctx, void *data, int size, double elapsed_ms) {
    struct iphdr *ip_header = (struct iphdr *)data;
    struct icmphdr *header = (struct icmphdr *)((char *)data + sizeof(struct iphdr));
    switch(header->type) {
    case ICMP_ECHO: break; // Ignore our own echo packets
    case ICMP_ECHOREPLY: {
        printf(
            "%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.2f ms\n",
            (int)(size - sizeof(struct iphdr)),
            ctx->dest_hostname, ctx->dest_addr_str,
            header->un.echo.sequence, ip_header->ttl, elapsed_ms
        );
    } break;

    case ICMP_TIME_EXCEEDED: {
        fprintf(stderr,
            "From %s: Time to live exceeded\n",
            ctx->dest_addr_str
        );
    } break;

    case ICMP_DEST_UNREACH: {
        fprintf(stderr,
            "From %s: Destination unreachable\n",
            ctx->dest_addr_str
        );
    } break;

    case ICMP_SOURCE_QUENCH:
        fprintf(stderr,
            "From %s: Source quench\n",
            ctx->dest_addr_str
        );
        break;

    case ICMP_PARAMETERPROB: {
        fprintf(stderr,
            "From %s: ICMP parameter problem\n",
            ctx->dest_addr_str
        );
    } break;

    default: {
        fprintf(stderr,
            "From %s: Invalid ICMP packet type (%d)\n",
            ctx->dest_addr_str,
            header->type
        );
    } break;

    // Not errors
    case ICMP_REDIRECT:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
    case ICMP_INFO_REQUEST:
    case ICMP_INFO_REPLY:
    case ICMP_ADDRESS:
    case ICMP_ADDRESSREPLY:
        break;
    }
}
