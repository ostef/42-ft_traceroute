#include "ft_traceroute.h"

void TraceRoute(Context *ctx) {
    char readback_buffer[128];

    for (int i = 1; i <= ctx->max_hops; i += 1) {
        struct timeval send_start;
        for (int j = 0; j < Num_Probes; j += 1) {
            SendICMPEchoPacket(ctx, i);
        }

        struct timeval recv_start;
        for (int j = 0; j < Num_Probes; j += 1) {
            int received = ReceiveICMPPacket(ctx, readback_buffer, sizeof(readback_buffer));
            if (received > 0) {
                PrintICMPPacket(ctx, readback_buffer, received, 0);
            }
        }
    }
}
