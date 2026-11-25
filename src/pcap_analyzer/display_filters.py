"""The Wireshark display filters the web interface offers. Only these reach tshark, so nothing a user types does.

The CLI still takes any filter, since whoever runs it already runs tshark.
"""

# Filter, then its English label; labels are translated in knowledge/. The empty filter means all packets.
PRESETS = {
    "": "All packets",
    "http || http2": "HTTP and HTTP/2",
    "tls": "TLS",
    "tls.handshake": "TLS handshakes",
    "tls.alert_message": "TLS alerts",
    "dns": "DNS",
    "dns.flags.rcode != 0": "DNS errors",
    "tcp.analysis.flags && !tcp.analysis.window_update": "TCP problems",
    "tcp.analysis.retransmission || tcp.analysis.fast_retransmission": "TCP retransmissions",
    "tcp.analysis.zero_window || tcp.analysis.window_full": "TCP window full or zero",
    "tcp.flags.reset == 1": "TCP resets",
    "tcp.flags.syn == 1 && tcp.flags.ack == 0": "New connections (SYN)",
    "tcp.analysis.ack_rtt > 0.2": "Round trips over 200 ms",
    "http.response.code >= 400 || http2.headers.status >= 400": "HTTP errors (4xx and 5xx)",
    "http.response.code >= 500 || http2.headers.status >= 500": "HTTP server errors (5xx)",
    "http2.type == 3 || http2.type == 7": "HTTP/2 resets and GOAWAY",
    "proxy": "PROXY protocol",
    "icmp || icmpv6": "ICMP",
}


def is_preset(value):
    return (value or "").strip() in PRESETS


def allowed(value):
    """The filter when it is one of the presets, otherwise no filter."""
    v = (value or "").strip()
    return v if v in PRESETS else ""
