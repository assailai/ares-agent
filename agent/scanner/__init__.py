"""Local network-scan pipeline (masscan + raw HTTP probe).

When hunt-agent-manager dispatches a ``task_type=local_network_scan`` row,
this package runs the actual probing on the customer LAN — replacing the
old per-probe path where Ares-side network-scan-service round-tripped
every probe through the WireGuard tunnel.
"""
