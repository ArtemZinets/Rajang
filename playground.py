
""" Sample internet packet entry
"timestamp": str(datetime.fromtimestamp(intercepted_packet.time)), # type: ignore
"protocol": protocol,
"origin": (source_ip,source_port),
"destination": (destination_ip,destination_port),
"direction": direction,
"geolocation": geolocate_ip(source_ip),
"url_lookup": reverse_DNS_lookup(source_ip)
"""

""" Sample disk transaction entry
{
    'timestamp': '2025-09-14 12:48:55.419', 
    'event_id': 77894, 
    'executable': 'auditctl -a always,exit -F dir /home -F perm rwx', 
    'syscall': 'sendto', 
    'success': 'yes', 
    'kernel_return': '1064', 
    'arguments': 'a0=0x4 a1=0x7fff52c22280 a2=0x428 a3=0x0', 
    'user_id': 'root', 
    'authed_user_id': 'st2005', 
    'process_id': 82612
}

{
    'timestamp': '2025-09-14 12:45:23.752', 
    'event_id': '75894', 
    'executable': '/usr/share/code/code', 
    'process_accessed_path': '/home/st2005/.config/Code/User/workspaceStorage/a12e361a5a555ce61bde6cd71bc54e7f/', 
    'syscall': 'unlink', 
    'success': 'yes', 
    'kernel_return': '0', 
    'arguments': 'a0=0x384c01ef99da a1=0x384c01ef99da a2=0x0 a3=0x0', 
    'user_id': 'st2005', 
    'authed_user_id': 'st2005', 
    'process_id': '48733'
}
"""