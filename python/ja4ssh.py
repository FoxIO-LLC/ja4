# Copyright (c) 2023, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4SSH is licenced under the FoxIO License 1.1. For full license text, see the repo root.

from collections import Counter

ja4sh_stats = {
    'client_payloads': [],
    'server_payloads': [],
    'client_packets': 0,
    'server_packets': 0,
    'client_acks': 0,
    'server_acks': 0
}

def _first(value):
    return value[0] if isinstance(value, list) else value

def _parse_int(value):
    if value is None:
        return None
    try:
        return int(str(value), 0)
    except Exception:
        try:
            return int(str(value))
        except Exception:
            return None

def _int_field(x, key):
    return _parse_int(_first(x.get(key)))

def _direction_from_value(value):
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ('1', 'true', 'server', 'srv', 'to_server', 's'):
            return 'server'
        if s in ('0', 'false', 'client', 'cli', 'to_client', 'c'):
            return 'client'
        return None
    try:
        return 'server' if int(value) == 1 else 'client'
    except Exception:
        return None

def _mode_from_lengths(values):
    if not values:
        return 0
    counts = Counter(values)
    max_count = max(counts.values())
    return min(k for k, v in counts.items() if v == max_count)

def tuple_string (x):
    return f"{x['stream']}: [{x['src']}:{x['srcport']} - {x['dst']}:{x['dstport']}]"

## JA4SSH Processing

def process_extra_parameters(entry, x, direction):
    if 'ssh_extras' not in entry:
        entry['ssh_extras'] = {
		'hassh': '',
                'hassh_server': '',
                'ssh_protocol_client': '',
                'ssh_protocol_server': '',
                'encryption_algorithm': '',
	}
    extras = entry['ssh_extras']
    if 'ssh_protocol' in x:
        extras[f'ssh_protocol_{direction}'] = x['ssh_protocol']
    if 'hassh' in x:
        extras['hassh'] = x['hassh']
    if 'hassh_server' in x:
        extras['hassh_server'] = x['hassh_server']
    if 'algo_client' in x:
        extras['encryption_algorithm'] = x['algo_client'].split(',')[0]
    if 'algo_server' in x:
        extras['encryption_algorithm'] = x['algo_server'].split(',')[0]

## Updates a SSH cache entry
## we return 1 whenever a new stats entry is added based on the sample rate
## This way the caller can print this packet out
def update_ssh_entry(entry, x, ssh_sample_count, debug_stream=None):
    
    if entry['count'] == 0 and len(entry['stats']) == 0:
        entry['stats'].append(dict(ja4sh_stats))

    has_ssh_extras = any(
        key in x
        for key in ('ssh_protocol', 'hassh', 'hassh_server', 'algo_client', 'algo_server')
    )
    has_ssh = ('ssh' in x['protos']) or ('direction' in x) or has_ssh_extras
    tcp_len = _int_field(x, 'len')

    # Count SSH packets
    if has_ssh:
        entry['count'] += 1

    e = entry['stats'][-1]
    direction = _direction_from_value(_first(x.get('direction')))
    if direction is None:
        direction = 'client' if entry['src'] == x['src'] else 'server'

    if has_ssh and tcp_len is not None:
        e[f'{direction}_payloads'].append(tcp_len)
        e[f'{direction}_packets'] += 1

    # Update ACK count based on direction and bare ACKs (no payload)
    flags = _int_field(x, 'flags')
    if (not has_ssh) and flags == 0x0010 and tcp_len == 0:
        if _int_field(x, 'dstport') == 22:
            e['client_acks'] += 1
        elif _int_field(x, 'srcport') == 22:
            e['server_acks'] += 1

    # Added extra output parameters
    if has_ssh:
        process_extra_parameters(entry, x, direction)

    if x['stream'] == debug_stream:
        print (f"stats[{len(entry['stats'])}]:tcp flag = {x['flags']}, c{e['client_packets']}s{e['server_packets']}_c{e['client_acks']}s{e['server_acks']}")

    if (entry['count'] % ssh_sample_count) == 0:
        to_ja4ssh(entry) if entry['count'] != 0 else None
        if (entry['count'] / ssh_sample_count) == len(entry['stats']):
            entry['stats'].append(dict(ja4sh_stats))

        if debug_stream and int(x['stream']) == debug_stream:
            if entry['count'] != 0:
                idx = len(entry['stats']) - 1
                try:
                    computed = entry[f'JA4SSH.{idx}']
                    print (f'computed JA4SSH.{idx}: {computed}')
                except Exception as e:
                    pass

# computes the JA4SSH from the segment x:
# The segment has data as specified by ja4sh_stats
##
def to_ja4ssh(x):
    idx = len(x['stats'])
    e = x['stats'][idx-1]
    if e['client_payloads'] or e['server_payloads']:
        mode_client = _mode_from_lengths(e['client_payloads'])
        mode_server = _mode_from_lengths(e['server_payloads'])
        client_packets = e['client_packets']
        server_packets = e['server_packets']
        client_acks = e['client_acks']
        server_acks = e['server_acks']
        hash_value = f'c{mode_client}s{mode_server}_c{client_packets}s{server_packets}_c{client_acks}s{server_acks}'
        x[f'JA4SSH.{idx}'] = hash_value
        
