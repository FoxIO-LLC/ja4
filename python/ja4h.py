# Copyright (c) 2023, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4H is licenced under the FoxIO License 1.1. For full license text, see the repo root.

from common import sha_encode, cache_update

######### HTTP FUNCTIONS ##############################
def http_method(method):
    return method.lower()[:2]

def http_language(lang):
    lang = lang.replace('-','').replace(';',',').lower().split(',')[0]
    lang = lang[:4]
    return f"{lang}{'0'*(4-len(lang))}"

def to_ja4h(x, debug_stream=-1):
    cookie = 'c' if 'cookies' in x else 'n'
    
    # Ensure headers is a list (tshark may return a string for a single header)
    if isinstance(x['headers'], str):
        # Split by newlines and filter empty lines
        x['headers'] = [h.strip() for h in x['headers'].split('\n') if h.strip()]
    
    header_fields = [y.lower().split(':')[0] for y in x['headers']]
    referer = 'r' if 'referer' in str(header_fields) else 'n'

    method = http_method(x['method'])
    
    # Extract HTTP version from tshark data (HTTP/1.0, HTTP/1.1, etc.)
    if x['hl'] == 'http2':
        version = 20
    elif 'version' in x:
        # Parse version string like "HTTP/1.0" or "HTTP/1.1"
        ver_str = x['version']
        if '/' in ver_str:
            ver_part = ver_str.split('/')[-1]  # "1.0" or "1.1"
            version = ver_part.replace('.', '')  # "10" or "11"
        else:
            version = 11  # Default to 1.1
    else:
        version = 11  # Default to HTTP/1.1
    
    unsorted_cookie_fields = []
    unsorted_cookie_values = []

    x['headers'] = [ h.split(':')[0] for h in x['headers'] ]
    x['headers'] = [ h for h in x['headers']
            if not h.startswith(':') and not h.lower().startswith('cookie')
            and h.lower() != 'referer' and h ]

    raw_headers = x['headers'][:]

    #x['headers'] = [ '-'.join([ y.capitalize() for y in h.split('-')]) for h in x['headers'] ]
    header_len = '{:02d}'.format(min(len(x['headers']), 99))

    if 'cookies' in x:
        if isinstance(x['cookies'], list):
            cookie_pairs = [(y.split('=', 1)[0].strip(), y.strip()) for y in x['cookies']]
        else:
            cookie_pairs = [(y.split('=', 1)[0].strip(), y.strip()) for y in x['cookies'].split(';')]
        
        # Store unsorted versions for _ro output
        unsorted_cookie_fields = [pair[0] for pair in cookie_pairs]
        unsorted_cookie_values = [pair[1] for pair in cookie_pairs]
        
        # Sort by cookie name, then build the sorted lists
        sorted_pairs = sorted(cookie_pairs, key=lambda p: p[0])
        x['cookie_fields'] = [pair[0] for pair in sorted_pairs]
        x['cookie_values'] = [pair[1] for pair in sorted_pairs]

    cookies = sha_encode(x['cookie_fields']) if 'cookies' in x else '0'*12
    cookie_values = sha_encode(x['cookie_values']) if 'cookies' in x else '0'*12

    lang = http_language(x['lang']) if 'lang' in x else '0000'
    headers = sha_encode(x['headers'])
    x['JA4H'] = f'{method}{version}{cookie}{referer}{header_len}{lang}_{headers}_{cookies if len(cookies) else ""}_{cookie_values}'
    x['JA4H_r'] = f"{method}{version}{cookie}{referer}{header_len}{lang}_{','.join(raw_headers)}_"
    x['JA4H_ro'] = f"{method}{version}{cookie}{referer}{header_len}{lang}_{','.join(raw_headers)}_"
    if 'cookie_fields' in x:
        x['JA4H_ro'] += f"{','.join(unsorted_cookie_fields)}_{','.join(unsorted_cookie_values)}"
        x['JA4H_r'] += f"{','.join(x['cookie_fields'])}_{','.join(x['cookie_values'])}"
    cache_update(x, 'JA4H', x['JA4H'], debug_stream)
    cache_update(x, 'JA4H_r', x['JA4H_r'], debug_stream)
    cache_update(x, 'JA4H_ro', x['JA4H_ro'], debug_stream)
    return x

############# END OF HTTP FUNCTIONS ##################
