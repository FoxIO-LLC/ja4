module FINGERPRINT::JA4T;

@load ../config
@load ../utils/common

export {
    # TODO: It would be nice to make this on par wtih the tcp_options event
  type TCP_Options: record {
      option_kinds: vector of count &default=vector();
      max_segment_size: count &default=0;
      window_scale: count &default=0;
  };

  # The fingerprint context 
  type Info: record {
    syn_window_size: count &default=0;
    syn_opts: TCP_Options &default=[];
  };

}

redef record FINGERPRINT::Info += {
  ja4t: FINGERPRINT::JA4T::Info &default=[];
};

redef record Conn::Info += {
    ja4t: string &log &default = "";
    ja4ts: string &log &default = "";
};




function get_tcp_options(): TCP_Options {
    local opts: TCP_Options;
    local rph = get_current_packet_header();
    if (!rph?$tcp || rph$tcp$hl <= 20 ) {
        return opts;
    }

    local pkt = get_current_packet();

    print(rph$l2);

    if (rph$l2$encap != LINK_ETHERNET) {
        return opts;
    }

    local offset = 12;
    # handle vlan including triple tagging
    while (offset + 2 < pkt$caplen) {
        local link_header_type = bytestring_to_count(pkt$data[offset:offset+2]);
            print(fmt("0x%x", link_header_type));
        if (link_header_type == 0x8100 || link_header_type == 0x8A88) {
            offset += 4;
            next;
        } else if (link_header_type == 0x0800) {  # IPv4            
            offset += 2 + rph$ip$hl;
            break;
        } else if (link_header_type == 0x86DD) {  # IPv6

            offset += 2 + 40;   # We know we're TCP.  There might be options.
            break;
        } else {
            return opts;  # Not sure where TCP header will start
        }
    }

    local header_end = offset + rph$tcp$hl;
    if (header_end > pkt$caplen) {
        print("WTF");
        return opts;
    }
    offset += 20;  # skip base tcp header
    while(offset < header_end) {
        print(fmt("Offset: %d", offset));
        local opt_kind = bytestring_to_count(pkt$data[offset]);
        if (opt_kind == 0) {
            break;
        }
        opts$option_kinds += opt_kind;
        if (opt_kind == 1  || offset + 1 >= header_end) {
            offset += 1;
            next;
        }
        local opt_len = bytestring_to_count(pkt$data[offset + 1]);

        if (opt_kind == 2 && offset + 3 < header_end) {
            opts$max_segment_size = bytestring_to_count(pkt$data[offset+2:offset+4]);
        }
        if (opt_kind == 3 && offset + 2 < header_end) {
            opts$window_scale = bytestring_to_count(pkt$data[offset+2]);
        }

        offset += opt_len;
    }

    return opts;

}

event new_connection(c: connection) {
       
    local rph = get_current_packet_header();
    if (!rph?$tcp || rph$tcp$flags != TH_SYN) {
        return;  
    }

    if(!c?$fp) { c$fp = []; }
    
    c$fp$ja4t$syn_window_size = rph$tcp$win;
    c$fp$ja4t$syn_opts = get_tcp_options();
    

    ConnThreshold::set_packets_threshold(c,1,F);
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
    # TODO: ja4ts
}

event connection_state_remove(c: connection) {
        c$conn$ja4t =  fmt("%d", c$fp$ja4t$syn_window_size);
        c$conn$ja4t += FINGERPRINT::delimiter;
        c$conn$ja4t += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$syn_opts$option_kinds, "%d", "-");
        c$conn$ja4t += FINGERPRINT::delimiter;
        c$conn$ja4t += fmt("%d", c$fp$ja4t$syn_opts$max_segment_size);
        c$conn$ja4t += FINGERPRINT::delimiter;
        c$conn$ja4t += fmt("%d", c$fp$ja4t$syn_opts$window_scale);
        

        # print(c);
}
