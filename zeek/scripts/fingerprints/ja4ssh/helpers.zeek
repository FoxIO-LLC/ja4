module FINGERPRINT::JA4SSH;

event new_connection(c: connection) {

    if(!c?$fp) { c$fp = []; }

     # filter incomplete\out of order connections
    local rp = get_current_packet_header();
    if (!rp?$tcp || rp$tcp$flags != TH_SYN) {
        return;
    }

    ConnThreshold::set_packets_threshold(c,1,F);  # start watching responses
    ConnThreshold::set_packets_threshold(c,2,T);  # start watching new orig packets after this one
}

event ssh_client_version(c: connection, version: string) {
    c$fp$ja4ssh$is_ssh = T;
    c$fp$ja4ssh$ts = c$start_time;
    c$fp$ja4ssh$uid = c$uid;
    c$fp$ja4ssh$id = c$id;
}


event ssh_server_version(c: connection, version: string) {
    c$fp$ja4ssh$is_ssh = T;
    c$fp$ja4ssh$ts = c$start_time;
    c$fp$ja4ssh$uid = c$uid;
    c$fp$ja4ssh$id = c$id;
}