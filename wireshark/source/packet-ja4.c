/* packet-ja4.c
# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4 is Open-Source, Licensed under BSD 3-Clause
# JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH, JA4T) are licenced under the FoxIO License 1.1.
# For full license text, see the repo root.
*/

#ifndef OOT_BUILD
#include "config.h"
#endif
#include <wireshark.h>

#include <glib.h>
#include <math.h>
#include <wsutil/to_str.h>

#define FIELD_VALUE_IS_PTR \
    ((WIRESHARK_VERSION_MAJOR > 4) || (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR > 1))

#if FIELD_VALUE_IS_PTR
#include <epan/ftypes/ftypes-int.h>
#endif

#ifndef array_length
#define array_length(x) (sizeof(x) / sizeof(x)[0])
#endif

#include <epan/epan_dissect.h>
#include <epan/ftypes/ftypes.h>
#include <epan/oids.h>
#include <epan/packet.h>
#include <epan/packet_info.h>
#include <epan/prefs.h>
#include <epan/tap.h>

#define MAX_SSL_VESION(a, b) ((a) > (b) ? (a) : (b))
#define IS_GREASE_TLS(x) ((((x) & 0x0f0f) == 0x0a0a) && (((x) & 0xff) == (((x) >> 8) & 0xff)))
#define SAMPLE_COUNT 200

static inline fvalue_t *get_value_ptr(field_info *field) {
#if FIELD_VALUE_IS_PTR
    return field->value;
#else
    return &field->value;
#endif
}

static inline const guint8 *field_bytes(fvalue_t const *fv) {
#if ((WIRESHARK_VERSION_MAJOR > 4) || (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR > 1))
    return fvalue_get_bytes_data((fvalue_t *)fv);
#else
    return fv->value.bytes->data;
#endif
}

static int insert_count = 0;
static int tap_display_count = 0;
static int dissector_display_count = 0;

char *bytes_to_string(fvalue_t *fv) {
    return fvalue_to_string_repr(wmem_packet_scope(), fv, FTREPR_DISPLAY, 0);
}

static int proto_ja4;
static int proto_http;
static gint ett_ja4 = -1;
static int hf_ja4s_raw = -1;
static int hf_ja4s = -1;
static int hf_ja4x_raw = -1;
static int hf_ja4x = -1;
static int hf_ja4h = -1;
static int hf_ja4h_raw = -1;
static int hf_ja4h_raw_original = -1;
static int hf_ja4l = -1;
static int hf_ja4l_delta = -1;
static int hf_ja4ls = -1;
static int hf_ja4ls_delta = -1;
static int hf_ja4ssh = -1;
static int hf_ja4t = -1;
static int hf_ja4ts = -1;
static int hf_ja4d = -1;

static int dissect_ja4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *dummy);

static dissector_handle_t ja4_handle;

static bool pref_omit_ja4h_zero_sections = FALSE;

const value_string ssl_versions[] = {
    {0x0002, "s2"},
    {0x0300, "s3"},
    {0x0301, "10"},
    {0x0302, "11"},
    {0x0303, "12"},
    {0x0304, "13"},
    {0xFEFF, "d1"},
    {0xFEFD, "d2"},
    {0xFEFC, "d3"},
    {0x00,   NULL}
};

#define HFIDS 61
const char *interesting_hfids[HFIDS] = {
    "tls.handshake.type",
    "dtls.handshake.type",
    "tls.handshake.version",
    "dtls.record.version",
    "tls.handshake.extension.type",
    "dtls.handshake.extension.type",
    "tls.handshake.ciphersuite",
    "dtls.handshake.ciphersuite",
    "tls.handshake.extensions.supported_version",
    "dtls.handshake.extensions.supported_version",
    "tls.handshake.sig_hash_alg",
    "dtls.handshake.sig_hash_alg",
    "tls.handshake.extensions_alpn_str",
    "dtls.handshake.extensions_alpn_str",
    "tls.handshake.certificate",
    "dtls.handshake.certificate",
    "x509if.oid",
    "x509af.issuer",
    "x509af.subject",
    "x509af.validity_element",
    "x509af.extension.id",
    "http.request.method",
    "http.request.version",
    "http.accept_language",
    "http.cookie",
    "http.cookie_pair",
    "http.referer",
    "http.request.line",
    "http2.headers.method",
    "http2.headers.accept_language",
    "http2.headers.cookie",
    "http2.headers.referer",
    "http2.header.name",
    "ip.ttl",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.len",
    "tcp.ack",
    "tcp.seq",
    "tcp.flags.ack",
    "tcp.flags",
    "tcp.option_kind",
    "tcp.options.mss_val",
    "tcp.options.wscale.shift",
    "tcp.window_size_value",
    "udp.stream",
    "udp.srcport",
    "udp.dstport",
    "frame.time_epoch",
    "frame.time_delta_displayed",
    "ssh.direction",
    "quic.long.packet_type",
    "dhcp.option.dhcp",
    "dhcp.option.dhcp_max_message_size",
    "dhcp.option.type",
    "dhcp.option.request_list_item",
    "dhcpv6.msgtype",
    "dhcpv6.duid.bytes",
    "dhcpv6.option.type",
    "dhcpv6.requested_option_code",
};

typedef struct {
    gchar proto;
    guint32 version;
    gboolean sni;    // only for JA4 client
    gint cipher_len; // only for ja4 client
    gint ext_len;
    wmem_strbuf_t *alpn;
    wmem_strbuf_t *ciphers;
    wmem_strbuf_t *extensions;
    wmem_list_t *sorted_ciphers;    // only for ja4 client
    wmem_list_t *sorted_extensions; // only for ja4 client
    wmem_strbuf_t *signatures;      // only for ja4 client
} ja4_info_t;

typedef struct {
    wmem_strbuf_t *field;
    wmem_strbuf_t *value;
} http_cookie_t;

typedef struct {
    wmem_strbuf_t *version;
    wmem_strbuf_t *method;
    wmem_strbuf_t *headers;
    wmem_strbuf_t *lang;
    wmem_list_t *sorted_cookies;
    wmem_strbuf_t *unsorted_cookie_fields;
    wmem_strbuf_t *unsorted_cookie_values;
    wmem_strbuf_t *sorted_cookie_fields;
    wmem_strbuf_t *sorted_cookie_values;
    int num_headers;
    gboolean cookie;
    gboolean referer;
    gboolean http2;
} ja4h_info_t;

typedef struct {
    wmem_strbuf_t *tcp_options;
    int mss_val;
    int window_scale;
    int window_size;
} ja4t_info_t;

typedef struct {
    gchar proto;
    guint32 type;
    wmem_strbuf_t *size;
    wmem_strbuf_t *options;
    wmem_strbuf_t *request_list;
} ja4d_info_t;

typedef struct {
    int stream;

    // Used for ja4l
    nstime_t timestamp_A;
    nstime_t timestamp_B;
    nstime_t timestamp_C;
    nstime_t timestamp_D;
    nstime_t timestamp_E;
    nstime_t timestamp_F;

    int client_ttl;
    int server_ttl;
    int client_latency;
    int server_latency;

    // Added for JA4T RST issue
    int mss_val;
    int window_scale;
    int window_size;
    wmem_strbuf_t *tcp_options;

    // used for Ja4TS
#define MAX_SYN_ACK_TIMES 10
    nstime_t syn_ack_times[MAX_SYN_ACK_TIMES];
    nstime_t rst_time;
    int syn_ack_count;

    // used for ja4ssh
    int pkts;
    int client_pkts;
    int server_pkts;
    int tcp_client_acks;
    int tcp_server_acks;
    wmem_map_t *client_mode;
    wmem_map_t *server_mode;

} conn_info_t;

typedef struct {
    wmem_strbuf_t *oids[3];
    wmem_strbuf_t *raw;
    wmem_strbuf_t *hash;
} cert_t;

typedef struct {
    int hf_field;
    wmem_strbuf_t *hf_value;
} packet_hash_t;

typedef struct {
    int frame_number;
    int num_of_hashes;
    wmem_array_t *pkt_hashes;
    bool complete;
    char *insert_at;
} pkt_info_t;

wmem_map_t *conn_hash = NULL;
wmem_map_t *quic_conn_hash = NULL;
wmem_map_t *packet_table = NULL;

static int64_t timediff(nstime_t *current, nstime_t *prev) {
    nstime_t result;
    nstime_delta(&result, current, prev);
    return (int64_t)(round(nstime_to_sec(&result)));
}

gint sort_by_string(gconstpointer s1, gconstpointer s2) {
    return strcmp(
        wmem_strbuf_get_str(((http_cookie_t *)s1)->field),
        wmem_strbuf_get_str(((http_cookie_t *)s2)->field)
    );
}

proto_tree *locate_tree(proto_tree *tree, const char *s) {
    proto_tree *position = tree->first_child;
    while ((position != NULL) && (position->finfo != NULL) &&
           (strcmp(position->finfo->hfinfo->abbrev, s) != 0)) {
        position = position->next;
    }
    return position;
}

pkt_info_t *packet_table_lookup(int frame_number) {
    pkt_info_t *data = wmem_map_lookup(packet_table, GINT_TO_POINTER(frame_number));
    if (data == NULL) {
        data = wmem_new0(wmem_file_scope(), pkt_info_t);
        data->pkt_hashes = wmem_array_new(wmem_file_scope(), 100);
        data->frame_number = frame_number;
        data->num_of_hashes = 0;
        data->complete = false;
        data->insert_at = NULL;
        wmem_map_insert(packet_table, GINT_TO_POINTER(frame_number), data);
    }
    return data;
}

void update_tree_item(
    tvbuff_t *tvb, proto_tree *tree, proto_tree **ja4_tree, int field,
    const void *data, const char *insert_at
) {

    // We get to the right part of the tree using locate_tree and insert the
    // hash there.

    proto_item *ja4_ti;

    if (*ja4_tree == NULL) {
        proto_tree *tree_location = locate_tree(tree, insert_at);

        if (tree_location == NULL)
            return;

        ja4_ti = proto_tree_add_item(tree_location, proto_ja4, tvb, 0, -1, ENC_NA);
        *ja4_tree = proto_item_add_subtree(ja4_ti, ett_ja4);
    }

    enum ftenum type = proto_registrar_get_ftype(field);
    if (type == FT_STRING) {
        proto_tree_add_string(*ja4_tree, field, NULL, 0, 0, (const char *)data);
    } else if (type == FT_DOUBLE) {
        proto_tree_add_double(*ja4_tree, field, NULL, 0, 0, *(const double *)data);
    }
}

// Replace the existing update_tree_item with the packet table version
void update_tree_item_with_table(
    int frame_number, tvbuff_t *tvb, proto_tree *tree, proto_tree **ja4_tree, int field,
    const char *str, const char *insert_at
) {
    // Store in packet table for column display
    pkt_info_t *pi = packet_table_lookup(frame_number);
    if (!pi->complete) {
        packet_hash_t *recorded_hash = wmem_new0(wmem_file_scope(), packet_hash_t);
        recorded_hash->hf_field = field;
        recorded_hash->hf_value = wmem_strbuf_new(wmem_file_scope(), (char *)str);
        ws_warning("Storing hash %s for field %d for frame %d\n", str, field, frame_number);
        ws_warning("JA4: dissect frame %u tree=%p", frame_number, tree);
        wmem_array_append(pi->pkt_hashes, recorded_hash, 1);
        pi->num_of_hashes++;
        pi->insert_at = (char *)insert_at;
    }
}

void mark_complete(int frame_number) {
    pkt_info_t *pi = packet_table_lookup(frame_number);
    pi->complete = true;
}

// Wireshark columns only work if the hash is added to the tree and displayed
// using proto_tree_add_string without using proto_item_append_text
// Tshark OTOH takes both values from the JA4 tree as well as from here to show them
// when using the -T fields option
static int
display_hashes_from_packet_table(int hash_val, proto_tree *tree, tvbuff_t *tvb, int frame_number) {
    pkt_info_t *pi = packet_table_lookup(frame_number);
    if ((pi->complete) && (pi->insert_at)) {
        proto_tree *tree_location = locate_tree(tree, pi->insert_at);
        if (tree_location == NULL)
            return 0;

        proto_tree *sub_tree = NULL;
        proto_tree *child = tree_location->first_child;
        while (child) {
            if (child->finfo->hfinfo &&
                (strcmp(child->finfo->hfinfo->abbrev, "ja4") == 0 ||
                 strncmp(child->finfo->hfinfo->abbrev, "ja4.", 4) == 0)) {
                // Found an existing JA4 subtree
                ws_warning("Found existing JA4 subtree for frame %u tree=%p", frame_number, tree);
                sub_tree = child;
                break;
            }
            child = child->next;
        }
        if (sub_tree == NULL) {
            ws_warning("Adding JA4 subtree for frame %u tree=%p", frame_number, tree);
            proto_item *ja4_ti = proto_tree_add_item(tree_location, proto_ja4, tvb, 0, -1, ENC_NA);
            sub_tree = proto_item_add_subtree(ja4_ti, ett_ja4);
        }
        
        for (int i = 0; i < pi->num_of_hashes; i++) {
            packet_hash_t *hash = (packet_hash_t *)wmem_array_index(pi->pkt_hashes, i);
            if ((hash->hf_field == hash_val) || (hash_val == 999)) {
                proto_tree_add_string(sub_tree, hash->hf_field, NULL, 0, 0, wmem_strbuf_get_str(hash->hf_value));
                ws_warning(
                    "Displaying hash %s for field %d for frame %d\n",
                    wmem_strbuf_get_str(hash->hf_value), hash->hf_field, frame_number
                );
                ws_warning("JA4: dissect frame %u tree=%p", frame_number, tree);
            }
        }
        return pi->num_of_hashes;
    }
    return 0;
}

void update_mode(int pkt_len, wmem_map_t *hash_table) {
    int counter = GPOINTER_TO_INT(wmem_map_lookup(hash_table, GINT_TO_POINTER(pkt_len)));
    if (counter == 0) {
        wmem_map_insert(hash_table, GINT_TO_POINTER(pkt_len), GINT_TO_POINTER(1));
    } else {
        counter++;
        wmem_map_insert(hash_table, GINT_TO_POINTER(pkt_len), GINT_TO_POINTER(counter));
    }
}

int get_max_mode(wmem_allocator_t *scratch, wmem_map_t *hash_table) {
    int counter = 0;
    int max_mode = 0;
    wmem_list_t *keys = wmem_map_get_keys(scratch, hash_table);
    wmem_list_frame_t *key = wmem_list_head(keys);
    while (key) {
        int pkt_len = GPOINTER_TO_INT(wmem_list_frame_data(key));
        int mode = GPOINTER_TO_INT(wmem_map_lookup(hash_table, GINT_TO_POINTER(pkt_len)));
        if (mode > counter) {
            counter = mode;
            max_mode = pkt_len;
        } else if (mode == counter) {
            if (pkt_len < max_mode) {
                max_mode = pkt_len;
            }
        }
        key = wmem_list_frame_next(key);
    }
    return max_mode;
}

conn_info_t *conn_lookup(char proto, int stream) {

    wmem_map_t *conn = NULL;
    if (proto == 'q') {
        conn = quic_conn_hash;
    } else {
        conn = conn_hash;
    }

    conn_info_t *data = wmem_map_lookup(conn, GINT_TO_POINTER(stream));
    if (data == NULL) {
        data = wmem_new0(wmem_file_scope(), conn_info_t);
        data->stream = stream;
        data->pkts = 0;
        data->client_pkts = 0;
        data->server_pkts = 0;
        data->tcp_client_acks = 0;
        data->tcp_server_acks = 0;
        data->tcp_options = NULL;

        nstime_set_zero(&data->timestamp_A);
        nstime_set_zero(&data->timestamp_B);
        nstime_set_zero(&data->timestamp_C);
        nstime_set_zero(&data->timestamp_D);
        nstime_set_zero(&data->timestamp_E);
        nstime_set_zero(&data->timestamp_F);
        nstime_set_zero(&data->rst_time);

        data->syn_ack_count = 0;
        for (int i = 0; i < MAX_SYN_ACK_TIMES; i++) {
            nstime_set_zero(&data->syn_ack_times[i]);
        }

        data->client_ttl = 0;
        data->server_ttl = 0;
        data->client_mode = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        data->server_mode = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        wmem_map_insert(conn, GINT_TO_POINTER(stream), data);
    }
    return data;
}

void decode_http_lang(wmem_allocator_t *scope, wmem_strbuf_t **out, const char *val) {
    wmem_strbuf_t *lang = wmem_strbuf_new(scope, "");
    int count = 0;

    // Format the language string
    for (int i = 0; i < 5; i++) {
        if ((val[i] == ',') || (val[i] == ';') || (count >= 4) || (val[i] == '\0')) {
            break;
        }
        if ((g_ascii_isspace(val[i])) || (val[i] == '-')) {
            continue;
        }
        if (g_ascii_isalpha(val[i])) {
            wmem_strbuf_append_c(lang, g_ascii_tolower(val[i]));
            count++;
        } else {
            // Convert a non-alpha character to hex
            static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            wmem_strbuf_append_c(lang, hex[(val[i] >> 4) & 0xF]);
            wmem_strbuf_append_c(lang, hex[(val[i] >> 0) & 0xF]);
            count += 2;
        }
    }

    // Ensure we have 4 characters
    if (count < 4) {
        wmem_strbuf_append_c_count(lang, '0', 4 - count);
    }
    wmem_strbuf_truncate(lang, 4);

    wmem_strbuf_append_printf(*out, "%s", wmem_strbuf_get_str(lang));

    wmem_strbuf_destroy(lang);
}

void decode_http_version(wmem_strbuf_t **out, const char *val) {
    gchar **strings;
    strings = g_strsplit(val, "/", 2);
    if (strings[1] != NULL) {
        for (int i = 0; i < (int)strlen(strings[1]); i++) {
            if (strings[1][i] != '.') {
                wmem_strbuf_append_c(*out, g_ascii_tolower(strings[1][i]));
            }
        }

        if (wmem_strbuf_get_len(*out) <= 1) {
            wmem_strbuf_append(*out, "0");
        }
    }
}

void create_sorted_cookies(wmem_strbuf_t **fields, wmem_strbuf_t **values, wmem_list_t *l) {
    wmem_list_frame_t *curr_entry = wmem_list_head(l);
    http_cookie_t *curr_cookie = NULL;
    while (curr_entry && wmem_list_frame_next(curr_entry)) {
        curr_cookie = wmem_list_frame_data(curr_entry);
        wmem_strbuf_append_printf(*fields, "%s,", wmem_strbuf_get_str(curr_cookie->field));
        wmem_strbuf_append_printf(
            *values, "%s=%s,", wmem_strbuf_get_str(curr_cookie->field),
            wmem_strbuf_get_str(curr_cookie->value)
        );
        curr_entry = wmem_list_frame_next(curr_entry);
    }

    // Append last entry without a trailing comma
    curr_cookie = wmem_list_frame_data(curr_entry);
    wmem_strbuf_append(*fields, wmem_strbuf_get_str(curr_cookie->field));
    wmem_strbuf_append_printf(
        *values, "%s=%s", wmem_strbuf_get_str(curr_cookie->field),
        wmem_strbuf_get_str(curr_cookie->value)
    );
}

char *ja4s_r(wmem_allocator_t *scope, ja4_info_t *data) {
    wmem_strbuf_t *display = wmem_strbuf_new(scope, "");
    wmem_strbuf_append_printf(
        display, "%c%s%02d%c%c_%s_%s", data->proto,
        val_to_str_const(data->version, ssl_versions, "00"), data->ext_len,
        (wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[0] : '0',
        (wmem_strbuf_get_len(data->alpn) > 0)
            ? wmem_strbuf_get_str(data->alpn)[wmem_strbuf_get_len(data->alpn) - 1]
            : '0',
        wmem_strbuf_get_str(data->ciphers), wmem_strbuf_get_str(data->extensions)
    );
    return wmem_strbuf_finalize(display);
}

char *ja4s(wmem_allocator_t *scope, ja4_info_t *data) {
    wmem_strbuf_t *display = wmem_strbuf_new(scope, "");
    gchar *_hash =
        g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(data->extensions), -1);
    wmem_strbuf_append_printf(
        display, "%c%s%02d%c%c_%s_%12.12s", data->proto,
        val_to_str_const(data->version, ssl_versions, "00"), data->ext_len,
        (wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[0] : '0',
        (wmem_strbuf_get_len(data->alpn) > 0)
            ? wmem_strbuf_get_str(data->alpn)[wmem_strbuf_get_len(data->alpn) - 1]
            : '0',
        wmem_strbuf_get_str(data->ciphers),
        wmem_strbuf_get_len(data->extensions) ? _hash : "000000000000"
    );
    if (_hash != NULL)
        g_free(_hash);
    return wmem_strbuf_finalize(display);
}

char *ja4x(wmem_allocator_t *scope, cert_t *cert) {
    wmem_strbuf_t *display = wmem_strbuf_new(scope, "");
    gchar *hash1 =
        g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(cert->oids[0]), -1);
    gchar *hash2 =
        g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(cert->oids[1]), -1);
    gchar *hash3 =
        g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(cert->oids[2]), -1);
    wmem_strbuf_append_printf(
        display, "%12.12s_%12.12s_%12.12s",
        wmem_strbuf_get_len(cert->oids[0]) ? hash1 : "000000000000",
        wmem_strbuf_get_len(cert->oids[1]) ? hash2 : "000000000000",
        wmem_strbuf_get_len(cert->oids[2]) ? hash3 : "000000000000"
    );
    if (hash1 != NULL)
        g_free(hash1);
    if (hash2 != NULL)
        g_free(hash2);
    if (hash3 != NULL)
        g_free(hash3);
    return wmem_strbuf_finalize(display);
}

char *ja4h_r(wmem_allocator_t *scope, ja4h_info_t *data) {
    wmem_strbuf_t *display = wmem_strbuf_new(scope, "");
    wmem_strbuf_append_printf(
        display, "%s%s%s%s%02d%s_%s_%s_%s", wmem_strbuf_get_str(data->method),
        wmem_strbuf_get_str(data->version), data->cookie ? "c" : "n", data->referer ? "r" : "n",
        data->num_headers, wmem_strbuf_get_str(data->lang), wmem_strbuf_get_str(data->headers),
        wmem_strbuf_get_str(data->sorted_cookie_fields),
        wmem_strbuf_get_str(data->sorted_cookie_values)
    );
    return wmem_strbuf_finalize(display);
}

char *ja4h_ro(wmem_allocator_t *scope, ja4h_info_t *data) {
    wmem_strbuf_t *display = wmem_strbuf_new(scope, "");
    wmem_strbuf_append_printf(
        display, "%s%s%s%s%02d%s_%s_%s_%s", wmem_strbuf_get_str(data->method),
        wmem_strbuf_get_str(data->version), data->cookie ? "c" : "n", data->referer ? "r" : "n",
        data->num_headers, wmem_strbuf_get_str(data->lang), wmem_strbuf_get_str(data->headers),
        wmem_strbuf_get_str(data->unsorted_cookie_fields),
        wmem_strbuf_get_str(data->unsorted_cookie_values)
    );
    return wmem_strbuf_finalize(display);
}

char *ja4h(wmem_allocator_t *scope, ja4h_info_t *data) {
    wmem_strbuf_t *display = wmem_strbuf_new(scope, "");
    gchar *hash1 =
        g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(data->headers), -1);
    gchar *hash2 = g_compute_checksum_for_string(
        G_CHECKSUM_SHA256, wmem_strbuf_get_str(data->sorted_cookie_fields), -1
    );
    gchar *hash3 = g_compute_checksum_for_string(
        G_CHECKSUM_SHA256, wmem_strbuf_get_str(data->sorted_cookie_values), -1
    );
    const char *zero_hash = pref_omit_ja4h_zero_sections ? "" : "000000000000";
    wmem_strbuf_append_printf(
        display, "%s%s%s%s%02d%s_%12.12s_%.12s_%.12s", wmem_strbuf_get_str(data->method),
        wmem_strbuf_get_str(data->version), data->cookie ? "c" : "n", data->referer ? "r" : "n",
        data->num_headers, wmem_strbuf_get_str(data->lang), hash1, data->cookie ? hash2 : zero_hash,
        data->cookie ? hash3 : zero_hash
    );
    if (hash1 != NULL)
        g_free(hash1);
    if (hash2 != NULL)
        g_free(hash2);
    if (hash3 != NULL)
        g_free(hash3);
    return wmem_strbuf_finalize(display);
}

char *ja4ssh(wmem_allocator_t *scope, conn_info_t *conn) {
    wmem_strbuf_t *display = wmem_strbuf_new(scope, "");
    wmem_strbuf_append_printf(
        display, "c%ds%d_c%ds%d_c%ds%d", get_max_mode(scope, conn->client_mode),
        get_max_mode(scope, conn->server_mode), conn->client_pkts, conn->server_pkts,
        conn->tcp_client_acks, conn->tcp_server_acks
    );
    return wmem_strbuf_finalize(display);
}

// Compute JA4T
char *ja4t(wmem_allocator_t *scope, ja4t_info_t *data, conn_info_t *conn) {
    wmem_strbuf_t *display = wmem_strbuf_new(scope, "");
    if (wmem_strbuf_get_len(data->tcp_options) > 0)
        wmem_strbuf_truncate(data->tcp_options, wmem_strbuf_get_len(data->tcp_options) - 1);
    if (data->window_scale == 0) {
        wmem_strbuf_append_printf(
            display, "%d_%s_%02d_%02d", data->window_size,
            (wmem_strbuf_get_len(data->tcp_options) == 0) ? "00"
                                                          : wmem_strbuf_get_str(data->tcp_options),
            data->mss_val, data->window_scale
        );
    } else {
        wmem_strbuf_append_printf(
            display, "%d_%s_%02d_%d", data->window_size,
            (wmem_strbuf_get_len(data->tcp_options) == 0) ? "00"
                                                          : wmem_strbuf_get_str(data->tcp_options),
            data->mss_val, data->window_scale
        );
    }

    if ((conn != NULL) && (conn->syn_ack_count > 1)) {
        wmem_strbuf_append_c(display, '_');
        for (int i = 1; i < conn->syn_ack_count; i++) {
            int64_t diff = timediff(&conn->syn_ack_times[i], &conn->syn_ack_times[i - 1]);
            wmem_strbuf_append_printf(display, "%" PRId64, diff);
            if (i < (conn->syn_ack_count - 1)) {
                wmem_strbuf_append_c(display, '-');
            }
        }
        if (!nstime_is_zero(&conn->rst_time)) {
            int64_t diff = timediff(&conn->rst_time, &conn->syn_ack_times[conn->syn_ack_count - 1]);
            wmem_strbuf_append_printf(display, "-R%" PRId64, diff);
        }
    }

    return wmem_strbuf_finalize(display);
}

char *ja4d(wmem_allocator_t *scope, ja4d_info_t *data) {
    wmem_strbuf_t *display = wmem_strbuf_new(scope, "");
    if (wmem_strbuf_get_len(data->size) == 0)
        wmem_strbuf_append_printf(data->size, "00");
    if (wmem_strbuf_get_len(data->options) == 0)
        wmem_strbuf_append_printf(data->options, "00");
    if (wmem_strbuf_get_len(data->request_list) == 0)
        wmem_strbuf_append_printf(data->request_list, "00");
    wmem_strbuf_append_printf(
        display, "%c-%d-%s_%s_%s",
        data->proto,
        data->type,
        wmem_strbuf_get_str(data->size),
        wmem_strbuf_get_str(data->options),
        wmem_strbuf_get_str(data->request_list)
    );
    return wmem_strbuf_finalize(display);
}

static void init_ja4_data(packet_info *pinfo, ja4_info_t *ja4_data) {
    ja4_data->version = 0;
    ja4_data->ext_len = 0;
    ja4_data->cipher_len = 0;
    ja4_data->sni = false;
    ja4_data->proto = proto_is_frame_protocol(pinfo->layers, "tcp") ? 't' : 'q';

    if (proto_is_frame_protocol(pinfo->layers, "dtls"))
        ja4_data->proto = 'd';

    ja4_data->sorted_ciphers = wmem_list_new(pinfo->pool);
    ja4_data->sorted_extensions = wmem_list_new(pinfo->pool);
    ja4_data->ciphers = wmem_strbuf_new(pinfo->pool, "");
    ja4_data->extensions = wmem_strbuf_new(pinfo->pool, "");
    ja4_data->signatures = wmem_strbuf_new(pinfo->pool, "");
    ja4_data->alpn = wmem_strbuf_new(pinfo->pool, "");
}

static void set_ja4s_extensions(proto_tree *tree, ja4_info_t *data) {
    guint value;
    GPtrArray *items;
    if (data->proto == 'd') {
        items =
            proto_find_finfo(tree, proto_registrar_get_id_byname("dtls.handshake.extension.type"));
    } else {
        items =
            proto_find_finfo(tree, proto_registrar_get_id_byname("tls.handshake.extension.type"));
    }
    if (items) {
        guint i;
        for (i = 0; i < items->len; i++) {
            field_info *field = (field_info *)g_ptr_array_index(items, i);
            value = fvalue_get_uinteger(get_value_ptr(field));
            if (!IS_GREASE_TLS(value)) {
                wmem_list_insert_sorted(
                    data->sorted_extensions, GUINT_TO_POINTER(value), wmem_compare_uint
                );
                wmem_strbuf_append_printf(data->extensions, "%04x,", value);

                if (value == 0x0000)
                    data->sni = true;
                data->ext_len++;
            }
        }
        g_ptr_array_free(items, TRUE);
    }
    if (wmem_strbuf_get_len(data->extensions) > 3) {
        wmem_strbuf_truncate(data->extensions, wmem_strbuf_get_len(data->extensions) - 1);
    }
}

static void set_ja4_ciphers(proto_tree *tree, ja4_info_t *data) {
    guint value;
    GPtrArray *items;
    if (data->proto == 'd') {
        items = proto_find_finfo(tree, proto_registrar_get_id_byname("dtls.handshake.ciphersuite"));
    } else {
        items = proto_find_finfo(tree, proto_registrar_get_id_byname("tls.handshake.ciphersuite"));
    }

    if (items) {
        guint i;
        for (i = 0; i < items->len; i++) {
            field_info *field = (field_info *)g_ptr_array_index(items, i);
            value = fvalue_get_uinteger(get_value_ptr(field));
            if (!IS_GREASE_TLS(value)) {
                wmem_list_insert_sorted(
                    data->sorted_ciphers, GUINT_TO_POINTER(value), wmem_compare_uint
                );
                wmem_strbuf_append_printf(data->ciphers, "%04x,", value);
                data->cipher_len++;
            }
        }
        g_ptr_array_free(items, TRUE);
    }
    if (wmem_strbuf_get_len(data->ciphers) > 3) {
        wmem_strbuf_truncate(data->ciphers, wmem_strbuf_get_len(data->ciphers) - 1);
    }
}

static int dissect_ja4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *dummy _U_) {
    guint32 handshake_type = 0;
    gboolean alpn_visited = false;
    gboolean dhcpv6_option_type_1_exists = false;
    proto_tree *ja4_tree = NULL;

    // For JA4C/S, record signature algorithms only when extension type == 13
    int record_signatures = 0;

    // For JA4X
    guint cert_num = -1;
    guint oid_type = -1;
    wmem_array_t *certificate_list = wmem_array_sized_new(pinfo->pool, sizeof(cert_t), 100);

    // For JA4H
    gchar **strings;
    int http_req = -100;

    // packet level stuff
    int curr_ttl = 0;
    int stream = 0;
    int srcport = 0;
    int dstport = 0;
    int tcp_len = 0;
    nstime_t latency;
    nstime_t latency2;

    nstime_t *packet_time = NULL;
    int seq = 0;
    int ack = 0;
    int syn = 0;

    if (tree == NULL)
        return tvb_captured_length(tvb);

    g_warning("JA4H dissector display count: %d", dissector_display_count++);
    int hashes = display_hashes_from_packet_table(999, tree, tvb, pinfo->num);
    if (hashes > 0)
        return tvb_captured_length(tvb);

    ja4_info_t ja4_data;
    init_ja4_data(pinfo, &ja4_data);

    ja4h_info_t ja4h_data;
    ja4h_data.version = wmem_strbuf_new(pinfo->pool, "");
    ja4h_data.headers = wmem_strbuf_new(pinfo->pool, "");
    ja4h_data.lang = wmem_strbuf_new(pinfo->pool, "");
    ja4h_data.method = wmem_strbuf_new(pinfo->pool, "");
    ja4h_data.cookie = false;
    ja4h_data.referer = false;
    ja4h_data.http2 = false;
    ja4h_data.num_headers = 0;
    ja4h_data.sorted_cookies = wmem_list_new(pinfo->pool);
    ja4h_data.unsorted_cookie_fields = wmem_strbuf_new(pinfo->pool, "");
    ja4h_data.unsorted_cookie_values = wmem_strbuf_new(pinfo->pool, "");
    ja4h_data.sorted_cookie_fields = wmem_strbuf_new(pinfo->pool, "");
    ja4h_data.sorted_cookie_values = wmem_strbuf_new(pinfo->pool, "");

    ja4t_info_t ja4t_data;
    ja4t_data.tcp_options = wmem_strbuf_new(pinfo->pool, "");
    ja4t_data.mss_val = 0;
    ja4t_data.window_scale = 0;
    ja4t_data.window_size = 0;

    ja4d_info_t ja4d_data;
    ja4d_data.proto = 0;
    ja4d_data.type = 0;
    ja4d_data.size = wmem_strbuf_new(pinfo->pool, "");
    ja4d_data.options = wmem_strbuf_new(pinfo->pool, "");
    ja4d_data.request_list = wmem_strbuf_new(pinfo->pool, "");

    char *proto = "tls";
    switch (ja4_data.proto) {
        case 'q': {
            proto = "quic";
            break;
        }
        case 'd': {
            proto = "dtls";
            break;
        }
        default: {
            proto = "tls";
        }
    }

    GPtrArray *items = proto_all_finfos(tree);
    if (items != NULL) {
        for (guint item_idx = 0; item_idx < items->len; item_idx++) {
            field_info *field = (field_info *)g_ptr_array_index(items, item_idx);

            if ((strcmp(field->hfinfo->abbrev, "tls.handshake.type") == 0) ||
                (strcmp(field->hfinfo->abbrev, "dtls.handshake.type") == 0)) {
                // DTLS has server hellos together with certificates. so
                // we need to compute ja4s and then go on to compute ja4x
                if (handshake_type == 2) {
                    set_ja4_ciphers(tree, &ja4_data);
                    set_ja4s_extensions(tree, &ja4_data);
                    update_tree_item(
                        tvb, tree, &ja4_tree, hf_ja4s, ja4s(pinfo->pool, &ja4_data), proto
                    );
                    update_tree_item(
                        tvb, tree, &ja4_tree, hf_ja4s_raw, ja4s_r(pinfo->pool, &ja4_data), proto
                    );
                }

                // Again for DTLS, we break
                if (handshake_type == 11)
                    break;

                handshake_type = fvalue_get_uinteger(get_value_ptr(field));
            }

            if ((strcmp(field->hfinfo->abbrev, "tls.handshake.version") == 0) ||
                (strcmp(field->hfinfo->abbrev, "dtls.record.version") == 0)) {
                ja4_data.version = fvalue_get_uinteger(get_value_ptr(field));
            }

            if ((strcmp(field->hfinfo->abbrev, "tls.handshake.extension.type") == 0) ||
                (strcmp(field->hfinfo->abbrev, "dtls.handshake.extension.type") == 0)) {
                if (fvalue_get_uinteger(get_value_ptr(field)) == 13) {
                    record_signatures = 1;
                } else {
                    record_signatures = 0;
                }
            }

            if ((strcmp(field->hfinfo->abbrev, "tls.handshake.sig_hash_alg") == 0) ||
                (strcmp(field->hfinfo->abbrev, "dtls.handshake.sig_hash_alg") == 0)) {
                if (record_signatures == 1) {
                    wmem_strbuf_append_printf(
                        ja4_data.signatures, "%04x,", fvalue_get_uinteger(get_value_ptr(field))
                    );
                }
            }

            if ((strcmp(field->hfinfo->abbrev, "tls.handshake.extensions.supported_version") == 0
                ) ||
                (strcmp(field->hfinfo->abbrev, "dtls.handshake.extensions.supported_version") == 0
                )) {
                if (!IS_GREASE_TLS(fvalue_get_uinteger(get_value_ptr(field)))) {
                    ja4_data.version =
                        MAX_SSL_VESION(ja4_data.version, fvalue_get_uinteger(get_value_ptr(field)));
                }
            }

            if ((strcmp(field->hfinfo->abbrev, "tls.handshake.extensions_alpn_str") == 0) ||
                (strcmp(field->hfinfo->abbrev, "dtls.handshake.extensions_alpn_str") == 0)) {
                if (!alpn_visited) {
                    const char *alpn_str = fvalue_get_string(get_value_ptr(field));
                    if (!g_ascii_isalnum(alpn_str[0])) {
                        wmem_strbuf_append(ja4_data.alpn, "99");
                    } else {
                        wmem_strbuf_append(ja4_data.alpn, alpn_str);
                    }
                    alpn_visited = true;
                }
            }

            // JA4X specifiers
            if ((strcmp(field->hfinfo->abbrev, "tls.handshake.certificate") == 0) ||
                (strcmp(field->hfinfo->abbrev, "dtls.handshake.certificate") == 0)) {
                cert_t cert;
                for (guint n = 0; n < 3; n++) {
                    cert.oids[n] = wmem_strbuf_new(pinfo->pool, "");
                }
                cert.raw = wmem_strbuf_new(pinfo->pool, "");
                wmem_array_append_one(certificate_list, cert);
                oid_type = 0;
                cert_num++;
            }

            if (strcmp(field->hfinfo->abbrev, "x509af.validity_element") == 0) {
                oid_type = 1;
            }

            if ((strcmp(field->hfinfo->abbrev, "x509if.oid") == 0) && (handshake_type == 11)) {
                cert_t *current_cert = (cert_t *)wmem_array_index(certificate_list, cert_num);

                // Append a comma to previous OIDs, if any
                if (wmem_strbuf_get_len(current_cert->oids[oid_type])) {
                    wmem_strbuf_append(current_cert->oids[oid_type], ",");
                }
                // BUG-FIX: Ja4x should use Hex codes instead of ascii
                const guint8 *bytes = field_bytes(get_value_ptr(field));
                for (gint j = 0; j < field->length; j++) {
                    wmem_strbuf_append_printf(current_cert->oids[oid_type], "%02x", bytes[j]);
                }
            }

            if ((strcmp(field->hfinfo->abbrev, "x509af.extension.id") == 0) &&
                (handshake_type == 11)) {
                cert_t *current_cert = (cert_t *)wmem_array_index(certificate_list, cert_num);
                oid_type = 2;

                // Append a comma to previous OIDs, if any
                if (wmem_strbuf_get_len(current_cert->oids[oid_type])) {
                    wmem_strbuf_append(current_cert->oids[oid_type], ",");
                }
                // BUG-FIX: Ja4x should use Hex codes instead of ascii
                const guint8 *bytes = field_bytes(get_value_ptr(field));
                for (gint j = 0; j < field->length; j++) {
                    wmem_strbuf_append_printf(current_cert->oids[oid_type], "%02x", bytes[j]);
                }
            }

            // Added for JA4H - HTTP1.0 and 1.1

            static const struct {
                const char *method;
                const char *code;
            } http_method_map[] = {
                {"ACL",               "ac"},
                {"BASELINE-CONTROL",  "ba"},
                {"BIND",              "bi"},
                {"CHECKIN",           "cn"},
                {"CHECKOUT",          "ct"},
                {"CONNECT",           "co"},
                {"COPY",              "cy"},
                {"DELETE",            "de"},
                {"GET",               "ge"},
                {"HEAD",              "he"},
                {"LABEL",             "la"},
                {"LINK",              "li"},
                {"LOCK",              "lo"},
                {"MERGE",             "me"},
                {"MKACTIVITY",        "ma"},
                {"MKCALENDAR",        "mc"},
                {"MKCOL",             "ml"},
                {"MKREDIRECTREF",     "mr"},
                {"MKWORKSPACE",       "mw"},
                {"MOVE",              "mo"},
                {"M-SEARCH",          "ms"},
                {"NOTIFY",            "no"},
                {"OPTIONS",           "op"},
                {"PATCH",             "pa"},
                {"POST",              "po"},
                {"PRI",               "pr"},
                {"PROPFIND",          "pf"},
                {"PROPPATCH",         "pp"},
                {"PURGE",             "pr"},
                {"PUT",               "pu"},
                {"REBIND",            "rb"},
                {"REPORT",            "rp"},
                {"SEARCH",            "se"},
                {"SUBSCRIBE",         "su"},
                {"TRACE",             "tr"},
                {"UNBIND",            "ub"},
                {"UNCHECKOUT",        "uc"},
                {"UNLINK",            "ui"},
                {"UNLOCK",            "uo"},
                {"UNSUBSCRIBE",       "un"},
                {"UPDATE",            "up"},
                {"UPDATEREDIRECTREF", "ur"},
                {"VERSION-CONTROL",   "ve"},
                {NULL,                NULL}
            };

            // Map full HTTP method to its two-letter JA4H code
            if ((strcmp(field->hfinfo->abbrev, "http.request.method") == 0) ||
                (strcmp(field->hfinfo->abbrev, "http2.headers.method") == 0)) {
                const char *method_str = fvalue_get_string(get_value_ptr(field));
                const char *ja4h_code = "00"; // fallback for unknown methods

                for (guint i = 0; http_method_map[i].method != NULL; i++) {
                    if (g_ascii_strcasecmp(method_str, http_method_map[i].method) == 0) {
                        ja4h_code = http_method_map[i].code;
                        break;
                    }
                }

                wmem_strbuf_append(ja4h_data.method, ja4h_code);

                http_req = field->hfinfo->parent;
            }

            if (strcmp(field->hfinfo->abbrev, "http2.headers.method") == 0) {
                wmem_strbuf_append(ja4h_data.version, "20");
                ja4h_data.http2 = true;
            }

            if (strcmp(field->hfinfo->abbrev, "http.request.version") == 0) {
                decode_http_version(&ja4h_data.version, fvalue_get_string(get_value_ptr(field)));
            }

            if ((strcmp(field->hfinfo->abbrev, "http.accept_language") == 0) ||
                (strcmp(field->hfinfo->abbrev, "http2.headers.accept_language") == 0)) {
                decode_http_lang(pinfo->pool, &ja4h_data.lang, fvalue_get_string(get_value_ptr(field)));
            }
            if ((strcmp(field->hfinfo->abbrev, "http.cookie") == 0) ||
                (strcmp(field->hfinfo->abbrev, "http2.headers.cookie") == 0)) {
                ja4h_data.cookie = true;
            }
            if ((strcmp(field->hfinfo->abbrev, "http.referer") == 0) ||
                (strcmp(field->hfinfo->abbrev, "http2.headers.referer") == 0)) {
                ja4h_data.referer = true;
            }

            if ((strcmp(field->hfinfo->abbrev, "http.cookie_pair") == 0) ||
                (strcmp(field->hfinfo->abbrev, "http2.headers.cookie") == 0)) {
                strings = g_strsplit(fvalue_get_string(get_value_ptr(field)), "=", 2);
                if (strings[0] && strings[1]) {
                    http_cookie_t *new_cookie = wmem_new(pinfo->pool, http_cookie_t);
                    new_cookie->field = wmem_strbuf_new(pinfo->pool, strings[0]);
                    new_cookie->value = wmem_strbuf_new(pinfo->pool, strings[1]);
                    wmem_strbuf_append_printf(ja4h_data.unsorted_cookie_fields, "%s,", strings[0]);
                    wmem_strbuf_append_printf(
                        ja4h_data.unsorted_cookie_values, "%s,",
                        fvalue_get_string(get_value_ptr(field))
                    );

                    // sort cookie fields
                    wmem_list_insert_sorted(
                        ja4h_data.sorted_cookies, (void *)new_cookie, sort_by_string
                    );
                }
            }

            if (field->hfinfo->parent == http_req) {
                if ((strcmp(field->hfinfo->abbrev, "http.request.line") == 0) ||
                    (strcmp(field->hfinfo->abbrev, "http2.header.name") == 0)) {
                    // Splitting the HTTP header name and value. No need to check HTTP2 header
                    // values as they are already parsed and stored in separate fields.
                    strings = g_strsplit(fvalue_get_string(get_value_ptr(field)), ":", -1);
                    if ((strings[0] != NULL) &&
                        (strings[1] != NULL || ja4h_data.http2 == true)) {
                        if ((strcmp(strings[0], "") != 0) &&
                            (strcmp(strings[0], "Cookie") != 0) &&
                            (strcmp(strings[0], "cookie") != 0) &&
                            (strcmp(strings[0], "Referer") != 0) &&
                            (strcmp(strings[0], "referer") != 0)) {
                            wmem_strbuf_append_printf(ja4h_data.headers, "%s,", strings[0]);
                            ja4h_data.num_headers++;
                        }
                    }
                }
            }

            // JA4L processng

            if (strcmp(field->hfinfo->abbrev, "ip.ttl") == 0) {
                curr_ttl = fvalue_get_uinteger(get_value_ptr(field));
            }

            if (strcmp(field->hfinfo->abbrev, "frame.time_epoch") == 0) {
                packet_time = (nstime_t *)fvalue_get_time(get_value_ptr(field));
            }

            if (strcmp(field->hfinfo->abbrev, "tcp.srcport") == 0) {
                srcport = fvalue_get_uinteger(get_value_ptr(field));
            }
            if (strcmp(field->hfinfo->abbrev, "udp.srcport") == 0) {
                srcport = fvalue_get_uinteger(get_value_ptr(field));
            }

            if (strcmp(field->hfinfo->abbrev, "tcp.dstport") == 0) {
                dstport = fvalue_get_uinteger(get_value_ptr(field));
            }
            if (strcmp(field->hfinfo->abbrev, "udp.dstport") == 0) {
                dstport = fvalue_get_uinteger(get_value_ptr(field));
            }

            if (strcmp(field->hfinfo->abbrev, "tcp.stream") == 0) {
                stream = fvalue_get_uinteger(get_value_ptr(field));
            }
            if (strcmp(field->hfinfo->abbrev, "udp.stream") == 0) {
                stream = fvalue_get_uinteger(get_value_ptr(field));
            }

            if (strcmp(field->hfinfo->abbrev, "tcp.len") == 0) {
                tcp_len = fvalue_get_uinteger(get_value_ptr(field));
            }
            if (strcmp(field->hfinfo->abbrev, "tcp.seq") == 0) {
                seq = fvalue_get_uinteger(get_value_ptr(field));
            }
            if (strcmp(field->hfinfo->abbrev, "tcp.ack") == 0) {
                ack = fvalue_get_uinteger(get_value_ptr(field));
            }

            if (strcmp(field->hfinfo->abbrev, "tcp.window_size_value") == 0) {
                ja4t_data.window_size = fvalue_get_uinteger(get_value_ptr(field));
            }

            if (strcmp(field->hfinfo->abbrev, "tcp.flags") == 0) {
                conn_info_t *conn = conn_lookup(ja4_data.proto, stream);

                // SYN for this stream - signal JA4T
                if (fvalue_get_uinteger(get_value_ptr(field)) == 0x02) {
                    syn = 1;
                    conn->client_ttl = curr_ttl;
                    if ((packet_time != NULL) && (nstime_is_zero(&conn->timestamp_A))) {
                        nstime_copy(&conn->timestamp_A, packet_time);
                    }
                }

                // SYN ACK for JA4TS - server latency
                if (fvalue_get_uinteger(get_value_ptr(field)) == 0x012) {
                    syn = 2;
                    conn->server_ttl = curr_ttl;
                    if ((packet_time != NULL) && (nstime_is_zero(&conn->timestamp_B))) {
                        nstime_copy(&conn->timestamp_B, packet_time);
                    }
                    if ((packet_time != NULL) && (conn->syn_ack_count < MAX_SYN_ACK_TIMES)) {
                        nstime_copy(&conn->syn_ack_times[conn->syn_ack_count++], packet_time);
                    }
                }

                // Add RST for JA4T
                if ((packet_time != NULL) && (fvalue_get_uinteger(get_value_ptr(field)) == 0x004)) {
                    syn = 3;
                    nstime_copy(&conn->rst_time, packet_time);
                }

                // ACK for JA4L-S - server latency
                if ((fvalue_get_uinteger(get_value_ptr(field)) == 0x010) && (tcp_len == 0)) {
                    if (dstport == 22) {
                        conn->tcp_client_acks++;
                    }
                    if (srcport == 22) {
                        conn->tcp_server_acks++;
                    }
                    srcport = dstport = 0;

                    if ((packet_time != NULL) && (nstime_is_zero(&conn->timestamp_C)) &&
                        (seq == 1) && (ack == 1)) {
                        nstime_copy(&conn->timestamp_C, packet_time);
                    }
                }

                // First packet after TCP handshake
                // JA4L - Timestamps D, E, and F are application packets
                // we identify them with PSH, ACK and the direction
                if (fvalue_get_uinteger(get_value_ptr(field)) == 0x018) {
                    if (conn->server_ttl && conn->client_ttl) {
                        if ((packet_time != NULL) && nstime_is_zero(&conn->timestamp_D)) {
                            // Denotes first PSH, ACK
                            nstime_copy(&conn->timestamp_D, packet_time);
                        } else {
                            wmem_strbuf_t *display = wmem_strbuf_new(pinfo->pool, "");
                            wmem_strbuf_t *display2 = wmem_strbuf_new(pinfo->pool, "");

                            bool is_http = false;
                            GPtrArray *proto_http_array = proto_find_first_finfo(tree, proto_http);
                            if (proto_http_array && proto_http_array->len > 0) {
                                is_http = true;
                            }

                            if ((packet_time != NULL) && (srcport < 5000) &&
                                (nstime_is_zero(&conn->timestamp_E))) {
                                // Denotes second PSH, ACK - JA4L-S goes here
                                nstime_copy(&conn->timestamp_E, packet_time);

                                if (is_http) {
                                    nstime_delta(&latency, &conn->timestamp_B, &conn->timestamp_A);
                                    wmem_strbuf_append_printf(
                                        display, "%d_%d_tcp", latency.nsecs / 2 / 1000, conn->server_ttl
                                    );
                                    update_tree_item_with_table(
                                        pinfo->num, tvb, tree, &ja4_tree, hf_ja4ls,
                                        wmem_strbuf_get_str(display), "tcp"
                                    );

                                    nstime_delta(&latency, &conn->timestamp_C, &conn->timestamp_B);
                                    wmem_strbuf_append_printf(
                                        display2, "%d_%d_tcp", latency.nsecs / 2 / 1000,
                                        conn->client_ttl
                                    );
                                    update_tree_item_with_table(
                                        pinfo->num, tvb, tree, &ja4_tree, hf_ja4l,
                                        wmem_strbuf_get_str(display2), "tcp"
                                    );
                                    mark_complete(pinfo->num);
                                }
                            }

                            if ((packet_time != NULL) && (dstport < 5000) &&
                                (nstime_is_zero(&conn->timestamp_F))) {
                                // Denotes third PSH, ACK - JA4L-C goes here
                                nstime_copy(&conn->timestamp_F, packet_time);

                                if (!is_http) {
                                    nstime_delta(&latency, &conn->timestamp_B, &conn->timestamp_A);
                                    nstime_delta(&latency2, &conn->timestamp_E, &conn->timestamp_D);
                                    wmem_strbuf_append_printf(
                                        display, "%d_%d_%d", latency.nsecs / 2 / 1000, conn->server_ttl,
                                        latency2.nsecs / 2 / 1000
                                    );
                                    update_tree_item_with_table(
                                        pinfo->num, tvb, tree, &ja4_tree, hf_ja4ls,
                                        wmem_strbuf_get_str(display), "tcp"
                                    );

                                    double delta = (double)latency2.nsecs / (double)latency.nsecs;
                                    delta = round(delta * 10.0) / 10.0;
                                    update_tree_item(
                                        tvb, tree, &ja4_tree, hf_ja4ls_delta,
                                        &delta, "tcp"
                                    );

                                    nstime_delta(&latency, &conn->timestamp_C, &conn->timestamp_B);
                                    nstime_delta(&latency2, &conn->timestamp_F, &conn->timestamp_E);
                                    wmem_strbuf_append_printf(
                                        display2, "%d_%d_%d", latency.nsecs / 2 / 1000,
                                        conn->client_ttl, latency2.nsecs / 2 / 1000
                                    );
                                    update_tree_item_with_table(
                                        pinfo->num, tvb, tree, &ja4_tree, hf_ja4l,
                                        wmem_strbuf_get_str(display2), "tcp"
                                    );

                                    double delta2 = (double)latency2.nsecs / (double)latency.nsecs;
                                    delta2 = round(delta2 * 10.0) / 10.0;
                                    update_tree_item(
                                        tvb, tree, &ja4_tree, hf_ja4l_delta,
                                        &delta2, "tcp"
                                    );
                                    mark_complete(pinfo->num);
                                }
                            }
                        }
                    }
                }

                // Fix to add JA4SSH when a connection terminates
                if ((fvalue_get_uinteger(get_value_ptr(field)) == 0x011) &&
                    ((srcport == 22) || (dstport == 22))) {
                    update_tree_item_with_table(
                        pinfo->num, tvb, tree, &ja4_tree, hf_ja4ssh, ja4ssh(pinfo->pool, conn), "tcp"
                    );
                    mark_complete(pinfo->num);
                }
            }

            // QUIC JA4L processing
            if (strcmp(field->hfinfo->abbrev, "quic.long.packet_type") == 0) {
                conn_info_t *conn = conn_lookup(ja4_data.proto, stream);

                // QUIC Initial packets
                if (fvalue_get_uinteger(get_value_ptr(field)) == 0) {
                    if ((packet_time != NULL) && (dstport == 443) &&
                        (nstime_is_zero(&conn->timestamp_A))) {
                        conn->client_ttl = curr_ttl;
                        nstime_copy(&conn->timestamp_A, packet_time);
                    }
                    if ((packet_time != NULL) && (srcport == 443) &&
                        (nstime_is_zero(&conn->timestamp_B))) {
                        conn->server_ttl = curr_ttl;
                        nstime_copy(&conn->timestamp_B, packet_time);
                    }
                }

                // QUIC handshake packets, keep updating C until D is found
                if (fvalue_get_uinteger(get_value_ptr(field)) == 2) {
                    if ((packet_time != NULL) && (srcport == 443) &&
                        (nstime_is_zero(&conn->timestamp_C))) {
                        nstime_copy(&conn->timestamp_C, packet_time);
                    }

                    if ((packet_time != NULL) && (dstport == 443) &&
                        (nstime_is_zero(&conn->timestamp_D))) {
                        nstime_copy(&conn->timestamp_D, packet_time);

                        wmem_strbuf_t *display = wmem_strbuf_new(pinfo->pool, "");
                        wmem_strbuf_t *display2 = wmem_strbuf_new(pinfo->pool, "");

                        nstime_delta(&latency, &conn->timestamp_B, &conn->timestamp_A);
                        wmem_strbuf_append_printf(
                            display, "%d_%d_quic", latency.nsecs / 2 / 1000, conn->server_ttl
                        );
                        update_tree_item_with_table(
                            pinfo->num, tvb, tree, &ja4_tree, hf_ja4ls,
                            wmem_strbuf_get_str(display), "quic"
                        );

                        nstime_delta(&latency, &conn->timestamp_D, &conn->timestamp_C);
                        wmem_strbuf_append_printf(
                            display2, "%d_%d_quic", latency.nsecs / 2 / 1000, conn->client_ttl
                        );
                        update_tree_item_with_table(
                            pinfo->num, tvb, tree, &ja4_tree, hf_ja4l,
                            wmem_strbuf_get_str(display2), "quic"
                        );
                        mark_complete(pinfo->num);
                    }
                }
            }

            // Added for JA4T processing
            if ((syn > 0) && (strcmp(field->hfinfo->abbrev, "tcp.option_kind") == 0)) {
                wmem_strbuf_append_printf(
                    ja4t_data.tcp_options, "%d-", fvalue_get_uinteger(get_value_ptr(field))
                );
            }
            if ((syn > 0) && (strcmp(field->hfinfo->abbrev, "tcp.options.mss_val") == 0)) {
                ja4t_data.mss_val = fvalue_get_uinteger(get_value_ptr(field));
            }
            if ((syn > 0) && (strcmp(field->hfinfo->abbrev, "tcp.options.wscale.shift") == 0)) {
                ja4t_data.window_scale = fvalue_get_uinteger(get_value_ptr(field));
            }
            // End of JA4T processing

            if ((strcmp(field->hfinfo->abbrev, "ssh.direction") == 0) &&
                (pinfo->fd->visited == 0)) {
                conn_info_t *conn = conn_lookup(ja4_data.proto, stream);
                conn->pkts++;

                fvalue_get_uinteger64(get_value_ptr(field)) ? conn->server_pkts++
                                                            : conn->client_pkts++;
                fvalue_get_uinteger64(get_value_ptr(field))
                    ? update_mode(tcp_len, conn->server_mode)
                    : update_mode(tcp_len, conn->client_mode);

                if ((conn->pkts % SAMPLE_COUNT) == 0) {
                    update_tree_item_with_table(
                        pinfo->num, tvb, tree, &ja4_tree, hf_ja4ssh, ja4ssh(pinfo->pool, conn), "ssh"
                    );
                    mark_complete(pinfo->num);

                    // reset conn parameters for the next ssh iteration
                    conn->tcp_server_acks = conn->tcp_client_acks = conn->client_pkts =
                        conn->server_pkts = 0;
                    conn->client_mode =
                        wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
                    conn->server_mode =
                        wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
                }
            }

            // JA4D processing

            // DHCPv4
            if (strcmp(field->hfinfo->abbrev, "dhcp.option.dhcp") == 0) {
                ja4d_data.proto = '4';
                ja4d_data.type = fvalue_get_uinteger(get_value_ptr(field));
            }
            if (strcmp(field->hfinfo->abbrev, "dhcp.option.dhcp_max_message_size") == 0) {
                wmem_strbuf_append_printf(
                    ja4d_data.size, "%d", fvalue_get_uinteger(get_value_ptr(field))
                );
            }
            if (strcmp(field->hfinfo->abbrev, "dhcp.option.type") == 0) {
                guint val = fvalue_get_uinteger(get_value_ptr(field));
                if (val != 0 && val != 53) {
                    wmem_strbuf_append_printf(ja4d_data.options, "%d-", val);
                }
            }
            if (strcmp(field->hfinfo->abbrev, "dhcp.option.request_list_item") == 0) {
                wmem_strbuf_append_printf(
                    ja4d_data.request_list, "%d-", fvalue_get_uinteger(get_value_ptr(field))
                );
            }

            // DHCPv6
            if (strcmp(field->hfinfo->abbrev, "dhcpv6.msgtype") == 0) {
                ja4d_data.proto = '6';
                ja4d_data.type = fvalue_get_uinteger(get_value_ptr(field));
            }
            if (strcmp(field->hfinfo->abbrev, "dhcpv6.duid.bytes") == 0 &&
                wmem_strbuf_get_len(ja4d_data.size) == 0 &&
                dhcpv6_option_type_1_exists == true) {
                wmem_strbuf_append_printf(
                    ja4d_data.size, "%d", field->length
                );
            }
            if (strcmp(field->hfinfo->abbrev, "dhcpv6.option.type") == 0) {
                guint val = fvalue_get_uinteger(get_value_ptr(field));
                if (val == 1)
                    dhcpv6_option_type_1_exists = true;
                wmem_strbuf_append_printf(
                    ja4d_data.options, "%d-", val
                );
            }
            if (strcmp(field->hfinfo->abbrev, "dhcpv6.requested_option_code") == 0) {
                wmem_strbuf_append_printf(
                    ja4d_data.request_list, "%d-", fvalue_get_uinteger(get_value_ptr(field))
                );
            }
        }
        g_ptr_array_free(items, TRUE);
    }

    if (syn == 1) {
        update_tree_item_with_table(pinfo->num, tvb, tree, &ja4_tree, hf_ja4t, ja4t(pinfo->pool, &ja4t_data, NULL), "tcp");
        mark_complete(pinfo->num);
    }
    if (syn == 2) {
        conn_info_t *conn = conn_lookup(ja4_data.proto, stream);
        conn->window_scale = ja4t_data.window_scale;
        conn->window_size = ja4t_data.window_size;
        conn->mss_val = ja4t_data.mss_val;
        if (conn->tcp_options == NULL)
            conn->tcp_options =
                wmem_strbuf_dup(wmem_file_scope(), ja4t_data.tcp_options);
        update_tree_item_with_table(pinfo->num, tvb, tree, &ja4_tree, hf_ja4ts, ja4t(pinfo->pool, &ja4t_data, conn), "tcp");
        mark_complete(pinfo->num);
    }

    if (syn == 3) {
        conn_info_t *conn = conn_lookup(ja4_data.proto, stream);
        ja4t_data.window_scale = conn->window_scale;
        ja4t_data.window_size = conn->window_size;
        ja4t_data.mss_val = conn->mss_val;
        if (conn->tcp_options != NULL)
            wmem_strbuf_append(
                ja4t_data.tcp_options, wmem_strbuf_get_str(conn->tcp_options)
            );
        update_tree_item_with_table(pinfo->num, tvb, tree, &ja4_tree, hf_ja4ts, ja4t(pinfo->pool, &ja4t_data, conn), "tcp");
        mark_complete(pinfo->num);
    }

    if (handshake_type == 2) {
        set_ja4_ciphers(tree, &ja4_data);
        set_ja4s_extensions(tree, &ja4_data);
        update_tree_item_with_table(pinfo->num, tvb, tree, &ja4_tree, hf_ja4s, ja4s(pinfo->pool, &ja4_data), proto);
        update_tree_item_with_table(pinfo->num, tvb, tree, &ja4_tree, hf_ja4s_raw, ja4s_r(pinfo->pool, &ja4_data), proto);
        mark_complete(pinfo->num);
    }

    if (handshake_type == 11) {
        for (guint i = 0; i < cert_num + 1; i++) {
            cert_t *current_cert = (cert_t *)wmem_array_index(certificate_list, i);
            wmem_strbuf_append_printf(
                current_cert->raw, "%s_%s_%s", wmem_strbuf_get_str(current_cert->oids[0]),
                wmem_strbuf_get_str(current_cert->oids[1]),
                wmem_strbuf_get_str(current_cert->oids[2])
            );
            update_tree_item_with_table(
                pinfo->num, tvb, tree, &ja4_tree, hf_ja4x_raw,
                wmem_strbuf_get_str(current_cert->raw), proto
            );
            update_tree_item_with_table(pinfo->num, tvb, tree, &ja4_tree, hf_ja4x, ja4x(pinfo->pool, current_cert), proto);
        }
        mark_complete(pinfo->num);
    }

    if (http_req != -100) {
        wmem_strbuf_truncate(ja4h_data.headers, wmem_strbuf_get_len(ja4h_data.headers) - 1);
        wmem_strbuf_truncate(
            ja4h_data.unsorted_cookie_fields,
            wmem_strbuf_get_len(ja4h_data.unsorted_cookie_fields) - 1
        );

        if (ja4h_data.cookie) {
            create_sorted_cookies(
                &ja4h_data.sorted_cookie_fields, &ja4h_data.sorted_cookie_values,
                ja4h_data.sorted_cookies
            );
        }

        if (wmem_strbuf_get_len(ja4h_data.lang) == 0) {
            wmem_strbuf_append(ja4h_data.lang, "0000");
        }

        char *http_proto = "http";
        if (ja4h_data.http2 == true) {
            http_proto = "http2";
        }
        g_warning("JA4H insert count: %d", insert_count++);
        update_tree_item_with_table(pinfo->num, tvb, tree, &ja4_tree, hf_ja4h, ja4h(pinfo->pool, &ja4h_data), http_proto);
        update_tree_item_with_table(
            pinfo->num, tvb, tree, &ja4_tree, hf_ja4h_raw, ja4h_r(pinfo->pool, &ja4h_data), http_proto
        );
        update_tree_item_with_table(
            pinfo->num, tvb, tree, &ja4_tree, hf_ja4h_raw_original, ja4h_ro(pinfo->pool, &ja4h_data), http_proto
        );
        mark_complete(pinfo->num);
    }

    if (ja4d_data.proto != 0) {
        wmem_strbuf_truncate(ja4d_data.options, wmem_strbuf_get_len(ja4d_data.options) - 1);
        wmem_strbuf_truncate(ja4d_data.request_list, wmem_strbuf_get_len(ja4d_data.request_list) - 1);

        char *dhcp_proto = "dhcp";
        if (ja4d_data.proto == '6') {
            dhcp_proto = "dhcpv6";
        }

        update_tree_item_with_table(pinfo->num, tvb, tree, &ja4_tree, hf_ja4d, ja4d(pinfo->pool, &ja4d_data), dhcp_proto);
        mark_complete(pinfo->num);
    }

    return tvb_reported_length(tvb);
}

static tap_packet_status tap_all(
    void *tapdata _U_, packet_info *pinfo, epan_dissect_t *edt, const void *data _U_,
    tap_flags_t flags _U_
) {
    g_warning("JA4H tap display count: %d", tap_display_count++);
    int added = display_hashes_from_packet_table(*(int *)tapdata, edt->tree, edt->tvb, pinfo->num);
    if (added > 0) {
        return TAP_PACKET_REDRAW;
    }
    return TAP_PACKET_DONT_REDRAW;;
}

typedef struct ja4_tap_s {
    const char *tap;
    int *hfid; // tapdata
    const char *filter;
} ja4_tap_t;

/* Wireshark ≤4.2 calls the TLS tap "tls",
 * after that it's "tls_follow"
 */
#if ((WIRESHARK_VERSION_MAJOR > 4) || (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR > 2))
#define TLS_TAP "tls_follow"
#else
#define TLS_TAP "tls"
#endif

static ja4_tap_t const ja4_taps[] = {
    {TLS_TAP, &hf_ja4s,              "tls.handshake.type == 2"                 },
    {TLS_TAP, &hf_ja4s_raw,          "tls.handshake.type == 2"                 },

    {"dtls",  &hf_ja4s,              "dtls.handshake.type == 2"                },
    {"dtls",  &hf_ja4s_raw,          "dtls.handshake.type == 2"                },

    {TLS_TAP, &hf_ja4x,              "tls.handshake.type == 11"                },
    {TLS_TAP, &hf_ja4x_raw,          "tls.handshake.type == 11"                },

    {"dtls",  &hf_ja4x,              "dtls.handshake.type == 11"               },
    {"dtls",  &hf_ja4x_raw,          "dtls.handshake.type == 11"               },

    {"http",  &hf_ja4h,              NULL                                      },
    {"http",  &hf_ja4h_raw,          NULL                                      },
    {"http",  &hf_ja4h_raw_original, NULL                                      },
    {"http2", &hf_ja4h,              NULL                                      },
    {"http2", &hf_ja4h_raw,          NULL                                      },
    {"http2", &hf_ja4h_raw_original, NULL                                      },
    {"tcp",   &hf_ja4l,              "tcp.flags == 0x018"                      },
    {"tcp",   &hf_ja4ls,             "tcp.flags == 0x018"                      },
    {"tcp",   &hf_ja4ssh,            "ssh.direction"                           },
    {"tcp",   &hf_ja4t,              "tcp.flags == 0x002"                      },
    {"tcp",   &hf_ja4ts,             "tcp.flags == 0x012 || tcp.flags == 0x004"},
    {"dhcp",  &hf_ja4d,              NULL                                      },

    {NULL,    NULL,                  NULL                                      }  // keep this at the end
};

// Add missing declaration so init/cleanup can reference it
static GPtrArray *active_taps = NULL;

static void init_globals(void) {
    GArray *wanted_hfids = g_array_new(FALSE, FALSE, (guint)sizeof(int));
    for (int i = 0; i < HFIDS; i++) {
        int id = proto_registrar_get_id_byname(interesting_hfids[i]);
        if (id != -1) {
            g_array_append_val(wanted_hfids, id);
        } else {
            g_warning("JA4: Unknown field: %s", interesting_hfids[i]);
        }
    }

    set_postdissector_wanted_hfids(ja4_handle, wanted_hfids);

    conn_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    quic_conn_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
    packet_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);

    if (proto_is_protocol_enabled(find_protocol_by_id(proto_ja4))) {
        GString *ret;
        size_t i;

        active_taps = g_ptr_array_sized_new(array_length(ja4_taps));
        for (i = 0; ja4_taps[i].hfid != NULL; i++) {
            ret = register_tap_listener(
                ja4_taps[i].tap, ja4_taps[i].hfid, ja4_taps[i].filter, TL_REQUIRES_PROTO_TREE, NULL,
                tap_all, NULL, NULL
            );
            if (ret == NULL) {
                g_ptr_array_add(active_taps, ja4_taps[i].hfid);
            } else {
                g_warning(
                    "JA4 failed to register tap on \"%s\" with filter \"%s\": %s",
                    ja4_taps[i].filter, ja4_taps[i].tap, ret->str
                );
                g_string_free(ret, TRUE);
            }
        }
    }
}

static void cleanup_globals(void) {
    set_postdissector_wanted_hfids(ja4_handle, NULL);

    if (active_taps != NULL) {
        /* Note that multiple taps are registered with the same tapdata
         * (which is simply the hfid). As long as we remove it the same
         * number of times it was added then we should be ok.
         */
        for (size_t i = 0; i < active_taps->len; i++) {
            int *hfid = g_ptr_array_index(active_taps, i);
            remove_tap_listener(hfid);
        }
        g_ptr_array_free(active_taps, TRUE);
        active_taps = NULL;
    }
}

void proto_reg_handoff_ja4(void) {
    proto_http = proto_registrar_get_id_byname("http");
}

void proto_register_ja4(void) {
    static hf_register_info hf[] = {
        {&hf_ja4s_raw,          {"JA4S Raw", "ja4.ja4s_r", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ja4s,              {"JA4S", "ja4.ja4s", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}      },
        {&hf_ja4x_raw,          {"JA4X Raw", "ja4.ja4x_r", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ja4x,              {"JA4X", "ja4.ja4x", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}      },
        {&hf_ja4h,              {"JA4H", "ja4.ja4h", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}      },
        {&hf_ja4h_raw,          {"JA4H Raw", "ja4.ja4h_r", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ja4h_raw_original,
         {"JA4H Raw (Original)", "ja4.ja4h_ro", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}           },
        {&hf_ja4l,              {"JA4L", "ja4.ja4l", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}      },
        {&hf_ja4l_delta,
         {"JA4L Delta", "ja4.ja4l_delta", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL}                 },
        {&hf_ja4ls,             {"JA4LS", "ja4.ja4ls", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}    },
        {&hf_ja4ls_delta,
         {"JA4LS Delta", "ja4.ja4ls_delta", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL}               },
        {&hf_ja4ssh,            {"JA4SSH", "ja4.ja4ssh", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}  },
        {&hf_ja4t,              {"JA4T", "ja4.ja4t", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}      },
        {&hf_ja4ts,             {"JA4TS", "ja4.ja4ts", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}   },
        {&hf_ja4d,              {"JA4D", "ja4.ja4d", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}      }
    };

    static gint *ett[] = {
        &ett_ja4,
    };

    proto_ja4 = proto_register_protocol("JA4 Fingerprint", "JA4", "ja4");
    ja4_handle = register_dissector("ja4", dissect_ja4, proto_ja4);

    proto_register_field_array(proto_ja4, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(init_globals);
    register_cleanup_routine(cleanup_globals);
    register_postdissector(ja4_handle);

    module_t *ja4_module = prefs_register_protocol(proto_ja4, NULL);
    prefs_register_bool_preference(ja4_module,
                                   "omit_ja4h_zero_sections",
                                   "Omit zero sections in JA4H",
                                   "If enabled, zeroed JA4H fingerprint sections (e.g., '000000000000') will be omitted when cookies are missing.",
                                   &pref_omit_ja4h_zero_sections);
}
