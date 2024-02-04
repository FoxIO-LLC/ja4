/* packet-ja4.c
 */

#include "config.h"
#include <glib.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

#include <epan/ftypes/ftypes-int.h>
#include <epan/ftypes/ftypes.h>
#include <epan/packet.h>
#include "epan/packet_info.h"
#include <epan/epan_dissect.h>
#include <epan/oids.h>
#include <epan/tap.h>
//#include <epan/conversation.h>
//#include <epan/dissectors/packet-tls-utils.h>

#define MAX_SSL_VESION(a,b) ((a) > (b) ? (a) : (b))
#define IS_GREASE_TLS(x) ((((x) & 0x0f0f) == 0x0a0a) && \
	(((x) & 0xff) == (((x)>>8) & 0xff)))
#define SAMPLE_COUNT 200

char *bytes_to_string(fvalue_t *fv) {
	return fvalue_to_string_repr(wmem_packet_scope(), fv, FTREPR_DISPLAY, 0);
}

static int proto_ja4;
static gint ett_ja4 = -1;
static int hf_ja4_raw = -1;
static int hf_ja4_raw_original = -1;
static int hf_ja4s_raw = -1;
static int hf_ja4s = -1;
static int hf_ja4 = -1;
static int hf_ja4x_raw = -1;
static int hf_ja4x = -1;
static int hf_ja4h = -1;
static int hf_ja4h_raw = -1;
static int hf_ja4h_raw_original = -1;
static int hf_ja4l = -1;
static int hf_ja4ls = -1;
static int hf_ja4ssh = -1;

static int hf_ja4t = -1;
static int hf_ja4ts = -1;

static int dissect_ja4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *dummy);

static dissector_handle_t ja4_handle;

const value_string ssl_versions[] = {
    	{ 0x0100,   "s1" },
    	{ 0x0200,   "s2" },
    	{ 0x0300,   "s3" },
    	{ 0x0301,   "10" },
    	{ 0x0302,   "11" },
    	{ 0x0303,   "12" },
    	{ 0x0304,   "13" },
    	{ 0x00, 	NULL }
};

#define HFIDS 40
const char *interesting_hfids[HFIDS] = {
	"tls.handshake.type",
	"tls.handshake.version",
	"tls.handshake.extension.type",
	"tls.handshake.ciphersuite",
	"tls.handshake.extensions.supported_version",
	"tls.handshake.sig_hash_alg",
	"tls.handshake.extensions_alpn_str",
	"tls.handshake.certificate",
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
	"quic.long.packet_type"
};

typedef struct {
	gchar          proto;
    	guint32        version;
   	gboolean       sni;   // only for JA4 client
    	gint           cipher_len; // only for ja4 client
    	gint           ext_len;
    	wmem_strbuf_t *alpn;
    	wmem_strbuf_t *ciphers;
    	wmem_strbuf_t *extensions;
    	wmem_list_t   *sorted_ciphers; // only for ja4 client
    	wmem_list_t   *sorted_extensions; // only for ja4 client
    	wmem_strbuf_t *signatures; // only for ja4 client
} ja4_info_t;

typedef struct {
	wmem_strbuf_t *field;
	wmem_strbuf_t *value;
} http_cookie_t;

typedef struct {
	wmem_strbuf_t	*version;
	wmem_strbuf_t	*method;
	wmem_strbuf_t	*headers;
	wmem_strbuf_t	*lang;
	wmem_list_t	*sorted_cookies;
	wmem_strbuf_t	*unsorted_cookie_fields;
	wmem_strbuf_t	*unsorted_cookie_values;
	wmem_strbuf_t	*sorted_cookie_fields;
	wmem_strbuf_t	*sorted_cookie_values;
	int 		num_headers;
	gboolean 	cookie;
	gboolean	referer;
} ja4h_info_t;

typedef struct {
	wmem_strbuf_t *tcp_options;
	int mss_val;
	int window_scale;
	int window_size;
} ja4t_info_t;

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

	// used for Ja4TS
	nstime_t syn_ack_times[10];
	nstime_t rst_time;
	int syn_ack_count;

	// used for ja4ssh
	int pkts;
	int client_pkts;
	int server_pkts;
	int tcp_client_acks;
	int tcp_server_acks;
	wmem_map_t	*client_mode;
	wmem_map_t 	*server_mode;

} conn_info_t;

typedef struct {
	wmem_strbuf_t *oids[3];
	wmem_strbuf_t *raw;
	wmem_strbuf_t *hash;
} cert_t;

typedef struct {
	int hf_field;
	char *hf_value;
} packet_hash_t;

typedef struct {
	int frame_number;
	int num_of_hashes;
	wmem_array_t *pkt_hashes;
	bool complete;
	char *insert_at;
} pkt_info_t;

wmem_map_t *conn_hash = NULL; // = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
wmem_map_t *quic_conn_hash = NULL; // Added for JA4L on quic
wmem_map_t *packet_table = NULL; 

pkt_info_t *packet_table_lookup (int frame_number) {
	pkt_info_t *data = wmem_map_lookup(packet_table, GINT_TO_POINTER(frame_number));
	if (data == NULL) {
		data = wmem_alloc(wmem_file_scope(), sizeof(pkt_info_t));
		data->pkt_hashes = wmem_array_new(wmem_file_scope(), 100);
		data->frame_number = frame_number;
		data->num_of_hashes = 0;
		data->complete = false;
		wmem_map_insert(packet_table, GINT_TO_POINTER(frame_number), data);
	}
	return data;
}

gint sort_by_string(gconstpointer s1, gconstpointer s2) {
	return strcmp(wmem_strbuf_get_str(((http_cookie_t *)s1)->field), wmem_strbuf_get_str(((http_cookie_t *)s2)->field));
}

// Fix #63
proto_tree *locate_tree(proto_tree *tree, const char *s) {
	proto_tree *position = tree->first_child;
	while ((position != NULL) && (strcmp(position->finfo->hfinfo->abbrev, s) != 0)) {
		position = position->next;
	}
	return position;
}

// Fix #63
void update_tree_item(int frame_number, tvbuff_t *tvb, proto_tree *tree, proto_tree **ja4_tree, int field, const char *str, const char *insert_at) {

	// We get to the right part of the tree using locate_tree and insert the 
	// hash there.
	
	proto_item *ja4_ti;

	if (*ja4_tree == NULL) {
	    proto_tree *tree_location = locate_tree(tree, insert_at);

	    if (tree_location == NULL) return;

	    ja4_ti = proto_tree_add_item(tree_location, proto_ja4, tvb, 0, -1, ENC_NA);
	    *ja4_tree = proto_item_add_subtree(ja4_ti, ett_ja4);
	}

	//proto_item *ti = proto_tree_add_string(*ja4_tree, field, NULL, 0, 0, "");
	//proto_item *ti = proto_tree_add_string(*ja4_tree, field, NULL, 0, 0, str);
	//proto_item_append_text(ti, "%s", str);
	//proto_item_set_generated(ti);
	pkt_info_t *pi = packet_table_lookup(frame_number);
	if (!pi->complete) {
		packet_hash_t *recorded_hash = wmem_alloc(wmem_file_scope(), sizeof(packet_hash_t));
		recorded_hash->hf_field = field;
		recorded_hash->hf_value = (char *) str;
		wmem_array_append(pi->pkt_hashes, recorded_hash, 1);
		pi->num_of_hashes++;
		pi->insert_at = (char *) insert_at;
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
static int display_hashes_from_packet_table(int hash_val, proto_tree *tree, tvbuff_t *tvb, int frame_number) {
	pkt_info_t *pi = packet_table_lookup(frame_number);
	if ((pi->complete)  && (pi->insert_at)){
        	proto_item *ja4_ti = proto_tree_add_item(locate_tree(tree, pi->insert_at), proto_ja4, tvb, 0, -1, ENC_NA);
        	proto_tree *sub_tree = proto_item_add_subtree(ja4_ti, ett_ja4);
		for (int i=0; i< pi->num_of_hashes; i++) {
               		packet_hash_t *hash = (packet_hash_t *) wmem_array_index(pi->pkt_hashes, i);
			if ((hash->hf_field == hash_val) || (hash_val == 999)) {
				proto_tree_add_string(sub_tree, hash->hf_field, NULL, 0, 0, hash->hf_value);
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

int get_max_mode(wmem_map_t *hash_table) {
	int counter = 0;
	int max_mode = 0;
	wmem_list_t *keys = wmem_map_get_keys(wmem_file_scope(), hash_table);
 	wmem_list_frame_t *key = wmem_list_head(keys);
	while(key) {

		int pkt_len = GPOINTER_TO_INT(wmem_list_frame_data(key));
		int mode = GPOINTER_TO_INT(wmem_map_lookup(hash_table, GINT_TO_POINTER(pkt_len)));
		if (mode > counter) {
			counter = mode;
			max_mode = pkt_len;
		}
        	key = wmem_list_frame_next(key);
	}
	return max_mode;
}

conn_info_t *conn_lookup (char proto, int stream) {

	wmem_map_t *conn = NULL;
	if (proto == 'q') {	
		conn = quic_conn_hash;
	} else {
		conn = conn_hash;
	}

	conn_info_t *data = wmem_map_lookup(conn, GINT_TO_POINTER(stream));
	if (data == NULL) {
		data = wmem_alloc(wmem_file_scope(), sizeof(conn_info_t));
		data->stream = stream;
		data->pkts = 0;
		data->client_pkts = 0;
		data->server_pkts = 0;
		data->tcp_client_acks = 0;
		data->tcp_server_acks = 0;

		nstime_set_zero(&data->timestamp_A);
		nstime_set_zero(&data->timestamp_B);
		nstime_set_zero(&data->timestamp_C);
		nstime_set_zero(&data->timestamp_D);
		nstime_set_zero(&data->timestamp_E);
		nstime_set_zero(&data->timestamp_F);
		nstime_set_zero(&data->rst_time);

		data->syn_ack_count = 0;
		for (int i=0; i<10; i++) {
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

void decode_http_lang(wmem_strbuf_t **out, const char *val) {
	gchar **strings;
	strings = g_strsplit(val, ",", 2);
	if (strings[0] != NULL) {
		for (int i=0; i < (int) strlen(strings[0]); i++) {
			if (strings[0][i] != '-') {
				wmem_strbuf_append_c(*out, g_ascii_tolower(strings[0][i]));
			}
		}

		if (wmem_strbuf_get_len(*out) <= 3) {
			wmem_strbuf_append_printf(*out, "%s", "00");
		}
	}
}

void decode_http_version(wmem_strbuf_t **out, const char *val) {
	gchar **strings;
	strings = g_strsplit(val, "/", 2);
	if (strings[1] != NULL) {
		for (int i=0; i < (int) strlen(strings[1]); i++) {
			if (strings[1][i] != '.') {
				wmem_strbuf_append_printf(*out, "%c", g_ascii_tolower(strings[1][i]));
			}
		}

		if (wmem_strbuf_get_len(*out) <= 1) {
			wmem_strbuf_append_printf(*out, "%s", "0");
		}
	}
}

char *wmem_list_to_str (wmem_list_t *l) {
	wmem_strbuf_t *temp = wmem_strbuf_new(wmem_packet_scope(), "");
 	wmem_list_frame_t *curr_entry = wmem_list_head(l);
	while(curr_entry && wmem_list_frame_next(curr_entry)) {
        	wmem_strbuf_append_printf(temp, "%04x,", GPOINTER_TO_UINT(wmem_list_frame_data(curr_entry)));
        	curr_entry = wmem_list_frame_next(curr_entry);
    	}

	if (curr_entry != NULL) {
        	wmem_strbuf_append_printf(temp, "%04x", GPOINTER_TO_UINT(wmem_list_frame_data(curr_entry)));
	}
	return (char *) wmem_strbuf_get_str(temp);
}

void create_sorted_cookies (wmem_strbuf_t **fields, wmem_strbuf_t **values, wmem_list_t *l) {
 	wmem_list_frame_t *curr_entry = wmem_list_head(l);
	http_cookie_t *curr_cookie = NULL;
	while(curr_entry && wmem_list_frame_next(curr_entry)) {

		curr_cookie = wmem_list_frame_data(curr_entry);
        	wmem_strbuf_append_printf(*fields, "%s,", wmem_strbuf_get_str(curr_cookie->field));
        	wmem_strbuf_append_printf(*values, "%s=%s,", wmem_strbuf_get_str(curr_cookie->field), wmem_strbuf_get_str(curr_cookie->value));
        	curr_entry = wmem_list_frame_next(curr_entry);
    	}

	// Append last entry without a trailing comma
	curr_cookie = wmem_list_frame_data(curr_entry);
        wmem_strbuf_append_printf(*fields, "%s", wmem_strbuf_get_str(curr_cookie->field));
        wmem_strbuf_append_printf(*values, "%s=%s", wmem_strbuf_get_str(curr_cookie->field), wmem_strbuf_get_str(curr_cookie->value));
}

char *ja4 (ja4_info_t *data) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	gchar *cipher_hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_list_to_str(data->sorted_ciphers), -1);

	wmem_strbuf_t *temp = wmem_strbuf_new(wmem_file_scope(), "");
	wmem_strbuf_append_printf(temp, 
		"%s_%s", 
		wmem_list_to_str(data->sorted_extensions), 
		wmem_strbuf_get_str(data->signatures)
	);

	gchar *ext_hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(temp), -1);

	wmem_strbuf_append_printf(display, "%c%s%c%02d%02d%c%c_%12.12s_%12.12s", 
		data->proto,
		val_to_str_const(data->version, ssl_versions, "00"),
		(data->sni ? 'd': 'i'), 
		data->cipher_len, 
		data->ext_len,
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[0] : '0',
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[wmem_strbuf_get_len(data->alpn)-1] : '0',
		cipher_hash,
		ext_hash
	);
	if (cipher_hash != NULL) g_free(cipher_hash);
	if (ext_hash != NULL) g_free(ext_hash);
	return (char *) wmem_strbuf_get_str(display);
}

char *ja4_r (ja4_info_t *data) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	wmem_strbuf_append_printf(display, "%c%s%c%02d%02d%c%c_%s_%s_%s", 
		data->proto,
		val_to_str_const(data->version, ssl_versions, "00"),
		(data->sni ? 'd': 'i'), 
		data->cipher_len, 
		data->ext_len,
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[0] : '0',
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[wmem_strbuf_get_len(data->alpn)-1] : '0',
		wmem_list_to_str(data->sorted_ciphers),
		wmem_list_to_str(data->sorted_extensions),
		wmem_strbuf_get_str(data->signatures)
	);
	return (char *) wmem_strbuf_get_str(display);
}

char *ja4_ro (ja4_info_t *data) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	wmem_strbuf_append_printf(display, "%c%s%c%02d%02d%c%c_%s_%s_%s", 
		data->proto,
		val_to_str_const(data->version, ssl_versions, "00"),
		(data->sni ? 'd': 'i'), 
		data->cipher_len, 
		data->ext_len,
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[0] : '0',
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[wmem_strbuf_get_len(data->alpn)-1] : '0',
		wmem_strbuf_get_str(data->ciphers),
		wmem_strbuf_get_str(data->extensions),
		wmem_strbuf_get_str(data->signatures)
	);
	return (char *) wmem_strbuf_get_str(display);
}

char *ja4s_r (ja4_info_t *data) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	wmem_strbuf_append_printf(display, "%c%s%02d%c%c_%s_%s", 
		data->proto,
		val_to_str_const(data->version, ssl_versions, "00"),
		data->ext_len,
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[0] : '0',
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[wmem_strbuf_get_len(data->alpn)-1] : '0',
		wmem_strbuf_get_str(data->ciphers),
		wmem_strbuf_get_str(data->extensions)
	);
	return (char *) wmem_strbuf_get_str(display);
}

char *ja4s (ja4_info_t *data) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	gchar *_hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(data->extensions),-1);
	wmem_strbuf_append_printf(display, "%c%s%02d%c%c_%s_%12.12s", 
		data->proto,
		val_to_str_const(data->version, ssl_versions, "00"),
		data->ext_len,
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[0] : '0',
		(wmem_strbuf_get_len(data->alpn) > 0) ? wmem_strbuf_get_str(data->alpn)[wmem_strbuf_get_len(data->alpn)-1] : '0',
		wmem_strbuf_get_str(data->ciphers),
		_hash
	);
	if (_hash != NULL) g_free(_hash);
	return (char *) wmem_strbuf_get_str(display);
}

char *ja4x (cert_t *cert) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	gchar *hash1 = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(cert->oids[0]),-1);
	gchar *hash2 = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(cert->oids[1]),-1);
	gchar *hash3 = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(cert->oids[2]),-1);
	wmem_strbuf_append_printf(display, "%12.12s_%12.12s_%12.12s", 
		hash1,
		hash2,
		hash3
	);
	if (hash1 != NULL) g_free(hash1);
	if (hash2 != NULL) g_free(hash2);
	if (hash3 != NULL) g_free(hash3);
	return (char *) wmem_strbuf_get_str(display);
}

char *ja4h_r (ja4h_info_t *data) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	wmem_strbuf_append_printf(display, "%s%s%s%s%02d%s_%s_%s_%s", 
		wmem_strbuf_get_str(data->method),
		wmem_strbuf_get_str(data->version),
		data->cookie ? "c" : "n",
		data->referer? "r": "n",
		data->num_headers,
		wmem_strbuf_get_str(data->lang),
		wmem_strbuf_get_str(data->headers),
		wmem_strbuf_get_str(data->sorted_cookie_fields),
		wmem_strbuf_get_str(data->sorted_cookie_values)
	);
	return (char *) wmem_strbuf_get_str(display);
}

char *ja4h_ro (ja4h_info_t *data) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	wmem_strbuf_append_printf(display, "%s%s%s%s%02d%s_%s_%s_%s", 
		wmem_strbuf_get_str(data->method),
		wmem_strbuf_get_str(data->version),
		data->cookie ? "c" : "n",
		data->referer? "r": "n",
		data->num_headers,
		wmem_strbuf_get_str(data->lang),
		wmem_strbuf_get_str(data->headers),
		wmem_strbuf_get_str(data->unsorted_cookie_fields),
		wmem_strbuf_get_str(data->unsorted_cookie_values)
	);
	return (char *) wmem_strbuf_get_str(display);
}

char *ja4h (ja4h_info_t *data) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	gchar *hash1 = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(data->headers),-1);
	gchar *hash2 = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(data->sorted_cookie_fields),-1);
	gchar *hash3 = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(data->sorted_cookie_values),-1);
	wmem_strbuf_append_printf(display, "%s%s%s%s%02d%s_%12.12s_%12.12s_%12.12s", 
		wmem_strbuf_get_str(data->method),
		wmem_strbuf_get_str(data->version),
		data->cookie ? "c" : "n",
		data->referer? "r": "n",
		data->num_headers,
		wmem_strbuf_get_str(data->lang), 
		hash1, 
		data->cookie ? hash2 : "000000000000", 
		data->cookie ? hash3 : "000000000000"
	);
	if (hash1 != NULL) g_free(hash1);
	if (hash2 != NULL) g_free(hash2);
	if (hash3 != NULL) g_free(hash3);
	return (char *) wmem_strbuf_get_str(display);
}

char *ja4ssh (conn_info_t *conn) {
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	wmem_strbuf_append_printf(display, "c%ds%d_c%ds%d_c%ds%d", 
		get_max_mode(conn->client_mode),
		get_max_mode(conn->server_mode),
		conn->client_pkts, 
		conn->server_pkts, 
		conn->tcp_client_acks, 
		conn->tcp_server_acks);
	return (char *) wmem_strbuf_get_str(display);
}


// Compute JA4T
char *ja4t (ja4t_info_t *data, conn_info_t *conn) {
	nstime_t latency;
	wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
	if (wmem_strbuf_get_len(data->tcp_options) > 0)
		wmem_strbuf_truncate(data->tcp_options, wmem_strbuf_get_len(data->tcp_options)-1);
	if (data->window_scale == 0) {
		wmem_strbuf_append_printf(display, 
			"%d_%s_%02d_%02d", 
			data->window_size, 
			(wmem_strbuf_get_len(data->tcp_options) == 0) ? "0" : wmem_strbuf_get_str(data->tcp_options), 
			data->mss_val, 
			data->window_scale);
	} else {
		wmem_strbuf_append_printf(display, 
			"%d_%s_%02d_%d", 
			data->window_size, 
			(wmem_strbuf_get_len(data->tcp_options) == 0) ? "0" : wmem_strbuf_get_str(data->tcp_options), 
			data->mss_val, 
			data->window_scale);
	}

	if ((conn != NULL) && (conn->syn_ack_count > 1)) {
		wmem_strbuf_append_printf(display, "%c", '_');
		for (int i=1; i<conn->syn_ack_count; i++) {
			nstime_delta(&latency, &conn->syn_ack_times[i], &conn->syn_ack_times[i-1]);
			wmem_strbuf_append_printf(display, "%d", (int) latency.secs);
			if (i < (conn->syn_ack_count - 1)) {
				wmem_strbuf_append_printf(display, "%c", '-');
			}
		}
		if (conn->rst_time.secs != 0) {
			nstime_delta(&latency, &conn->rst_time, &conn->syn_ack_times[conn->syn_ack_count-1]);
			wmem_strbuf_append_printf(display, "-R%d", (int) latency.secs);
		}
	}

	return (char *) wmem_strbuf_get_str(display);
}


static void init_ja4_data(packet_info *pinfo, ja4_info_t *ja4_data) {
	ja4_data->version = 0;
	ja4_data->ext_len = 0;
	ja4_data->cipher_len = 0;
	ja4_data->sni = false;
	ja4_data->proto = proto_is_frame_protocol(pinfo->layers,"tcp") ? 't': 'q';

	ja4_data->sorted_ciphers = wmem_list_new(wmem_packet_scope());
	ja4_data->sorted_extensions = wmem_list_new(wmem_packet_scope());
	ja4_data->ciphers = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4_data->extensions = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4_data->signatures = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4_data->alpn = wmem_strbuf_new(wmem_packet_scope(), "");
}


static void set_ja4_extensions(proto_tree *tree, ja4_info_t *data) {
	guint value;
	GPtrArray *items = proto_find_finfo(tree, proto_registrar_get_id_byname("tls.handshake.extension.type"));
        if (items) {
                guint i;
                for (i=0; i< items->len; i++) {
                        field_info *field = (field_info *)g_ptr_array_index(items,i);
			value = fvalue_get_uinteger(field->value);
			if (!IS_GREASE_TLS(value)) {
				if ((value != 0x0000) && (value != 0x0010)) {
					// Ignore SNI and ALPN when storing extensions
					wmem_list_insert_sorted(data->sorted_extensions, GUINT_TO_POINTER(value), wmem_compare_uint);
					wmem_strbuf_append_printf(data->extensions, "%04x,", value);
				}

				if (value == 0x0000) data->sni = true;
				//Count has SNI and ALPN!
				data->ext_len ++;
			}
		}
	}
	if (wmem_strbuf_get_len(data->extensions) > 3) {
		wmem_strbuf_truncate(data->extensions, wmem_strbuf_get_len(data->extensions)-1);
	}
}

static void set_ja4_ciphers(proto_tree *tree, ja4_info_t *data) {
	guint value;
	GPtrArray *items = proto_find_finfo(tree, proto_registrar_get_id_byname("tls.handshake.ciphersuite"));
	if (items) {
                guint i;
                for (i=0; i< items->len; i++) {
                        field_info *field = (field_info *)g_ptr_array_index(items,i);
			value = fvalue_get_uinteger(field->value);
			if (!IS_GREASE_TLS(value)) {
				wmem_list_insert_sorted(data->sorted_ciphers, GUINT_TO_POINTER(value), wmem_compare_uint);
				wmem_strbuf_append_printf(data->ciphers, "%04x,", value);
				data->cipher_len ++;
			}
		}
	}
	if (wmem_strbuf_get_len(data->ciphers) > 3) {
		wmem_strbuf_truncate(data->ciphers, wmem_strbuf_get_len(data->ciphers)-1);
	}
}

static int
dissect_ja4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *dummy _U_)
{
	guint32 handshake_type = 0;
	gboolean alpn_visited = false;
	proto_tree      *ja4_tree = NULL;

	// For JA4C/S, record signature algorithms only when extension type == 13
	int record_signatures = 0;

	//For JA4X
	guint cert_num = -1;
	guint oid_type = -1;
	wmem_array_t *certificate_list = wmem_array_new(wmem_packet_scope(), 100);

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

	nstime_t *packet_time;
	int seq = 0;
	int ack = 0;
	int syn = 0;

        if (tree == NULL) 
		return tvb_captured_length(tvb);


	int hashes = display_hashes_from_packet_table(999, tree, tvb, pinfo->num);
	if (hashes > 0) 
		return tvb_captured_length(tvb);

	ja4_info_t ja4_data;
	ja4h_info_t ja4h_data;

	init_ja4_data(pinfo, &ja4_data);

	// JA4T data
	ja4t_info_t ja4t_data;
	ja4t_data.tcp_options = wmem_strbuf_new(wmem_file_scope(), "");
	ja4t_data.mss_val = 0;
	ja4t_data.window_scale = 0;
	ja4t_data.window_size = 0;
	// End of Ja4T data

	ja4h_data.version = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4h_data.headers = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4h_data.lang = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4h_data.method = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4h_data.cookie = false;
	ja4h_data.referer = false;
	ja4h_data.num_headers = 0;
	ja4h_data.sorted_cookies = wmem_list_new(wmem_packet_scope());
	ja4h_data.unsorted_cookie_fields = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4h_data.unsorted_cookie_values = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4h_data.sorted_cookie_fields = wmem_strbuf_new(wmem_packet_scope(), "");
	ja4h_data.sorted_cookie_values = wmem_strbuf_new(wmem_packet_scope(), "");

	GPtrArray *items = proto_all_finfos(tree);
        if (items != NULL) {
            	guint i;
            	for (i=0; i< items->len; i++) {
                	field_info *field = (field_info *)g_ptr_array_index(items,i);

                	if (strcmp(field->hfinfo->abbrev, "tls.handshake.type") == 0) {
				handshake_type = fvalue_get_uinteger(field->value);
                	}

                	if (strcmp(field->hfinfo->abbrev, "tls.handshake.version") == 0) {
				ja4_data.version = fvalue_get_uinteger(field->value);
                	}

                	if (strcmp(field->hfinfo->abbrev, "tls.handshake.extension.type") == 0) {
				if (fvalue_get_uinteger(field->value) == 13) {
					record_signatures = 1;
				} else {
					record_signatures = 0;
				}
                	}

                	if (strcmp(field->hfinfo->abbrev, "tls.handshake.sig_hash_alg") == 0) {
				if (record_signatures == 1) {
					wmem_strbuf_append_printf(ja4_data.signatures, "%04x,", fvalue_get_uinteger(field->value));
				}
			}

                	if (strcmp(field->hfinfo->abbrev, "tls.handshake.extensions.supported_version") == 0) {
				if (!IS_GREASE_TLS(fvalue_get_uinteger(field->value))) {
					ja4_data.version = MAX_SSL_VESION(ja4_data.version, fvalue_get_uinteger(field->value));
				}
			}


                	if (strcmp(field->hfinfo->abbrev, "tls.handshake.extensions_alpn_str") == 0) {
				if (!alpn_visited) {
					const char *alpn_str = fvalue_get_string(field->value);
					if (!isascii(alpn_str[0])) {
						wmem_strbuf_append_printf(ja4_data.alpn, "%s", "99");
					} else {
						wmem_strbuf_append_printf(ja4_data.alpn, "%s", fvalue_get_string(field->value));
					}
					alpn_visited = true;
				}
			}

			//JA4X specifiers
                	if (strcmp(field->hfinfo->abbrev, "tls.handshake.certificate") == 0) {
				cert_t cert;
				for (guint n=0; n<3; n++) {
					cert.oids[n] = wmem_strbuf_new(wmem_packet_scope(), "");
				}
				cert.raw = wmem_strbuf_new(wmem_packet_scope(), "");
				wmem_array_append_one(certificate_list, cert);
				oid_type = 0;
				cert_num++;
			}

                	if (strcmp(field->hfinfo->abbrev, "x509af.validity_element") == 0) {
				oid_type = 1;
			} 

                	if ((strcmp(field->hfinfo->abbrev, "x509if.oid") == 0) && (handshake_type == 11)) {
				cert_t *current_cert = (cert_t *) wmem_array_index(certificate_list, cert_num);
				wmem_strbuf_append_printf(current_cert->oids[oid_type], "%s,", bytes_to_string(field->value));
			}
                	if ((strcmp(field->hfinfo->abbrev, "x509af.extension.id") == 0) && (handshake_type == 11)) {
				cert_t *current_cert = (cert_t *) wmem_array_index(certificate_list, cert_num);
				wmem_strbuf_append_printf(current_cert->oids[2], "%s,", bytes_to_string(field->value));
			}

			// Added for JA4H - HTTP1.0 and 1.1

                        if (strcmp(field->hfinfo->abbrev, "http.request.method") == 0) {
				wmem_strbuf_append_printf(ja4h_data.method, "%c", g_ascii_tolower(fvalue_get_string(field->value)[0]));
				wmem_strbuf_append_printf(ja4h_data.method, "%c", g_ascii_tolower(fvalue_get_string(field->value)[1]));
                                http_req = field->hfinfo->parent;

                        }

                	if (strcmp(field->hfinfo->abbrev, "http.request.version") == 0) {
				decode_http_version(&ja4h_data.version, fvalue_get_string(field->value));
			}

                	if (strcmp(field->hfinfo->abbrev, "http.accept_language") == 0) {
				decode_http_lang(&ja4h_data.lang, fvalue_get_string(field->value));
			}
                	if (strcmp(field->hfinfo->abbrev, "http.cookie") == 0) {
				ja4h_data.cookie = true;
			}
                	if (strcmp(field->hfinfo->abbrev, "http.referer") == 0) {
				ja4h_data.referer = true;
			}

			if (strcmp(field->hfinfo->abbrev, "http.cookie_pair") == 0) {
				strings = g_strsplit(fvalue_get_string(field->value), "=", -1);
				if (strings[0] && strings[1]) {
					http_cookie_t *new_cookie = wmem_new(wmem_packet_scope(), http_cookie_t);
					new_cookie->field = wmem_strbuf_new(wmem_packet_scope(), strings[0]);
					new_cookie->value = wmem_strbuf_new(wmem_packet_scope(), strings[1]);

					wmem_strbuf_append_printf(ja4h_data.unsorted_cookie_fields, "%s,", strings[0]);
					wmem_strbuf_append_printf(ja4h_data.unsorted_cookie_values, "%s,", fvalue_get_string(field->value));

					// sort cookie fields
					wmem_list_insert_sorted(ja4h_data.sorted_cookies, (void *)new_cookie, sort_by_string);
				}
			}


                        if (field->hfinfo->parent == http_req) {
				if (strcmp(field->hfinfo->abbrev, "http.request.line") == 0) {
						strings = g_strsplit(fvalue_get_string(field->value), ":", -1);
						if ((strings[0] != NULL) && (strings[1] != NULL)) {
							if( 
								(strcmp(strings[0], "Cookie") != 0) && 
								(strcmp(strings[0], "Referer") != 0)
							){
								wmem_strbuf_append_printf(ja4h_data.headers, "%s,", strings[0]);
								ja4h_data.num_headers ++;
							}
						}
                        	}
			}

			// JA4L processng

			if (strcmp(field->hfinfo->abbrev, "ip.ttl") == 0) {
				curr_ttl = fvalue_get_uinteger(field->value);
			}

			if (strcmp(field->hfinfo->abbrev, "frame.time_epoch") == 0) {
				packet_time = (nstime_t *) fvalue_get_time(field->value);
			}

			if (strcmp(field->hfinfo->abbrev, "tcp.srcport") == 0) {
				srcport = fvalue_get_uinteger(field->value);
			}
			if (strcmp(field->hfinfo->abbrev, "udp.srcport") == 0) {
				srcport = fvalue_get_uinteger(field->value);
			}

			if (strcmp(field->hfinfo->abbrev, "tcp.dstport") == 0) {
				dstport = fvalue_get_uinteger(field->value);
			}
			if (strcmp(field->hfinfo->abbrev, "udp.dstport") == 0) {
				dstport = fvalue_get_uinteger(field->value);
			}

			if (strcmp(field->hfinfo->abbrev, "tcp.stream") == 0) {
				stream = fvalue_get_uinteger(field->value);
			}
			if (strcmp(field->hfinfo->abbrev, "udp.stream") == 0) {
				stream = fvalue_get_uinteger(field->value);
			}

			if (strcmp(field->hfinfo->abbrev, "tcp.len") == 0) {
				tcp_len = fvalue_get_uinteger(field->value);
			}
			if (strcmp(field->hfinfo->abbrev, "tcp.seq") == 0) {
				seq = fvalue_get_uinteger(field->value);
			}
			if (strcmp(field->hfinfo->abbrev, "tcp.ack") == 0) {
				ack = fvalue_get_uinteger(field->value);
			}

			if (strcmp(field->hfinfo->abbrev, "tcp.window_size_value") == 0) {
				ja4t_data.window_size = fvalue_get_uinteger(field->value);
			}

			if (strcmp(field->hfinfo->abbrev, "tcp.flags") == 0) {
				conn_info_t *conn = conn_lookup(ja4_data.proto, stream);

				// SYN for this stream - signal JA4T
				if (fvalue_get_uinteger(field->value) == 0x02) {
					syn = 1;
					conn->client_ttl = curr_ttl;
					if (conn->timestamp_A.secs == 0) {
						conn->timestamp_A.secs = packet_time->secs;
						conn->timestamp_A.nsecs = packet_time->nsecs;
					}
				}

				// SYN ACK for JA4TS - server latency
				if (fvalue_get_uinteger(field->value) == 0x012) {
					syn = 2;
					conn->server_ttl = curr_ttl;
					if (conn->timestamp_B.secs == 0) {
						conn->timestamp_B.secs = packet_time->secs;
						conn->timestamp_B.nsecs = packet_time->nsecs;
					}
					if (conn->syn_ack_count <= 10) {
						conn->syn_ack_times[conn->syn_ack_count].secs = packet_time->secs;
						conn->syn_ack_times[conn->syn_ack_count++].nsecs = packet_time->nsecs;
					}
				}

				// Add RST for JA4T
				if (fvalue_get_uinteger(field->value) == 0x004) {
					syn = 2;
					conn->rst_time.secs = packet_time->secs;
					conn->rst_time.nsecs = packet_time->nsecs;
				}

				// ACK for JA4L-S - server latency
				if ((fvalue_get_uinteger(field->value) == 0x010) && (tcp_len == 0)) {
					if (dstport == 22) {
						conn->tcp_client_acks++;
					}
					if (srcport == 22) {
						conn->tcp_server_acks++;
					}
					srcport = dstport = 0;

					if ((conn->timestamp_C.secs == 0) && (seq == 1) && (ack == 1)) {
						conn->timestamp_C.secs = packet_time->secs;
						conn->timestamp_C.nsecs = packet_time->nsecs;
					}
				}

				// First packet after TCP handshake
				// JA4L - Timestamps D, E, and F are application packets
				// we identify them with PSH, ACK and the direction
				if (fvalue_get_uinteger(field->value) == 0x018) {
					if (conn->server_ttl && conn->client_ttl) {
						if (conn->timestamp_D.nsecs == 0) {
							// Denotes first PSH, ACK
							conn->timestamp_D.secs = packet_time->secs;
							conn->timestamp_D.nsecs = packet_time->nsecs;
						} else {


							if ((srcport < 5000) && (conn->timestamp_E.nsecs == 0)) {
								// Denotes second PSH, ACK - JA4L-S goes here
								conn->timestamp_E.secs = packet_time->secs;
								conn->timestamp_E.nsecs = packet_time->nsecs;
							}

							if ((dstport < 5000) && (conn->timestamp_F.nsecs == 0)) {
								// Denotes third PSH, ACK - JA4L-C goes here
								conn->timestamp_F.secs = packet_time->secs;
								conn->timestamp_F.nsecs = packet_time->nsecs;

	        						//ti = proto_tree_add_item(tree->last_child, proto_ja4, tvb, 0, -1, ENC_NA);
	        						//ja4_tree = proto_item_add_subtree(ti, ett_ja4);
								wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
								wmem_strbuf_t *display2 = wmem_strbuf_new(wmem_file_scope(), "");

								nstime_delta(&latency, &conn->timestamp_B, &conn->timestamp_A);
								nstime_delta(&latency2, &conn->timestamp_E, &conn->timestamp_D);
								wmem_strbuf_append_printf(display, "%d_%d_%d", 
									latency.nsecs/2/1000, 
									conn->server_ttl, 
									latency2.nsecs/2/1000);
								update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4ls, wmem_strbuf_get_str(display), "tcp");

								nstime_delta(&latency, &conn->timestamp_C, &conn->timestamp_B);
								nstime_delta(&latency2, &conn->timestamp_F, &conn->timestamp_E);
								wmem_strbuf_append_printf(display2, "%d_%d_%d", 
									latency.nsecs/2/1000, 
									conn->client_ttl, 
									latency2.nsecs/2/1000);
								update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4l, wmem_strbuf_get_str(display2), "tcp");
								mark_complete(pinfo->num);
							}
						}
					}
				}

				// Fix to add JA4SSH when a connection terminates
				if ((fvalue_get_uinteger(field->value) == 0x011) && ((srcport == 22) || (dstport == 22))) {
					update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4ssh, ja4ssh(conn), "tcp");
					mark_complete(pinfo->num);
				}
			}

			// QUIC JA4L processing
			if (strcmp(field->hfinfo->abbrev, "quic.long.packet_type") == 0) {
				conn_info_t *conn = conn_lookup(ja4_data.proto, stream);

				// QUIC Initial packets
				if (fvalue_get_uinteger(field->value) == 0) {
					if ((dstport == 443) && (conn->timestamp_A.nsecs == 0)){
						conn->client_ttl = curr_ttl;
						conn->timestamp_A.secs = packet_time->secs;
						conn->timestamp_A.nsecs = packet_time->nsecs;
					}
					if ((srcport == 443) && (conn->timestamp_B.nsecs == 0)) {
						conn->server_ttl = curr_ttl;
						conn->timestamp_B.secs = packet_time->secs;
						conn->timestamp_B.nsecs = packet_time->nsecs;
					}
				}
	
				// QUIC handshake packets, keep updating C until D is found
				if (fvalue_get_uinteger(field->value) == 2) {
					if ((srcport == 443) && (conn->timestamp_D.nsecs == 0)) {
						conn->timestamp_C.secs = packet_time->secs;
						conn->timestamp_C.nsecs = packet_time->nsecs;
					}

					if ((dstport == 443) && (conn->timestamp_D.nsecs == 0)){
						conn->timestamp_D.secs = packet_time->secs;
						conn->timestamp_D.nsecs = packet_time->nsecs;

	        				//ti = proto_tree_add_item(tree->last_child, proto_ja4, tvb, 0, -1, ENC_NA);
	        				//ja4_tree = proto_item_add_subtree(ti, ett_ja4);
						wmem_strbuf_t *display = wmem_strbuf_new(wmem_file_scope(), "");
						wmem_strbuf_t *display2 = wmem_strbuf_new(wmem_file_scope(), "");

						nstime_delta(&latency, &conn->timestamp_B, &conn->timestamp_A);
						wmem_strbuf_append_printf(display, "%d_%d_q", 
							latency.nsecs/2/1000, 
							conn->server_ttl);
						update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4ls, wmem_strbuf_get_str(display), "tcp");

						nstime_delta(&latency, &conn->timestamp_D, &conn->timestamp_C);
						wmem_strbuf_append_printf(display2, "%d_%d_q", 
							latency.nsecs/2/1000, 
							conn->client_ttl);
						update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4l, wmem_strbuf_get_str(display2), "tcp");
						mark_complete(pinfo->num);
					}
				}
			}

			// Added for JA4T processing
			if ((syn > 0) && (strcmp(field->hfinfo->abbrev, "tcp.option_kind") == 0)) {
				wmem_strbuf_append_printf(ja4t_data.tcp_options, "%d-", fvalue_get_uinteger(field->value));
			}
			if ((syn > 0) && (strcmp(field->hfinfo->abbrev, "tcp.options.mss_val") == 0)) {
				ja4t_data.mss_val = fvalue_get_uinteger(field->value);
			}
			if ((syn > 0) && (strcmp(field->hfinfo->abbrev, "tcp.options.wscale.shift") == 0)) {
				ja4t_data.window_scale = fvalue_get_uinteger(field->value);
			}
			// End of JA4T processing


			if ((strcmp(field->hfinfo->abbrev, "ssh.direction") == 0) && (pinfo->fd->visited == 0)) {
				conn_info_t *conn = conn_lookup(ja4_data.proto, stream);
				conn->pkts++;

				field->value->value.uinteger ? conn->server_pkts++ : conn->client_pkts++;
				field->value->value.uinteger ? 
					update_mode(tcp_len, conn->server_mode) : 
					update_mode(tcp_len, conn->client_mode);
				
				if ((conn->pkts % SAMPLE_COUNT) == 0) {
	        			//ti = proto_tree_add_item(tree->last_child, proto_ja4, tvb, 0, -1, ENC_NA);
	        			//ja4_tree = proto_item_add_subtree(ti, ett_ja4);
					update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4ssh, ja4ssh(conn), "ssh");
					mark_complete(pinfo->num);

					// reset conn parameters for the next ssh iteration
					conn->tcp_server_acks = conn->tcp_client_acks = conn->client_pkts = conn->server_pkts = 0;
					conn->client_mode = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
					conn->server_mode = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
				}
			}
			
            	}
            	//g_ptr_array_free(items,TRUE);
        }

	if (syn == 1) {
		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4t, ja4t(&ja4t_data, NULL), "tcp");
		mark_complete(pinfo->num);
	}
	if (syn == 2) {
		conn_info_t *conn = conn_lookup(ja4_data.proto, stream);
		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4ts, ja4t(&ja4t_data, conn), "tcp");
		mark_complete(pinfo->num);
	}

	/*if ((handshake_type == 1) || (handshake_type == 2) || (handshake_type == 11) || (http_req != -100)) {
		if (ja4_tree == NULL) {
	        	ti = proto_tree_add_item(locate_tree(tree, "tls"), proto_ja4, tvb, 0, -1, ENC_NA);
	        	ja4_tree = proto_item_add_subtree(ti, ett_ja4);
		}
	}*/

	if (handshake_type == 1) {
		set_ja4_ciphers(tree, &ja4_data);
		set_ja4_extensions(tree, &ja4_data);
		if (wmem_strbuf_get_len(ja4_data.signatures) > 3) {
			wmem_strbuf_truncate(ja4_data.signatures, wmem_strbuf_get_len(ja4_data.signatures)-1);
		}
		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4, ja4(&ja4_data), (ja4_data.proto == 't') ? "tls": "quic");
		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4_raw, ja4_r(&ja4_data), (ja4_data.proto == 't') ? "tls": "quic");
		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4_raw_original, ja4_ro(&ja4_data), (ja4_data.proto == 't') ? "tls": "quic");
		mark_complete(pinfo->num);
	}
	if (handshake_type == 2) {
		set_ja4_ciphers(tree, &ja4_data);
		set_ja4_extensions(tree, &ja4_data);
		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4s, ja4s(&ja4_data), "tls");
		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4s_raw, ja4s_r(&ja4_data), "tls");
		mark_complete(pinfo->num);
	}

        if (handshake_type == 11) {
                for (guint i=0; i<cert_num+1; i++) {
                        cert_t *current_cert = (cert_t *) wmem_array_index(certificate_list, i);
                        wmem_strbuf_truncate(current_cert->oids[0], wmem_strbuf_get_len(current_cert->oids[0])-1);
                        wmem_strbuf_truncate(current_cert->oids[1], wmem_strbuf_get_len(current_cert->oids[1])-1);
                        wmem_strbuf_truncate(current_cert->oids[2], wmem_strbuf_get_len(current_cert->oids[2])-1);
                        wmem_strbuf_append_printf(current_cert->raw,
                                "%s_%s_%s",
                                wmem_strbuf_get_str(current_cert->oids[0]),
                                wmem_strbuf_get_str(current_cert->oids[1]),
                                wmem_strbuf_get_str(current_cert->oids[2])
                        );
			update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4x_raw, wmem_strbuf_get_str(current_cert->raw), "tls");
			update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4x, ja4x(current_cert), "tls");
                }
		mark_complete(pinfo->num);
        }

	if (http_req != -100) {
		wmem_strbuf_truncate(ja4h_data.headers, wmem_strbuf_get_len(ja4h_data.headers)-1);
		wmem_strbuf_truncate(ja4h_data.unsorted_cookie_fields, wmem_strbuf_get_len(ja4h_data.unsorted_cookie_fields)-1);

		if (ja4h_data.cookie) {
			create_sorted_cookies(&ja4h_data.sorted_cookie_fields, &ja4h_data.sorted_cookie_values, ja4h_data.sorted_cookies);
		}

		if (wmem_strbuf_get_len(ja4h_data.lang) == 0) {
			wmem_strbuf_append_printf(ja4h_data.lang, "%s", "0000");
		}

		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4h, ja4h(&ja4h_data), "http");
		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4h_raw, ja4h_r(&ja4h_data), "http");
		update_tree_item(pinfo->num, tvb, tree, &ja4_tree, hf_ja4h_raw_original, ja4h_ro(&ja4h_data), "http");
		mark_complete(pinfo->num);
	}

	//tap_queue_packet(ja4_tap, pinfo, NULL);
	return tvb_reported_length(tvb);
}


static tap_packet_status
tap_all(void *tapdata _U_, packet_info *pinfo, epan_dissect_t *edt, const void *data _U_, tap_flags_t flags _U_)
{

	display_hashes_from_packet_table(*(int*)tapdata, edt->tree, edt->tvb, pinfo->num);
	return TAP_PACKET_REDRAW;
}

static void init_globals (void) {
	conn_hash = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
	quic_conn_hash = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
	packet_table = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

	GArray *wanted_hfids = g_array_new(FALSE, FALSE, (guint)sizeof(int));
	for (int i=0; i< HFIDS; i++) {
		int id = proto_registrar_get_id_byname(interesting_hfids[i]);
		g_array_append_val(wanted_hfids, id);
	}

	set_postdissector_wanted_hfids(ja4_handle, wanted_hfids);

	GString *ret _U_;
	ret = register_tap_listener("tls", &hf_ja4s, "tls.handshake.type == 2", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tls", &hf_ja4s_raw, "tls.handshake.type == 2", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tls", &hf_ja4, "tls.handshake.type == 1", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tls", &hf_ja4_raw, "tls.handshake.type == 1", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tls", &hf_ja4_raw_original, "tls.handshake.type == 1", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tls", &hf_ja4x, "tls.handshake.type == 11", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tls", &hf_ja4x_raw, "tls.handshake.type == 11", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("http", &hf_ja4h, NULL, TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("http", &hf_ja4h_raw, NULL, TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("http", &hf_ja4h_raw_original, NULL, TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("http", &hf_ja4h_raw_original, NULL, TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tcp", &hf_ja4l, "tcp.flags == 0x018", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tcp", &hf_ja4ls, "tcp.flags == 0x018", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tcp", &hf_ja4ssh, "ssh.direction", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tcp", &hf_ja4t, "tcp.flags == 0x002", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
	ret = register_tap_listener("tcp", &hf_ja4ts, "tcp.flags == 0x012 || tcp.flags == 0x004", TL_REQUIRES_PROTO_TREE, NULL, tap_all, NULL, NULL);
}

static void cleanup_globals (void) {
	//set_postdissector_wanted_hfids(ja4_handle, NULL);
}

void proto_reg_handoff_ja4(void)
{
	//register_postdissector(ja4_handle);
	//ja4_tap = register_tap("ja4");
}

void
proto_register_ja4(void)
{
	static hf_register_info hf[] = {
		{ &hf_ja4_raw,
			{ "JA4 Raw", "ja4.ja4_r",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4_raw_original,
			{ "JA4 Raw (Original)", "ja4.ja4_ro",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4s_raw,
			{ "JA4S Raw", "ja4.ja4s_r",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4s,
			{ "JA4S", "ja4.ja4s",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4,
			{ "JA4", "ja4.ja4",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4x_raw,
			{ "JA4X Raw", "ja4.ja4x_r",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4x,
			{ "JA4X", "ja4.ja4x",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4h,
			{ "JA4H", "ja4.ja4h",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4h_raw,
			{ "JA4H Raw", "ja4.ja4h_r",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4h_raw_original,
			{ "JA4H Raw (Original)", "ja4.ja4h_ro",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4l,
			{ "JA4L", "ja4.ja4l",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4ls,
			{ "JA4LS", "ja4.ja4ls",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4ssh,
			{ "JA4SSH", "ja4.ja4ssh",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4t,
			{ "JA4T", "ja4.ja4t",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_ja4ts,
			{ "JA4T-S", "ja4.ja4ts",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		}
	};

    	static gint *ett[] = {
        	&ett_ja4,
    	};


	proto_ja4 = proto_register_protocol("JA4 Fingerprint", "JA4", "ja4");
	ja4_handle = create_dissector_handle(dissect_ja4, proto_ja4); //register_dissector("ja4", dissect_ja4, proto_ja4);

	proto_register_field_array(proto_ja4, hf, array_length(hf));
    	proto_register_subtree_array(ett, array_length(ett));	

	register_init_routine(init_globals);
	register_cleanup_routine(cleanup_globals);
	//dissector_add_uint("tcp.port", 443, ja4_handle);
	register_postdissector(ja4_handle);
}
