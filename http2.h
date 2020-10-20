#ifndef HTTP2_H
#define HTTP2_H

#include "http2_value.h"
#include "http2_macro.h"

typedef enum _http2_mode_
{
    HTTP2_MODE_SERVER = 0x0,
    HTTP2_MODE_CLIENT
}HTTP2_MODE;

typedef enum _http2_id_init_
{
    HTTP2_ID_CLIENT_INIT = 0x01,
    HTTP2_ID_SERVER_INIT,
}HTTP2_ID_INIT;

typedef enum _frame_type_
{
    FRAME_TYPE_DATA = 0x0,
    FRAME_TYPE_HEADER,
    FRAME_TYPE_PRIORITY,
    FRAME_TYPE_RST_STREAM,
    FRAME_TYPE_SETTING,
    FRAME_TYPE_PUSH_PROMISE,
    FRAME_TYPE_PING,
    FRAME_TYPE_GOAWAY,
    FRAME_TYPE_WINDOW_UPDATE,
    FRAME_TYPE_CONTINUATION,
    FRAME_TYPE_OTHER
}HTTP2_FRAME_TYPE;

typedef enum _http2_conn_state_
{
    HTTP2_CONN_STATE_CONNECTING,
    HTTP2_CONN_STATE_READY
}HTTP2_CONNECTION_STATE;

typedef enum _frame_state_
{
    FRAME_STATE_IDLE = 0x0,
    FRAME_STATE_LOCAL_RESERV,
    FRAME_STATE_REMOTE_RESERV,
    FRAME_STATE_OPEN,
    FRAME_STATE_LOCAL_HALF_CLOSE,
    FRAME_STATE_REMOTE_HALF_CLOSE,
    FRAME_STATE_CLOSE
}HTTP2_FRAME_STATE;

typedef enum _setting_type_
{
    SETTINGS_HEADER_TABLE_SIZE = 0x1,
    SETTINGS_ENABLE_PUSH,
    SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
    MAX_SETTINGS_SIZE
}SETTING_TYPE;

enum STATIC_TABLE_EM{
    IDX_NOT_USE = 0x0,
	IDX_AUTHORITY,
	IDX_METHOD_GET,
	IDX_METHOD_POST,
	IDX_PATH,
	IDX_PATH_INDEX_HTML,
	IDX_SCHEME_HTTP,
	IDX_SCHEME_HTTPS,
	IDX_STATUS_200,
	IEX_STATUS_204,
	IDX_STATUS_206,
	IDX_STATUS_304,
	IDX_STATUS_400,
	IDX_STATUS_404,
	IDX_STATUS_500,
	IDX_ACCEPT_CHARSET,
	IDX_ACCEPT_ENCODING_GZIP_DEFLATE,
	IDX_ACCEPT_LANGUAGE,
	IDX_ACCEPT_RANGES,
	IDX_ACCEPT,
	IDX_ACCESS_CONTROL_ALLOW_ORIGIN,
	IDX_AGE,
	IDX_ALLOW,
	IDX_AUTHORIZATION,
	IDX_CACHE_CONTROL,
	IDX_CONTENT_DISPOSITION,
	IDX_CONTENT_ENCODING,
	IDX_CONTENT_LANGUAGE,
	IDX_CONTENT_LENGTH,
	IDX_CONTENT_LOCATION,
	IDX_CONTENT_RANGE,
	IDX_CONTENT_TYPE,
	IDX_COOKIE,
	IDX_DATE,
	IDX_ETAG,
	IDX_EXPECT,
	IDX_EXPIRES,
	IDX_FROM,
	IDX_HOST,
	IDX_IF_MATCH,
	IDX_IF_MODIFIED,
	IDX_IF_NONE_MATCH,
	IDX_IF_RANGE,
	IDX_IF_UNMODIFIED_SINCE,
	IDX_LAST_MODIFIED,
	IDX_LINK,
	IDX_LOCATION,
	IDX_MAX_FORWARDS,
	IDX_PROXY_AUTHENTICATE,
	IDX_PROXY_AUTHORIZATION,
	IDX_RANGE,
	IDX_REFERER,
	IDX_REFRESH,
	IDX_RETRY_AFTER,
	IDX_SERVER,
	IDX_SET_COOKIE,
	IDX_STRICT_TRANSPORT_SECURITY,
	IDX_TRANSFER_ENCODING,
	IDX_USER_AGENT,
	IDX_VARY,
	IDX_VIA,
	IDX_WWW_AUTHENTICATE,
    MAX_STATIC_TABLE_INDEX
};

typedef enum _http2_error_code_
{
    HTTP2_ERROR_CODE_NO_ERROR = 0x0,
    HTTP2_ERROR_CODE_PROTOCOL_ERROR,
    HTTP2_ERROR_CODE_INTERNAL_ERROR,
    HTTP2_ERROR_CODE_FLOW_CONTROL_ERROR,
    HTTP2_ERROR_CODE_SETTINGS_TIMEOUT,
    HTTP2_ERROR_CODE_STREAM_CLOSED,
    HTTP2_ERROR_CODE_FRAME_SIZE_ERROR,
    HTTP2_ERROR_CODE_REFUSED_STREAM,
    HTTP2_ERROR_CODE_CANCEL,
    HTTP2_ERROR_CODE_COMPRESSION_ERROR,
    HTTP2_ERROR_CODE_CONNECT_ERROR,
    HTTP2_ERROR_CODE_ENHANCE_YOUR_CALM,
    HTTP2_ERROR_CODE_INADEQUATE_SECURITY,
    HTTP2_ERROR_CODE_HTTP_1_1_REQUIRED
}HTTP2_ERROR_CODE;

typedef enum _return_code_
{
    HTTP2_RETURN_SUCCESS = 0,
    HTTP2_RETURN_NEED_MORE_DATA,
    HTTP2_RETURN_NEED_NEXT_DATA,
    HTTP2_RETURN_PROTOCOL_VERSION_NOT_SUPPORT,
    HTTP2_RETURN_STREAM_CLOSE,
    HTTP2_RETURN_CONNECTION_CLOSE,
    HTTP2_RETURN_ERROR,
    HTTP2_RETURN_SKIP_DATA
}HTTP2_RETURN_CODE;

typedef struct _http2_header_
{
    struct _http2_header_ *next;
    int size;
    char name[HTTP_H_NAME_SIZE];
    char value[HTTP_H_VALUE_SIZE];
}HTTP2_HEADER;

typedef struct _http2_table_
{
    int index;
    HTTP2_HEADER header;
}HTTP2_TABLE;

typedef struct _http2_settings_
{
    unsigned int setting_value;
    unsigned int current_value;
}HTTP2_SETTINGS;

typedef struct _http2_data_
{
	struct _http2_data_ *prev;
	struct _http2_data_ *next;
	int size;
	int len;
    int frame_type;
	char data[1];
} HTTP2_DATA;

typedef struct _http2_stream_info_ STREAM_INFO;

typedef struct _http2_connection_
{
    struct _http2_connection_ *prev;
    struct _http2_connection_ *next;
    
    int use_ssl;
    int (*ssl_write_callback)(int, void *, size_t, int *, char *);
    int (*ssl_read_callback)(int, void *, size_t, int *, char *);
    
    
    unsigned int version;
    int sock;
    HTTP2_MODE mode;
    unsigned long active_time;
    unsigned int last_stream_id_send;
    unsigned int last_stream_id_recv;
    
    //Flags group
    int sent_setting_f;
    int recv_setting_f;
    int goaway_sent;
    int state;
    int last_house_keeper;
    
    HTTP2_DATA *r_buffer;
    int w_buffer_curr;
    HTTP2_DATA *w_buffer;
    
    int dynamic_table_send_count;
    HTTP2_HEADER *dynamic_table_send;
    int dynamic_table_recv_count;
    HTTP2_HEADER *dynamic_table_recv;
    
    HTTP2_SETTINGS http2_settings_send[MAX_SETTINGS_SIZE];
    HTTP2_SETTINGS http2_settings_recv[MAX_SETTINGS_SIZE];
    
    //int stream_info_list_count;
    STREAM_INFO *stream_info_list[MAX_STREAM_INFO_LIST];
}HTTP2_CONNECTION;

typedef struct _http2_decode_data_
{
    struct _http2_decode_data_ *prev;
    struct _http2_decode_data_ *next;
    
    HTTP2_HEADER *first_header_list;
    HTTP2_HEADER *last_header;
    int data_len;
    int stream_flag;
    char *data;
}HTTP2_DECODE_DATA;

struct _http2_stream_info_
{
    struct _http2_stream_info_ *prev;
    struct _http2_stream_info_ *next;
    
    int state;
    
    unsigned long active_time;
    
    int stream_pp;
    
    void *user_data;
    int (*free_user_data_cb)(void *, char*);
    
    HTTP2_CONNECTION *conn;
    
    HTTP2_DATA *r_buffer;
    
    unsigned int stream_id;
    unsigned int version;
    int frame_type;
    int req_msg;
    
    HTTP2_DECODE_DATA data_send;
    HTTP2_DECODE_DATA data_recv;
};

extern HTTP2_TABLE *static_table;
extern const char http2_magic[24];

//HTTP2 COMMON
int data_alloc(HTTP2_DATA **xml, int len, char *err);
void http2_init();
HTTP2_CONNECTION *http2_conn_init(HTTP2_MODE mode,
                           int sock,
                           int use_ssl,
                           int (*ssl_write_callback)(int, void *, size_t, int *, char *),
                           int (*ssl_read_callback)(int, void *, size_t, int *, char *),
                           unsigned int *h_table_size,
                           unsigned int *push_enable,
                           unsigned int *max_concurrent_stream,
                           unsigned int *initial_windows_size,
                           unsigned int *max_frame_size,
                           unsigned int *max_header_list_size,
                           char *err);
                           
int http2_destroy(HTTP2_CONNECTION **conn);
STREAM_INFO* http2_stream_info_init(HTTP2_CONNECTION *conn, unsigned int *last_stream_id, int init_id, unsigned int *concurrent, unsigned int setting_concurrent, char *err);
int http2_stream_info_destroy(STREAM_INFO **info, HTTP2_ERROR_CODE err_code, char *diag);
int http2_dynamic_table_add(HTTP2_HEADER **dynamic, int *dynamic_count, char *name, char *value, int table_size, char *err);
int http2_dynamic_table_size_rotate(HTTP2_HEADER **dynamic, int *dynamic_count, int size, char *err);
int http2_get_setting_value(HTTP2_CONNECTION *conn, int current_value, SETTING_TYPE type);
int http2_window_update_calc(HTTP2_SETTINGS *http2_setting, unsigned int incremental_window_size, char *err);
int http2_valid(STREAM_INFO *info, char *err);
int http2_stream_info_set_user_data(STREAM_INFO *info, void *user_data, int (*free_user_data_cb)(void*, char*));
void * http2_stream_info_get_user_data(STREAM_INFO *info);
STREAM_INFO *http2_find_stream_info(HTTP2_CONNECTION *conn, unsigned int stream_id);
int http2_stream_info_rotate(STREAM_INFO *info);
int http2_conn_housekeeper(HTTP2_CONNECTION *conn, unsigned long stream_wait_timeout);
unsigned long http2_get_current_time();

//HTTP2 SEND
STREAM_INFO* http2_init_stream_info_send(HTTP2_CONNECTION *conn, int init_id, char *err);
int http2_build_setting(HTTP2_CONNECTION *conn, HTTP2_SETTINGS *setting, char *err);
int http2_build_setting_ack(HTTP2_CONNECTION *conn, char *err);
int http2_goaway_build(HTTP2_CONNECTION *conn, unsigned int promised_stream_id, HTTP2_ERROR_CODE err_code, char *diag);
int http2_ping_build(HTTP2_CONNECTION *conn, unsigned int flag, char *msg, char *err);
int http2_build_header(STREAM_INFO *info, int end_stream, char *err);
int http2_build_data(STREAM_INFO *info, int p_curr, int end_stream, char *err);
int http2_create_msg(STREAM_INFO *info, int end_stream, char *err);
int http2_add_header(STREAM_INFO *stream, char *name, char *value, char *err);
int http2_add_header_decode(HTTP2_DECODE_DATA *decode_data, char *name, char *value, int append_f, char *err);
int http2_add_decode_to_stream_info(STREAM_INFO *info, HTTP2_DECODE_DATA **decode_data);
int http2_free_decode_data(HTTP2_DECODE_DATA **decode_data, char *err);
int http2_add_data(STREAM_INFO *stream, char *data, int len, char *err);
int http2_add_data_decode(HTTP2_DECODE_DATA *decode_data, char *data, int len, char *err);
int http2_need_write(HTTP2_CONNECTION *conn);
int http2_can_write(HTTP2_CONNECTION *conn);
int http2_reset_stream_build(HTTP2_CONNECTION *conn, unsigned int stream_id, int err_code, char *diag, char *err);
int http2_window_update_build(HTTP2_CONNECTION *conn, unsigned int stream_id, int size);
int http2_write(HTTP2_CONNECTION *conn, char *err);

//HTTP2 RECV
int http2_read(HTTP2_CONNECTION *conn, char *err);
HTTP2_RETURN_CODE http2_decode(HTTP2_CONNECTION *conn, STREAM_INFO **info_ret, int *len, char *err);

#endif
