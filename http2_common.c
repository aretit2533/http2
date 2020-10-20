#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "http2.h"
#include "huffman.h"
#include "linklist.h"
#include "http2_macro.h"

HTTP2_TABLE *static_table = NULL;
const char http2_magic[24] = {0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a};

unsigned int version_count = 1;
char lib_http2_version[] = "1.0.4";

int data_alloc(HTTP2_DATA **xml, int len, char *err)
{

	if (*xml == NULL)
	{
		ADJUST_SIZE(len, MY_DATA_BUFFER)
		*xml = (HTTP2_DATA*)malloc(sizeof(HTTP2_DATA) + len);
		if (*xml == NULL)
		{
			HTTP2_PRINT_ERROR(err, "Can not allocate memory size (%u)", (unsigned int)(sizeof(HTTP2_DATA) + len));
			return -1;
		}
		(void)memset((*xml), 0, sizeof(HTTP2_DATA)+len);
		(*xml)->size = len;
		(*xml)->len = 0;
	}
	else if (((*xml)->len + len) > (*xml)->size)
	{
		HTTP2_DATA *x;
		len += (*xml)->len;
		ADJUST_SIZE(len, MY_DATA_BUFFER)
		x = (HTTP2_DATA*)realloc((*xml), sizeof(HTTP2_DATA) + len);
		if (x == NULL)
		{
			HTTP2_PRINT_ERROR(err, "Can not allocate memory size (%u)", (unsigned int)(sizeof(HTTP2_DATA) + len));
			return -1;
		}
		x->size = len;
		*xml = x;
		(void)memset((*xml)->data+(*xml)->len, 0, (*xml)->size-(*xml)->len);
	}
    
    (*xml)->frame_type = FRAME_TYPE_OTHER;
    
	return 0;
}

void http2_init() {
    //ROOT variable define in huffman.h
    if(!ROOT)
    {
        hf_init();
    }
    if(!static_table)
    {
        static_table = (HTTP2_TABLE *)calloc(sizeof(HTTP2_TABLE), MAX_STATIC_TABLE_INDEX);
        ADD_HEADER(static_table, IDX_NOT_USE, "", "");
        ADD_HEADER(static_table, IDX_AUTHORITY, ":authority", "");
        ADD_HEADER(static_table, IDX_METHOD_GET, ":method", "GET");
        ADD_HEADER(static_table, IDX_METHOD_POST, ":method", "POST");
        ADD_HEADER(static_table, IDX_PATH, ":path", "/");
        ADD_HEADER(static_table, IDX_PATH_INDEX_HTML, ":path", "/index.html");
        ADD_HEADER(static_table, IDX_SCHEME_HTTP, ":scheme", "http");
        ADD_HEADER(static_table, IDX_SCHEME_HTTPS, ":scheme", "https");
        ADD_HEADER(static_table, IDX_STATUS_200, ":status", "200");
        ADD_HEADER(static_table, IEX_STATUS_204, ":status", "204");
        ADD_HEADER(static_table, IDX_STATUS_206, ":status", "206");
        ADD_HEADER(static_table, IDX_STATUS_304, ":status", "304");
        ADD_HEADER(static_table, IDX_STATUS_400, ":status", "400");
        ADD_HEADER(static_table, IDX_STATUS_404, ":status", "404");
        ADD_HEADER(static_table, IDX_STATUS_500, ":status", "500");
        ADD_HEADER(static_table, IDX_ACCEPT_CHARSET, "accept-charset", "");
        ADD_HEADER(static_table, IDX_ACCEPT_ENCODING_GZIP_DEFLATE, "accept-encoding", "gzip, deflate");
        ADD_HEADER(static_table, IDX_ACCEPT_LANGUAGE, "accept-language", "");
        ADD_HEADER(static_table, IDX_ACCEPT_RANGES, "accept-ranges", "");
        ADD_HEADER(static_table, IDX_ACCEPT, "accept", "");
        ADD_HEADER(static_table, IDX_ACCESS_CONTROL_ALLOW_ORIGIN, "access-control-allow-origin", "");
        ADD_HEADER(static_table, IDX_AGE, "age", "");
        ADD_HEADER(static_table, IDX_ALLOW, "allow", "");
        ADD_HEADER(static_table, IDX_AUTHORIZATION, "authorization", "");
        ADD_HEADER(static_table, IDX_CACHE_CONTROL, "cache-control", "");
        ADD_HEADER(static_table, IDX_CONTENT_DISPOSITION, "content-disposition", "");
        ADD_HEADER(static_table, IDX_CONTENT_ENCODING, "content-encoding", "");
        ADD_HEADER(static_table, IDX_CONTENT_LANGUAGE, "content-language", "");
        ADD_HEADER(static_table, IDX_CONTENT_LENGTH, "content-length", "");
        ADD_HEADER(static_table, IDX_CONTENT_LOCATION, "content-location", "");
        ADD_HEADER(static_table, IDX_CONTENT_RANGE, "content-range", "");
        ADD_HEADER(static_table, IDX_CONTENT_TYPE, "content-type", "");
        ADD_HEADER(static_table, IDX_COOKIE, "cookie", "");
        ADD_HEADER(static_table, IDX_DATE, "date", "");
        ADD_HEADER(static_table, IDX_ETAG, "etag", "");
        ADD_HEADER(static_table, IDX_EXPECT, "expect", "");
        ADD_HEADER(static_table, IDX_EXPIRES, "expires", "");
        ADD_HEADER(static_table, IDX_FROM, "from", "");
        ADD_HEADER(static_table, IDX_HOST, "host", "");
        ADD_HEADER(static_table, IDX_IF_MATCH, "if-match", "");
        ADD_HEADER(static_table, IDX_IF_MODIFIED, "if-modified-since", "");
        ADD_HEADER(static_table, IDX_IF_NONE_MATCH, "if-none-match", "");
        ADD_HEADER(static_table, IDX_IF_RANGE, "if-range", "");
        ADD_HEADER(static_table, IDX_IF_UNMODIFIED_SINCE, "if-unmodified-since", "");
        ADD_HEADER(static_table, IDX_LAST_MODIFIED, "last-modified", "");
        ADD_HEADER(static_table, IDX_LINK, "link", "");
        ADD_HEADER(static_table, IDX_LOCATION, "location", "");
        ADD_HEADER(static_table, IDX_MAX_FORWARDS, "max-forwards", "");
        ADD_HEADER(static_table, IDX_PROXY_AUTHENTICATE, "proxy-authenticate", "");
        ADD_HEADER(static_table, IDX_PROXY_AUTHORIZATION, "proxy-authorization", "");
        ADD_HEADER(static_table, IDX_RANGE, "range", "");
        ADD_HEADER(static_table, IDX_REFERER, "referer", "");
        ADD_HEADER(static_table, IDX_REFRESH, "refresh", "");
        ADD_HEADER(static_table, IDX_RETRY_AFTER, "retry-after", "");
        ADD_HEADER(static_table, IDX_SERVER, "server", "");
        ADD_HEADER(static_table, IDX_SET_COOKIE, "set-cookie", "");
        ADD_HEADER(static_table, IDX_STRICT_TRANSPORT_SECURITY, "strict-transport-security", "");
        ADD_HEADER(static_table, IDX_TRANSFER_ENCODING, "transfer-encoding", "");
        ADD_HEADER(static_table, IDX_USER_AGENT, "user-agent", "");
        ADD_HEADER(static_table, IDX_VARY, "vary", "");
        ADD_HEADER(static_table, IDX_VIA, "via", "");
        ADD_HEADER(static_table, IDX_WWW_AUTHENTICATE, "www-authenticate", "");
    }
}

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
                           char *err)
{
    HTTP2_CONNECTION *property = (HTTP2_CONNECTION *)malloc(sizeof(HTTP2_CONNECTION));
    if(!property)
    {
        HTTP2_PRINT_ERROR(err, "Can not allocate memory property size [%lu]", sizeof(HTTP2_CONNECTION));
        return NULL;
    }
    property->mode = mode;
    switch(mode)
    {
        case HTTP2_MODE_CLIENT:
            property->last_stream_id_send = HTTP2_ID_CLIENT_INIT;
            break;
        case HTTP2_MODE_SERVER:
            property->last_stream_id_send = HTTP2_ID_SERVER_INIT;
            break;
        default:
            HTTP2_PRINT_ERROR(err, "Unsupport mode [0x%02x]", mode);
            free(property);
            return NULL;
    }
    
    property->use_ssl = use_ssl;
    property->ssl_write_callback = ssl_write_callback;
    property->ssl_read_callback = ssl_read_callback;
    
    property->sock = sock;
    property->state = HTTP2_CONN_STATE_CONNECTING;
    property->version = version_count++;
    if(version_count > MAX_VERSION_COUNT)
    {
        version_count = 1;
    }
    property->last_stream_id_recv = 0;
    property->dynamic_table_send_count = 0;
    property->dynamic_table_send = NULL;
    property->dynamic_table_recv_count = 0;
    property->dynamic_table_recv = NULL;
    
    property->sent_setting_f = 0;
    property->recv_setting_f = 0;
    property->goaway_sent = 0;
    
    property->r_buffer = NULL;
    property->w_buffer_curr = 0;
    property->w_buffer = NULL;
    
    int c;
    for(c = 0; c < MAX_STREAM_INFO_LIST; c++)
    {
        property->stream_info_list[c] = NULL;
    }
    
    memset(property->http2_settings_send, 0, sizeof(property->http2_settings_send));
    memset(property->http2_settings_recv, 0, sizeof(property->http2_settings_recv));
    int count;
    for(count = 1; count < MAX_SETTINGS_SIZE; count++)
    {
        switch(count)
        {
            case SETTINGS_HEADER_TABLE_SIZE:
                 if(h_table_size) property->http2_settings_send[count].setting_value = *h_table_size;
                 else property->http2_settings_send[count].setting_value = DEFAULT_SETTINGS_HEADER_TABLE_SIZE;
                 property->http2_settings_recv[count].setting_value = DEFAULT_SETTINGS_HEADER_TABLE_SIZE;
                 break;
            case SETTINGS_ENABLE_PUSH:
                 if(push_enable && (*push_enable == 0 || *push_enable == 1)) property->http2_settings_send[count].setting_value = *push_enable;
                 else property->http2_settings_send[count].setting_value = DEFAULT_SETTINGS_ENABLE_PUSH;
                 property->http2_settings_recv[count].setting_value = DEFAULT_SETTINGS_ENABLE_PUSH;
                 break;
            case SETTINGS_MAX_CONCURRENT_STREAMS:
                 if(max_concurrent_stream) property->http2_settings_send[count].setting_value = *max_concurrent_stream;
                 else property->http2_settings_send[count].setting_value = DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS;
                 property->http2_settings_recv[count].setting_value = DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS;
                 break;
            case SETTINGS_INITIAL_WINDOW_SIZE:
                 if(initial_windows_size && (*initial_windows_size >= 1 && *initial_windows_size <= MAX_SETTINGS_INITIAL_WINDOW_SIZE)) property->http2_settings_send[count].setting_value = *initial_windows_size;
                 else property->http2_settings_send[count].setting_value = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
                 property->http2_settings_recv[count].setting_value = DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
                 break;
            case SETTINGS_MAX_FRAME_SIZE:
                 if(max_frame_size && (*max_frame_size >= DEFAULT_SETTINGS_MAX_FRAME_SIZE && *max_frame_size <= MAX_SETTINGS_MAX_FRAME_SIZE)) property->http2_settings_send[count].setting_value = *max_frame_size;
                 else property->http2_settings_send[count].setting_value = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
                 property->http2_settings_recv[count].setting_value = DEFAULT_SETTINGS_MAX_FRAME_SIZE;
                 break;
            case SETTINGS_MAX_HEADER_LIST_SIZE:
                 if(max_header_list_size) property->http2_settings_send[count].setting_value = *max_header_list_size;
                 else property->http2_settings_send[count].setting_value = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
                 property->http2_settings_recv[count].setting_value = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
                 break;
            default:
                 break;
        }
    }
    
    return property;
}

int http2_destroy(HTTP2_CONNECTION **conn)
{
    if((*conn)->dynamic_table_send)
    {
        HTTP2_HEADER *h_tmp;
        while((*conn)->dynamic_table_send)
        {
            POP_HEADER((*conn)->dynamic_table_send, h_tmp);
            free(h_tmp);
        }
    }
    if((*conn)->dynamic_table_recv)
    {
        HTTP2_HEADER *h_tmp;
        while((*conn)->dynamic_table_recv)
        {
            POP_HEADER((*conn)->dynamic_table_recv, h_tmp);
            free(h_tmp);
        }
    }
    int c;
    for(c = 0; c < MAX_STREAM_INFO_LIST; c++)
    {
        if((*conn)->stream_info_list[c])
        {
            STREAM_INFO *s_tmp = (*conn)->stream_info_list[c];
            while(s_tmp)
            {
                LIST_REMOVE((*conn)->stream_info_list[c], s_tmp);
                s_tmp->conn = NULL;
				s_tmp->state = FRAME_STATE_CLOSE;
                http2_stream_info_destroy(&s_tmp, HTTP2_ERROR_CODE_INTERNAL_ERROR,"Connection closed.");
                s_tmp = (*conn)->stream_info_list[c];
            }
        }
    }
    free(*conn);
    *conn = NULL;
    
    return 0;
}

STREAM_INFO* http2_stream_info_init(HTTP2_CONNECTION *conn, unsigned int *last_stream_id, int init_id, unsigned int *concurrent, unsigned int setting_concurrent, char *err)
{
    if(setting_concurrent != DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS && *concurrent >= setting_concurrent)
    {
        HTTP2_PRINT_ERROR(err, "Max concurrent stream [%u:%u]", *concurrent, setting_concurrent);
        return NULL;
    }
    STREAM_INFO *info = (STREAM_INFO*) malloc(sizeof(STREAM_INFO));
    if(!info)
    {
        HTTP2_PRINT_ERROR(err, "Can not allocate memory size (%lu)", sizeof(STREAM_INFO));
        return NULL;
    }
    info->conn = conn;
    info->stream_id = *last_stream_id;
    *last_stream_id += 2;
    if(*last_stream_id > MAX_STREAM_ID)
    {
        *last_stream_id = init_id;
    }
    info->state = FRAME_STATE_IDLE;
    info->active_time = http2_get_current_time();
    info->stream_pp = 0;
    info->req_msg = 0;
    info->version = conn->version;
    info->user_data = NULL;
    info->r_buffer = NULL;
    info->data_send.first_header_list = NULL;
    info->data_send.last_header = NULL;
    info->data_send.data_len = 0;
    info->data_send.data = NULL;
    info->data_send.stream_flag = 0;
    info->data_recv.first_header_list = NULL;
    info->data_recv.last_header = NULL;
    info->data_recv.data_len = 0;
    info->data_recv.data = NULL;
    info->data_recv.stream_flag = 0;
    
    LIST_APPEND(conn->stream_info_list[info->stream_id % MAX_STREAM_INFO_LIST], info);
    *concurrent += 1;
    return info;
}

int http2_stream_info_set_user_data(STREAM_INFO *info, void *user_data, int (*free_user_data_cb)(void*, char*))
{
    info->user_data = user_data;
    info->free_user_data_cb = free_user_data_cb;
    return 0;
}

void * http2_stream_info_get_user_data(STREAM_INFO *info)
{
    return info->user_data;
}

STREAM_INFO *http2_find_stream_info(HTTP2_CONNECTION *conn, unsigned int stream_id)
{
    int id_bucket;
    id_bucket = stream_id % MAX_STREAM_INFO_LIST;
    STREAM_INFO *info = conn->stream_info_list[id_bucket];
    if(info)
    {
        do
        {
            if(info->stream_id == stream_id)
            {
                return info;
            }
            info = info->next;
        }
        while(info != conn->stream_info_list[id_bucket]);
    }
    return NULL;
}

int http2_stream_info_rotate(STREAM_INFO *info)
{
    int id_bucket;
    id_bucket = info->stream_id % MAX_STREAM_INFO_LIST;
    STREAM_INFO *info_tmp = info->conn->stream_info_list[id_bucket];
    if(info_tmp)
    {
        LIST_REMOVE(info->conn->stream_info_list[id_bucket], info);
        LIST_APPEND(info->conn->stream_info_list[id_bucket], info);
    }
    return -1;
}

int http2_stream_info_destroy(STREAM_INFO **info, HTTP2_ERROR_CODE err_code, char *diag)
{
    if(!info || !(*info)) return 0;
    STREAM_INFO *info_temp = *info;
    if(info_temp->state != FRAME_STATE_CLOSE) http2_reset_stream_build(info_temp->conn, info_temp->stream_id, err_code, diag, NULL);
    if(info_temp->conn)
    {
        info_temp->conn->http2_settings_recv[SETTINGS_MAX_CONCURRENT_STREAMS].current_value -= 1;
        LIST_REMOVE(info_temp->conn->stream_info_list[info_temp->stream_id % MAX_STREAM_INFO_LIST], info_temp);
    }
    if(info_temp->r_buffer)
    {
        free(info_temp->r_buffer);
    }
    if(info_temp->data_send.data)
    {
        free(info_temp->data_send.data);
    }
    if(info_temp->data_recv.data)
    {
        free(info_temp->data_recv.data);
    }
    if(info_temp->data_send.first_header_list)
    {
        HTTP2_HEADER *h_tmp;
        while(info_temp->data_send.first_header_list)
        {
            POP_HEADER(info_temp->data_send.first_header_list, h_tmp);
            free(h_tmp);
        }
    }
    if(info_temp->data_recv.first_header_list)
    {
        HTTP2_HEADER *h_tmp;
        while(info_temp->data_recv.first_header_list)
        {
            POP_HEADER(info_temp->data_recv.first_header_list, h_tmp);
            free(h_tmp);
        }
    }
    
    if(info_temp->user_data && info_temp->free_user_data_cb)
    {
        info_temp->free_user_data_cb(info_temp->user_data, diag);
    }
    
    free(info_temp);
    *info = NULL;
    
    return 0;
}


int http2_dynamic_table_size_rotate(HTTP2_HEADER **dynamic, int *dynamic_count, int size, char *err)
{
    int curr_size = 0;
    HTTP2_HEADER *h = *dynamic;
    if(!h)
        return 0;
    curr_size += h->size;
    while(h->next)
    {
        if(curr_size + h->next->size > size)
            break;
        curr_size += h->next->size;
        h = h->next;
    }
    if(h->next)
    {
        HTTP2_HEADER *h_t = h->next;
        HTTP2_HEADER *h_rm;
        h->next = NULL;
        while(h_t)
        {
            POP_HEADER(h_t, h_rm);
            free(h_rm);
            *dynamic_count -= 1;
        }
    }
    return 0;
}

int http2_dynamic_table_add(HTTP2_HEADER **dynamic, int *dynamic_count, char *name, char *value, int table_size, char *err)
{
    if(!name || !value)
    {
        HTTP2_PRINT_ERROR(err, "Invalid argument [%p:%p]", name, value);
        return -1;
    }
    HTTP2_HEADER *h = (HTTP2_HEADER *)malloc(sizeof(HTTP2_HEADER));
    if(!h)
    {
        HTTP2_PRINT_ERROR(err, "Can not allocate memory size [%lu]", sizeof(HTTP2_HEADER));
        return -1;
    }
    strcpy(h->name, name);
    strcpy(h->value, value);
    
    h->size = strlen(h->name) + strlen(h->value) + OVERHEAD_TABLE_SIZE;
    
    PUSH_HEADER((*dynamic), h);
    *dynamic_count += 1;
    
    http2_dynamic_table_size_rotate(dynamic, dynamic_count, table_size, err);
    
    return 0;
}

int http2_window_update_calc(HTTP2_SETTINGS *http2_setting, unsigned int incremental_window_size, char *err)
{
    if(http2_setting[SETTINGS_INITIAL_WINDOW_SIZE].setting_value < incremental_window_size)
    {
        if((http2_setting[SETTINGS_INITIAL_WINDOW_SIZE].setting_value + incremental_window_size) > MAX_SETTING_LENGTH)
        {
            HTTP2_PRINT_ERROR(err, "Window size exceed [%d] [%d]", MAX_SETTING_LENGTH, (http2_setting[SETTINGS_INITIAL_WINDOW_SIZE].setting_value + incremental_window_size));
            return -1;
        }
        http2_setting[SETTINGS_INITIAL_WINDOW_SIZE].setting_value += incremental_window_size;
    }
    
    if(http2_setting[SETTINGS_INITIAL_WINDOW_SIZE].current_value > incremental_window_size)
    {
        http2_setting[SETTINGS_INITIAL_WINDOW_SIZE].current_value -= incremental_window_size;
    }
    else
    {
        http2_setting[SETTINGS_INITIAL_WINDOW_SIZE].current_value = 0;
    }
    
    return 0;
}

int http2_get_setting_value(HTTP2_CONNECTION *conn, int current_value, SETTING_TYPE type)
{
    if(type < SETTINGS_HEADER_TABLE_SIZE || type >= MAX_SETTINGS_SIZE)
    {
        return -1;
    }
    if(current_value) return conn->http2_settings_recv[type].current_value;
    else return conn->http2_settings_recv[type].setting_value;
}

int http2_valid(STREAM_INFO *info, char *err)
{
    HTTP2_HEADER *header = info->data_recv.first_header_list;
    char scheme_f, status_f, content_length_f, method_f;
    int content_length = 0;
    method_f = scheme_f = status_f = content_length_f = 0;
    while(header)
    {
        if(!strcmp(header->name, static_table[IDX_SCHEME_HTTP].header.name))
        {
            if(!strcmp(header->value, "http") || !strcmp(header->value, "https"))
            {
                scheme_f = 1;
            }
            else
            {
                HTTP2_PRINT_ERROR(err, "Header [%s] value [%s] not support", header->name, header->value);
                return 0;
            }
        }
        else if(!strcmp(header->name, static_table[IDX_STATUS_200].header.name))
        {
            int _status_code = atoi(header->value);
            if(_status_code < 100 || _status_code > 999)
            {
                HTTP2_PRINT_ERROR(err, "Invalid status code [%s]", header->value);
                return 0;
            }
            status_f = 1;
        }
        else if(!strcmp(header->name, static_table[IDX_CONTENT_LENGTH].header.name))
        {
            content_length = atoi(header->value);
            if(content_length != info->data_recv.data_len)
            {
                HTTP2_PRINT_ERROR(err, "Invalid content_length [%d] are conflict with data length [%d]", content_length, info->data_recv.data_len);
                return 0;
            }
            content_length_f = 1;
        }
        else if(!strcmp(header->name, static_table[IDX_METHOD_GET].header.name))
        {
            method_f = 1;
        }
        if(scheme_f && status_f && content_length_f && method_f) break;
        header = header->next;
    }
    if((method_f && status_f) || !(method_f || status_f))
    {
        HTTP2_PRINT_ERROR(err, "Invalid header");
        return 0;
    }
    return 1;
}

int http2_conn_housekeeper(HTTP2_CONNECTION *conn, unsigned long stream_wait_timeout)
{
    int c;
    char err[1024];
    unsigned long begin_time = http2_get_current_time();
    if(conn->last_house_keeper < 0 || conn->last_house_keeper >= (MAX_STREAM_INFO_LIST - 1))
        conn->last_house_keeper = 0;
    for(c = conn->last_house_keeper; c < MAX_STREAM_INFO_LIST; c++)
    {
        unsigned long current_time = http2_get_current_time();
        if (current_time - begin_time > 200000)
            break;
        conn->last_house_keeper = c;
        if(conn->stream_info_list[c])
        {
            STREAM_INFO *s_tmp = conn->stream_info_list[c];
            STREAM_INFO *s_root = s_tmp;
            char root_change;
            do
            {
                root_change = 0;
                if((s_tmp->active_time + (stream_wait_timeout * 1000000)) < http2_get_current_time())
                {
                    if(s_root == s_tmp) root_change = 1;
                    http2_reset_stream_build(conn, s_tmp->stream_id, HTTP2_ERROR_CODE_CANCEL, "Wait timeout", err);
                    STREAM_INFO *rm_tmp = s_tmp->next;
                    LIST_REMOVE(conn->stream_info_list[c], s_tmp);
					s_tmp->state = FRAME_STATE_CLOSE;
                    http2_stream_info_destroy(&s_tmp, HTTP2_ERROR_CODE_REFUSED_STREAM, "Wait timeout");
                    s_tmp = rm_tmp;
                    if(root_change) s_root = conn->stream_info_list[c];
                }
                else
                {
                    break;
                }
            } while(conn->stream_info_list[c] && (s_tmp != conn->stream_info_list[c] || root_change));
        }
    }
    return 0;
}

unsigned long http2_get_current_time()
{
    struct timeval end;
    gettimeofday(&end,NULL);
    return (unsigned long)((((unsigned long)end.tv_sec)*1000000) + (unsigned long)end.tv_usec);
}