#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "http2.h"
#include "http1.h"
#include "linklist.h"

typedef struct _user_data_decode_ {
    int curr;
    int is_chunked;
    int total_length;
    int is_header_end;
    char *body;
}DATA_DECODE;

char *http1_code_to_string(char *code);

char *http1_1_methods[] = {"HTTP/1", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"};
int http1_1_methods_sizes[] = {6, 7, 3, 4, 4, 3, 6, 5, 7};

#define HTTP_1_1_METHOD_COUNT    (sizeof(http1_1_methods_sizes)/sizeof(int))

static int get_header(char *data, unsigned int *curr, char *name, char *value) {
    char *data_p = data + *curr;
    if (*curr == 0) {
        data_p = strstr(data, "\r\n"); //Skip first line
    }
    if (data_p && data_p[0] != '\0') {
        data_p += 2; // Length of \r\n
        char *end_p = strstr(data_p, ":");
        if (end_p) {
            memcpy(name, data_p, end_p - data_p);
            name[end_p - data_p] = 0x0;
            int i = 0;
            for (; i < strlen(name); i++) {
                if (name[i] == ' ') {
                    name[i] = 0x0;
                    break;
                }
            }
            data_p = end_p + 1;
            value[0] = 0x0;
            int v = 0;
            for (i = 0; data_p[i] != '\r' && data_p[i] != '\0'; i++) {
                if (data_p[i] == ' ' && value[0] == 0x0) {
                    continue;
                }
                value[v++] = data_p[i];
            }
            value[v] = 0x0;
            data_p = &data_p[i];
            *curr = data_p - data;
        }
        if (data_p[0] != '\0') 
        {
            data_p = strstr(data_p, "\r\n");
            *curr = data_p - data;
        }
        return 0;
    }
    return -1;
}

int free_decode_data_callback(void *data, char *diag) {
    DATA_DECODE *decode = data;
    free(decode);
    return 0;
}

HTTP2_RETURN_CODE http1_decode(HTTP2_CONNECTION *conn, STREAM_INFO **info_ret, char *err) {
    char *end_header = NULL;
    int is_request = 0;
    if (conn->r_buffer->len <= 0 || (end_header = strstr(conn->r_buffer->data, "\r\n\r\n")) == NULL) {
        return HTTP2_RETURN_NEED_MORE_DATA;
    }
    
    DATA_DECODE *decode = NULL;
    conn->last_stream_id_send = 1;
    
    (*info_ret) = http2_find_stream_info(conn, 1);
    
    if (!(*info_ret)) {
        (*info_ret) = http2_init_stream_info_send(conn, 0, err);
        if (!(*info_ret)) {
            return HTTP2_RETURN_ERROR;
        }
        decode = (DATA_DECODE*) malloc (sizeof(DATA_DECODE));
        http2_stream_info_set_user_data(*info_ret, decode, free_decode_data_callback);
        memset(decode, 0, sizeof(DATA_DECODE));
    } else {
        decode = http2_stream_info_get_user_data(*info_ret);
        if (decode == NULL) {
            decode = (DATA_DECODE*) malloc (sizeof(DATA_DECODE));
            memset(decode, 0, sizeof(DATA_DECODE));
        }
    }
    
    STREAM_INFO *info = *info_ret;
    
    if (!decode->is_header_end) {
        int loop_count = 0;
        for(loop_count = 0; loop_count < HTTP_1_1_METHOD_COUNT; loop_count++)
        {
            if(!memcmp(conn->r_buffer->data, http1_1_methods[loop_count], http1_1_methods_sizes[loop_count]))
            {
                break;
            }
        }
        
        if (loop_count >= HTTP_1_1_METHOD_COUNT) {
            HTTP2_PRINT_ERROR(err, "Unknown message [%.*s..]", 128, conn->r_buffer->data);
            return HTTP2_RETURN_ERROR;
        }
        
        if (loop_count != 0) {
            is_request = 1;
        }
        
        if (is_request) {
            //Message Request
            info->state = FRAME_STATE_REMOTE_HALF_CLOSE;
            http2_add_header_recv(info, ":method", http1_1_methods[loop_count], err);
            char *path = strstr(conn->r_buffer->data, " ");
            if (path) {
                path += 1;
                char *end_path = strstr(path, " ");
                if (end_path) {
                    *end_path = 0x0;
                    http2_add_header_recv(info, ":path", path, err);
                    *end_path = ' ';
                }
                else {
                    HTTP2_PRINT_ERROR(err, "Invalid message [%.*s..]", 128, conn->r_buffer->data);
                    return HTTP2_RETURN_ERROR;
                }
            }
            else {
                HTTP2_PRINT_ERROR(err, "Invalid message [%.*s..]", 128, conn->r_buffer->data);
                return HTTP2_RETURN_ERROR;
            }
        } else {
            //Message Response
            info->state = FRAME_STATE_CLOSE;
            char *status = strstr(conn->r_buffer->data, " ");
            if (status) {
                status += 1;
                char *end_status = strstr(status, " ");
                if (end_status) {
                    *end_status = 0x0;
                    http2_add_header_recv(info, ":status", status, err);
                    *end_status = ' ';
                }
                else {
                    HTTP2_PRINT_ERROR(err, "Invalid message [%.*s..]", 128, conn->r_buffer->data);
                    return HTTP2_RETURN_ERROR;
                }
            }
            else {
                HTTP2_PRINT_ERROR(err, "Invalid message [%.*s..]", 128, conn->r_buffer->data);
                return HTTP2_RETURN_ERROR;
            }
        }
        int ret = 0;
        char name[256];
        char value[4096];
        *end_header = 0x0;
        decode->curr = 0;
        while ((ret = get_header(conn->r_buffer->data, (unsigned int *)&(decode->curr), name, value)) == 0) {
            http2_add_header_recv(info, name, value, err);
            if (strcasecmp(name, "content-length") == 0) {
                decode->total_length = atoi(value);
            } else if ((strcasecmp(name, "transfer-encoding") == 0) && (strcasecmp(value, "chunked") == 0)) {
                decode->is_chunked = 1;
            }
        }
        decode->is_header_end = 1;
        *end_header = '\r';
        decode->body = end_header + 4;
    }
    
    if (!decode->is_chunked) {
        int curr_recv_body = conn->r_buffer->len - (decode->body - conn->r_buffer->data);
        if (curr_recv_body >= decode->total_length && decode->total_length <= MY_MAX_BODY_SIZE) {
            http2_add_data_recv(info, decode->body, decode->total_length, err);
            conn->r_buffer->len = 0; //Not support multiple request
            http2_stream_info_set_user_data(info, NULL, NULL);
            info->data_recv.stream_flag = FLAG_ENDSTREAM_TRUE;
            free(decode);
            return HTTP2_RETURN_SUCCESS;
        } else if (decode->total_length > MY_MAX_BODY_SIZE) {
            HTTP2_PRINT_ERROR(err, "Data entity too large [%d].", decode->total_length);
            return HTTP2_RETURN_ERROR;
        }
    } else {
        //Chunked message
        char chunked_size[9];
        char *end_p = NULL;
        while (1) {
            memmove(conn->r_buffer->data, decode->body, conn->r_buffer->len - (decode->body - conn->r_buffer->data));
            conn->r_buffer->len -= decode->body - conn->r_buffer->data;
            
            if ((end_p = strstr(conn->r_buffer->data, "\r\n")) == NULL) {
                return HTTP2_RETURN_NEED_MORE_DATA;
            }
            
            if (end_p - conn->r_buffer->data > 8) {
                HTTP2_PRINT_ERROR(err, "Cannot decode chunked data [Invalid length of chunked morethan max size of body].");
                return HTTP2_RETURN_ERROR;
            }
            
            memcpy(chunked_size, conn->r_buffer->data, end_p - conn->r_buffer->data);
            chunked_size[end_p - conn->r_buffer->data] = 0x0;
            char *end_fn = NULL;
            long chunked_len = strtol(chunked_size, &end_fn, 16);
            if (*end_fn != 0x0) {
                HTTP2_PRINT_ERROR(err, "Invalid hex chunked size [%s].", chunked_size);
                return HTTP2_RETURN_ERROR;
            }
            
            if (chunked_len == 0) {
                conn->r_buffer->len = 0;
                http2_stream_info_set_user_data(info, NULL, NULL);
                free(decode);
                info->data_recv.stream_flag = FLAG_ENDSTREAM_TRUE;
                return HTTP2_RETURN_SUCCESS;
            }
            
            if (decode->total_length + chunked_len > MY_MAX_BODY_SIZE) {
                HTTP2_PRINT_ERROR(err, "Data entity too large [more than %ld].", decode->total_length + chunked_len);
                return HTTP2_RETURN_ERROR;
            }
            
            if (conn->r_buffer->len < chunked_len) {
                return HTTP2_RETURN_NEED_MORE_DATA;
            }

            decode->body = end_p + 2;
            decode->total_length += chunked_len;
            
            http2_add_data_recv(info, decode->body, chunked_len, err);
            decode->body += chunked_len + 2;
        }
    }
    
    return HTTP2_RETURN_NEED_MORE_DATA;
}

void http1_header_to_upper(char *header_name) {
    if (header_name == NULL) return;
    
    header_name[0] = toupper(header_name[0]);
    
    char *dash = strchr(header_name, '-');
    
    while (dash != NULL) {
        dash = dash + 1;
        *dash = toupper(*dash);
        dash = strchr(dash, '-');
    }
}

int http1_create_msg(STREAM_INFO *info, int to_upper, char *describe, char *err) {
    HTTP2_HEADER *h = info->data_send.first_header_list;
    int is_request = 1;
    HTTP2_DATA *data_buff = NULL;
    if (h) {
        HTTP2_HEADER *h_name = NULL;
        HTTP2_HEADER *url_name = NULL;
        while (h) {
            if (strcasecmp(h->name, ":method") == 0) {
                h_name = h;
                is_request = 1;
            } else if (strcasecmp(h->name, ":path") == 0) {
                url_name = h;
            }else if (strcasecmp(h->name, ":status") == 0) {
                h_name = h;
                is_request = 0;
            }
            h = h->next;
            if (!h) {
                char len_buff[16];
                sprintf(len_buff, "%d", (int)info->data_send.data_len);
                http2_add_header(info, "content-lengthx", len_buff, err);
            }
        }
        
        if (data_alloc(&data_buff, 4096, err) != 0) {
            if (data_buff) {
                free(data_buff);
            }
            return -1;
        }
        
        if (is_request) {
            info->state = FRAME_STATE_LOCAL_HALF_CLOSE;
            data_buff->len += sprintf(data_buff->data, "%s %s HTTP/1.1\r\n", (h_name)?h_name->value:"GET", (url_name)?url_name->value:"/");
        } else {
            info->state = FRAME_STATE_CLOSE;
            data_buff->len += sprintf(data_buff->data, "HTTP/1.1 %s %s\r\n",
                                     (h_name)?h_name->value:"200",
                                     (describe)?describe:(h_name)?http1_code_to_string(h_name->value):"OK");
        }
        
        HTTP2_HEADER *h_temp;
        while (info->data_send.first_header_list) {
            POP_HEADER(info->data_send.first_header_list, h_temp);
            if (h_temp->name[0] == ':' || !strcasecmp(h_temp->name, "content-length")) {
                free(h_temp);
                continue;
            }
            
            if(!strcasecmp(h_temp->name, "content-lengthx")) {
                h_temp->name[strlen(h_temp->name) - 1] = 0x0;
            }
            
            if (to_upper) {
                http1_header_to_upper(h_temp->name);
            }
            
            if (data_alloc(&data_buff, strlen(h_temp->name) + strlen(h_temp->value) + 9, err) != 0) {
                if (data_buff) {
                    free(h_temp);
                    free(data_buff);
                }
                return -1;
            }
            
            data_buff->len += sprintf(data_buff->data + data_buff->len, "%s: %s\r\n", h_temp->name, h_temp->value);
            free(h_temp);
        }
        
        data_buff->len += sprintf(data_buff->data + data_buff->len, "\r\n");
        
        LIST_APPEND(info->conn->w_buffer, data_buff);
    }
    if (info->data_send.data_len > 0) {
        data_buff = NULL;
        if (data_alloc(&data_buff, info->data_send.data_len + 13, err) != 0) {
            if (data_buff) {
                free(data_buff);
            }
            return -1;
        }
        memcpy(data_buff->data + data_buff->len, info->data_send.data, info->data_send.data_len);
        data_buff->len += info->data_send.data_len;
        info->data_send.data_len = 0;
        free(info->data_send.data);
        info->data_send.data = NULL;
        LIST_APPEND(info->conn->w_buffer, data_buff);
    }
    
    return 0;
}

int http1_create_msg_chunke(STREAM_INFO *info, int to_upper, char *describe, int is_end, char *err) {
    HTTP2_HEADER *h = info->data_send.first_header_list;
    int is_request = 1;
    HTTP2_DATA *data_buff = NULL;
    if (h) {
        HTTP2_HEADER *h_name = NULL;
        HTTP2_HEADER *url_name = NULL;
        while (h) {
            if (strcasecmp(h->name, ":method") == 0) {
                h_name = h;
                is_request = 1;
            } else if (strcasecmp(h->name, ":path") == 0) {
                url_name = h;
            }else if (strcasecmp(h->name, ":status") == 0) {
                h_name = h;
                is_request = 0;
            }
            h = h->next;
            if (!h) {
                http2_add_header(info, "transfer-encoding", "chunked", err);
            }
        }
        
        if (data_alloc(&data_buff, 4096, err) != 0) {
            if (data_buff) {
                free(data_buff);
            }
            return -1;
        }
        
        if (is_request) {
            info->state = FRAME_STATE_LOCAL_HALF_CLOSE;
            data_buff->len += sprintf(data_buff->data, "%s %s HTTP/1.1\r\n", (h_name)?h_name->value:"GET", (url_name)?url_name->value:"/");
        } else {
            info->state = FRAME_STATE_CLOSE;
            data_buff->len += sprintf(data_buff->data, "HTTP/1.1 %s %s\r\n",
                                     (h_name)?h_name->value:"200",
                                     (describe)?describe:(h_name)?http1_code_to_string(h_name->value):"OK");
        }
        
        HTTP2_HEADER *h_temp;
        HTTP2_HEADER *h = info->data_send.first_header_list;
        while (h) {
            POP_HEADER(h, h_temp);
            if (h_temp->name[0] == ':' || strcasecmp(h_temp->name, "content-length")) {
                continue;
            }
            
            if (to_upper) {
                http1_header_to_upper(h_temp->name);
            }
            
            if (data_alloc(&data_buff, strlen(h_temp->name) + strlen(h_temp->value) + 9, err) != 0) {
                if (data_buff) {
                    free(data_buff);
                }
                return -1;
            }
            
            data_buff->len += sprintf(data_buff->data + data_buff->len, "%s: %s\r\n", h_temp->name, h_temp->value);
        }
        
        data_buff->len += sprintf(data_buff->data + data_buff->len, "\r\n");
        
        LIST_APPEND(info->conn->w_buffer, data_buff);
    }
    int max_data_size = info->conn->http2_settings_recv[SETTINGS_MAX_FRAME_SIZE].setting_value;
    while (info->data_send.data_len > 0) {
        data_buff = NULL;
        if (info->data_send.data_len > max_data_size) {
            if (data_alloc(&data_buff, max_data_size + 13, err) != 0) {
                if (data_buff) {
                    free(data_buff);
                }
                return -1;
            }
            
            data_buff->len += sprintf(data_buff->data, "%x\r\n", max_data_size);
            memcpy(data_buff->data + data_buff->len, info->data_send.data, max_data_size);
            data_buff->len += max_data_size;
            data_buff->len += sprintf(data_buff->data + data_buff->len, "\r\n");
            
            memmove(info->data_send.data, info->data_send.data + max_data_size, info->data_send.data_len - max_data_size);
            info->data_send.data_len -= max_data_size;
            LIST_APPEND(info->conn->w_buffer, data_buff);
        } else {
            if (data_alloc(&data_buff, max_data_size + 13, err) != 0) {
                if (data_buff) {
                    free(data_buff);
                }
                return -1;
            }
            data_buff->len += sprintf(data_buff->data, "%x\r\n", info->data_send.data_len);
            memcpy(data_buff->data + data_buff->len, info->data_send.data, info->data_send.data_len);
            data_buff->len += info->data_send.data_len;
            data_buff->len += sprintf(data_buff->data + data_buff->len, "\r\n");
            info->data_send.data_len = 0;
            free(info->data_send.data);
            info->data_send.data = NULL;
            LIST_APPEND(info->conn->w_buffer, data_buff);
        }
    }
    
    if (is_end) {
        data_buff = NULL;
        if (data_alloc(&data_buff, 4, err) != 0) {
            if (data_buff) {
                free(data_buff);
            }
            return -1;
        }
        
        data_buff->len += sprintf(data_buff->data, "0\r\n");
        LIST_APPEND(info->conn->w_buffer, data_buff);
    }
    
    return 0;
}

char *http1_code_to_string(char *code) {
    int code_i = atoi(code);
    
    switch (code_i) {
        //Too many used
        case 200: return "OK";
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        
        //Basic
        case 102: return "Processing";
        case 103: return "Early Hints";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 207: return "Multi-Status";
        case 208: return "Already Reported";
        case 226: return "IM Used";
        
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 306: return "Switch Proxy";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 418: return "I'm a teapot";
        case 421: return "Misdirected Request";
        case 422: return "Unprocessable Entity";
        case 423: return "Locked";
        case 424: return "Failed Dependency";
        case 425: return "Too Early";
        case 426: return "Upgrade Required";
        case 428: return "Precondition Required";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 451: return "Unavailable For Legal Reasons";
        
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        case 506: return "Variant Also Negotiates";
        case 507: return "Insufficient Storage";
        case 508: return "Loop Detected";
        case 510: return "Not Extended";
        case 511: return "Network Authentication Required";
        default: return "Unknown";
    }
}
