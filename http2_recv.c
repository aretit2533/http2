#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "http2.h"
#include "huffman.h"
#include "linklist.h"
#include "http2_macro.h"

char *http1_1_method[] = {"OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "HTTP/1"};
int http1_1_method_size[] = {7, 3, 4, 4, 3, 6, 5, 7, 6};
#define HTTP1_1_STRING           "HTTP/1"

#define HTTP_1_1_METHOD_COUNT    (sizeof(http1_1_method_size)/sizeof(int))
static int http2_extract_push_promise(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err);
static void http2_extract_goaway(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err);
static int http2_extract_setting(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err);
static int http2_extract_window_update(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err);
static int http2_extract_header(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err);
static int http2_extract_data(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err);


/*static void print_hex(char *data, int len)
{
    int i = 0;
    int b_len = 0;
    char buff[(len * 3)+1];
    for(i = 0; i < len; i++)
    {
        b_len += sprintf(buff + b_len, "%02x ", (data[i] & 0xff));
    }
    printf("%s\n", buff);
}*/

//find_table_by_index return 0 if fail 1 if success
int find_table_by_index(HTTP2_CONNECTION *conn, int index, char *name, char *value)
{
    int count = MAX_STATIC_TABLE_INDEX;
    if(index >= MAX_STATIC_TABLE_INDEX)
    {
        HTTP2_HEADER *h_buff = conn->dynamic_table_recv;
        while(1)
        {
            if(!h_buff || count == index)
                break;
            h_buff = h_buff->next;
            count++;
        }
        if(!h_buff)
            return 0;
        strcpy(name, h_buff->name);
        strcpy(value, h_buff->value);
        return 1;
    }
    else if(index > IDX_NOT_USE)
    {
        strcpy(name, static_table[index].header.name);
        strcpy(value, static_table[index].header.value);
        return 1;
    }
    return 0;
}
//find_table_name_by_index return 0 if fail 1 if success
int find_table_name_by_index(HTTP2_CONNECTION *conn, int index, char *name)
{
    int count = MAX_STATIC_TABLE_INDEX;
    if(index >= MAX_STATIC_TABLE_INDEX)
    {
        HTTP2_HEADER *h_buff = conn->dynamic_table_recv;
        while(1)
        {
            if(!h_buff || count == index)
                break;
            h_buff = h_buff->next;
            count++;
        }
        if(!h_buff)
            return 0;
        strcpy(name, h_buff->name);
        return 1;
    }
    else if(index > IDX_NOT_USE)
    {
        strcpy(name, static_table[index].header.name);
        return 1;
    }
    return 0;
}

void http2_extract_overhead(char *raw_data, unsigned int *stream_id, int *frame_type, int *frame_len, int *flag)
{
    int curr = 0;
    *stream_id = *frame_type = *frame_len = *flag = 0;
    GET_DATA_LENGTH_BYTE(raw_data + curr, *frame_len, FRAME_LEN_SIZE);
    curr += FRAME_LEN_SIZE;
    GET_DATA_LENGTH_BYTE(raw_data + curr, *frame_type, TYPE_SIZE);
    curr += TYPE_SIZE;
    GET_DATA_LENGTH_BYTE(raw_data + curr, *flag, FLAG_SIZE);
    curr += FLAG_SIZE;
    GET_DATA_LENGTH_BYTE(raw_data + curr, *stream_id, STREAM_ID_SIZE);
    curr += STREAM_ID_SIZE;
    
    *stream_id &= MAX_STREAM_ID;
}

static int http2_add_header_recv(STREAM_INFO *info, char *name, char *value, char *err)
{
    HTTP2_HEADER *header = (HTTP2_HEADER *) malloc(sizeof(HTTP2_HEADER));
    if(!header)
    {
        HTTP2_PRINT_ERROR(err, "Can not allocate memory size (%lu)", sizeof(HTTP2_HEADER));
        return -1;
    }
    strcpy(header->name, name);
    strcpy(header->value, value);
    printf("Add header name[%s] value [%s]\n", header->name, header->value);
    APPEND_HEADER(info->data_recv.first_header_list, info->data_recv.last_header, header);
    
    return 0;
}

static int http2_add_data_recv(STREAM_INFO *info, char *data, int len, char *err)
{
    if(info->data_recv.data != NULL)
    {
        char *x_buff = (char *) realloc(info->data_recv.data, info->data_recv.data_len + len + 1);
        if(!x_buff)
        {
            HTTP2_PRINT_ERROR(err, "Can not allocate memory size (%d)", info->data_send.data_len + len);
            return -1;
        }
        info->data_recv.data = x_buff;
    }
    else
    {
        info->data_recv.data = (char*)malloc(len + 1);
        info->data_recv.data_len = 0;
    }
    
    memcpy(info->data_recv.data + info->data_recv.data_len, data, len);
    
    info->data_recv.data_len += len;
    return 0;
}

static int http2_extract_push_promise(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err)
{
    if(!frame_len || frame_len < STREAM_ID_SIZE)
    {
        HTTP2_PRINT_ERROR(err, "Recv push_promise without StreamID");
        return HTTP2_RETURN_ERROR;
    }
    info->stream_id = 0;
    info->stream_pp = 1;
    GET_DATA_LENGTH_BYTE(process_p, info->stream_id, STREAM_ID_SIZE);
    frame_len -= STREAM_ID_SIZE;
    process_p += STREAM_ID_SIZE;
    switch(info->state)
    {
        case FRAME_STATE_IDLE:
             info->state = FRAME_STATE_REMOTE_RESERV;
             break;
        default:
             info->state = FRAME_STATE_CLOSE;
             HTTP2_PRINT_ERROR(err, "Recv push_promise invalid state [%d]",  info->state);
             http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_FLOW_CONTROL_ERROR, "", err);
             return HTTP2_RETURN_STREAM_CLOSE;
    }
    if(frame_len > 0)
    {
        info->state = FRAME_STATE_LOCAL_HALF_CLOSE;
        return http2_extract_header(conn, info, process_p, frame_len, flag, err);
    }
    
    return HTTP2_RETURN_SUCCESS;
}

static void http2_extract_goaway(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err)
{
    unsigned int last_stream_id_recv = 0;
    unsigned int err_code = 0;
    char goaway_diag[256];
    goaway_diag[0] = 0x0;
    GET_DATA_LENGTH_BYTE(process_p , last_stream_id_recv, STREAM_ID_SIZE);
    process_p += STREAM_ID_SIZE;
    GET_DATA_LENGTH_BYTE(process_p  , err_code, ERROR_CODE_SIZE);
    process_p += ERROR_CODE_SIZE;
    if(frame_len > STREAM_ID_SIZE + ERROR_CODE_SIZE)
    {
        memcpy(goaway_diag, process_p, frame_len - (STREAM_ID_SIZE + ERROR_CODE_SIZE));
        goaway_diag[frame_len - (STREAM_ID_SIZE + ERROR_CODE_SIZE)] = 0x0;
    }

    HTTP2_PRINT_ERROR(err, "recv FRAME_TYPE_GOAWAY [%u;%u;%s]", last_stream_id_recv, err_code, goaway_diag);
}

static int http2_extract_setting(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err)
{
    if(info)
    {
        return HTTP2_RETURN_SKIP_DATA;
    }
    if(flag & SETTING_ACK_FLAG)
    {
        return HTTP2_RETURN_SKIP_DATA;
    }
    http2_build_setting_ack(conn, err);
    int curr, setting_id, setting_val;
    for(curr = 0; curr < frame_len;)
    {
        setting_id = setting_val = 0;
        GET_DATA_LENGTH_BYTE(process_p + curr, setting_id, SETTING_ID_SIZE);
        curr += SETTING_ID_SIZE;
        GET_DATA_LENGTH_BYTE(process_p + curr, setting_val, SETTING_VAL_SIZE);
        curr += SETTING_VAL_SIZE;
        switch(setting_id)
        {
            case SETTINGS_HEADER_TABLE_SIZE:
            case SETTINGS_MAX_CONCURRENT_STREAMS:
            case SETTINGS_INITIAL_WINDOW_SIZE:
            case SETTINGS_MAX_HEADER_LIST_SIZE:
                 conn->http2_settings_recv[setting_id].setting_value = setting_val;
                 break;
            case SETTINGS_ENABLE_PUSH:
                 if(setting_val < 0 || setting_val > 1)
                 {
                     HTTP2_PRINT_ERROR(err, "Invalid value for SETTINGS_ENABLE_PUSH [0x%08x]", setting_val);
                     return HTTP2_RETURN_ERROR;
                 }
                 conn->http2_settings_recv[setting_id].setting_value = setting_val;
                 break;
            case SETTINGS_MAX_FRAME_SIZE:
                 if(setting_val < DEFAULT_SETTINGS_MAX_FRAME_SIZE || setting_val > MAX_SETTINGS_MAX_FRAME_SIZE)
                 {
                     HTTP2_PRINT_ERROR(err, "Invalid value for SETTINGS_MAX_FRAME_SIZE [0x%08x]", setting_val);
                     return HTTP2_RETURN_ERROR;
                 }
                 conn->http2_settings_recv[setting_id].setting_value = setting_val;
                 break;
            default:
                 HTTP2_PRINT_ERROR(err, "Invalid setting id [0x%02x]", setting_id);
                 return HTTP2_RETURN_ERROR;
        }
    }
    return HTTP2_RETURN_SKIP_DATA;
}

static int http2_extract_window_update(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err)
{
    if(frame_len > 0 && !info)
    {
        unsigned int len;
        GET_DATA_LENGTH_BYTE(process_p, len, SETTING_VAL_SIZE);
        if(http2_window_update_calc(conn->http2_settings_recv, len, err))
        {
            return HTTP2_RETURN_ERROR;
        }
    }
    return HTTP2_RETURN_SKIP_DATA;
}

static int http2_extract_header(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err)
{
    if(!info)
    {
        HTTP2_PRINT_ERROR(err, "Recv header from stream id 0");
        return HTTP2_RETURN_ERROR;
    }
    if(frame_len == 0 && !(flag & FLAG_ENDHEADER_TRUE))
    {
        HTTP2_PRINT_ERROR(err, "Recv header len 0 but not END_HEADER flag");
        return HTTP2_RETURN_ERROR;
    }
    if(frame_len == 0)
    {
        return HTTP2_RETURN_SUCCESS;
    }

    info->data_recv.stream_flag |= flag;
    
    if(!(info->data_recv.stream_flag & FLAG_ENDHEADER_TRUE) && (info->data_recv.stream_flag & FLAG_ENDSTREAM_TRUE))
    {
        http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_FLOW_CONTROL_ERROR, "Receive end stream but header not complete", err);
        return HTTP2_RETURN_STREAM_CLOSE;
    }
    
    switch(info->state)
    {
        case FRAME_STATE_IDLE:
        case FRAME_STATE_OPEN:
             info->state = (info->data_recv.stream_flag & FLAG_ENDSTREAM_TRUE) ? FRAME_STATE_REMOTE_HALF_CLOSE:FRAME_STATE_OPEN;
             break;
        case FRAME_STATE_LOCAL_HALF_CLOSE:
        case FRAME_STATE_REMOTE_HALF_CLOSE:
             if(!info->stream_pp)
             {
                 info->state = (info->data_recv.stream_flag & FLAG_ENDSTREAM_TRUE) ? FRAME_STATE_CLOSE:FRAME_STATE_LOCAL_HALF_CLOSE;
             }
             break;
        default:
             info->state = FRAME_STATE_CLOSE;
             HTTP2_PRINT_ERROR(err, "Recv header invalid state [%d]", info->state);
             http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_FLOW_CONTROL_ERROR, "", err);
             return HTTP2_RETURN_STREAM_CLOSE;
    }
    int curr, index, len;
    
    char name[HTTP_H_NAME_SIZE];
    char value[HTTP_H_VALUE_SIZE];
    char buff[HTTP_H_VALUE_SIZE];
    curr = 0;
    
    //TODO: Care of dependency stream and weight
    
    //Current skip priority stream dependency and weight (5 byte)
    if(flag & FLAG_PRIORYTY_TRUE)
    {
        curr += 5;
    }

    for(; curr < frame_len;)
    {
        index = len = 0;
        memset(name, 0, HTTP_H_NAME_SIZE);
        memset(value, 0, HTTP_H_VALUE_SIZE);
        GET_DATA_LENGTH_BYTE(process_p + curr, index, HEADER_INDEX_SIZE);
        if(index & HEADER_TYPE_INDEXED)
        {
            //Indexed
            *(process_p + curr) &= (~HEADER_TYPE_INDEXED);
            index = hf_integer_decode(process_p + curr, HEADER_TYPE_INDEXED_NBIT, &curr);
            if(!(find_table_by_index(conn, index & (~HEADER_TYPE_INDEXED), name, value)))
            {
                HTTP2_PRINT_ERROR(err, "Header Index [%d] not found in table", index & (~HEADER_TYPE_INDEXED));
                http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_COMPRESSION_ERROR, "", err);
                return HTTP2_RETURN_STREAM_CLOSE;
            }
            printf("indexing [%d]\n", index);
            if(http2_add_header_recv(info, name, value, err))
            {
                return HTTP2_RETURN_ERROR;
            }
            continue;
        }
        else if(index & HEADER_TYPE_INCREMENTAL_INDEX)
        {
            *(process_p + curr) &= (~HEADER_TYPE_INCREMENTAL_INDEX);
            index = hf_integer_decode(process_p + curr, HEADER_TYPE_INCREMENTAL_INDEX_NBIT, &curr);
            if(index)
            {
                //Indexed name
                if(!(find_table_name_by_index(conn, index, name)))
                {
                    HTTP2_PRINT_ERROR(err, "Header Index [%d] not found in table", index & (~HEADER_TYPE_INDEXED));
                    http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_COMPRESSION_ERROR, "", err);
                    return HTTP2_RETURN_STREAM_CLOSE;
                }
                GET_DATA_LENGTH_BYTE(process_p + curr, len, HEADER_LEN_SIZE);
                if(len & HUFFMAN_ENCODE_PREFIX_LEN)
                {
                    *(process_p + curr) &= (~HUFFMAN_ENCODE_PREFIX_LEN);
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(buff, process_p + curr, len);
                    hf_string_decode((unsigned char *)buff, len, value, HTTP_H_VALUE_SIZE);
                }
                else
                {
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(value, process_p + curr, len);
                }
                curr += len;
                if(http2_dynamic_table_add(&(conn->dynamic_table_recv), &(conn->dynamic_table_recv_count), name, value, info->conn->http2_settings_recv[SETTINGS_HEADER_TABLE_SIZE].setting_value, err) != 0)
                {
                    return HTTP2_RETURN_ERROR;
                }
                if(http2_add_header_recv(info, name, value, err))
                {
                    return HTTP2_RETURN_ERROR;
                }
                continue;
            }
            else
            {
                //New name
                GET_DATA_LENGTH_BYTE(process_p + curr, len, HEADER_LEN_SIZE);
                if(len & HUFFMAN_ENCODE_PREFIX_LEN)
                {
                    *(process_p + curr) &= (~HUFFMAN_ENCODE_PREFIX_LEN);
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(buff, process_p + curr, len);
                    
                    hf_string_decode((unsigned char *)buff, len, name, HTTP_H_VALUE_SIZE);
                }
                else
                {
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(name, process_p + curr, len);
                    
                }
                curr += len;
                
                GET_DATA_LENGTH_BYTE(process_p + curr, len, HEADER_LEN_SIZE);
                if(len & HUFFMAN_ENCODE_PREFIX_LEN)
                {
                    *(process_p + curr) &= (~HUFFMAN_ENCODE_PREFIX_LEN);
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(buff, process_p + curr, len);
                    
                    hf_string_decode((unsigned char *)buff, len, value, HTTP_H_VALUE_SIZE);
                }
                else
                {
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(value, process_p + curr, len);
                    
                }
                curr += len;
                if(http2_dynamic_table_add(&(conn->dynamic_table_recv), &(conn->dynamic_table_recv_count), name, value, info->conn->http2_settings_recv[SETTINGS_HEADER_TABLE_SIZE].setting_value, err) != 0)
                {
                    return HTTP2_RETURN_ERROR;
                }
                if(http2_add_header_recv(info, name, value, err))
                {
                    return HTTP2_RETURN_ERROR;
                }
                continue;
            }
        }
        else if(index & HEADER_DYNAMIC_TABLE_SIZE_UPDATE)
        {
            *(process_p + curr) &= (~HEADER_DYNAMIC_TABLE_SIZE_UPDATE);
            len = hf_integer_decode(process_p + curr, HEADER_DYNAMIC_TABLE_SIZE_UPDATE_NBIT, &curr);
            conn->http2_settings_recv[SETTINGS_HEADER_TABLE_SIZE].setting_value = len;
            continue;
        }
        else if(index & HEADER_TYPE_NERVER_INDEX)
        {
            *(process_p + curr) &= (~HEADER_TYPE_NERVER_INDEX);
            index = hf_integer_decode(process_p + curr, HEADER_TYPE_NERVER_INDEX_NBIT, &curr);
            if(index)
            {
                //Indexed name
                if(!(find_table_name_by_index(conn, index, name)))
                {
                    HTTP2_PRINT_ERROR(err, "Header Index [%d] not found in table", index);
                    http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_COMPRESSION_ERROR, "", err);
                    return HTTP2_RETURN_STREAM_CLOSE;
                }
                GET_DATA_LENGTH_BYTE(process_p + curr, len, HEADER_LEN_SIZE);
                if(len & HUFFMAN_ENCODE_PREFIX_LEN)
                {
                    *(process_p + curr) &= (~HUFFMAN_ENCODE_PREFIX_LEN);
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(buff, process_p + curr, len);
                    
                    hf_string_decode((unsigned char *)buff, len, value, HTTP_H_VALUE_SIZE);
                }
                else
                {
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(value, process_p + curr, len);
                    
                }
                curr += len;
                if(http2_add_header_recv(info, name, value, err))
                {
                    return HTTP2_RETURN_ERROR;
                }
                continue;
            }
            else
            {
                //New name
                GET_DATA_LENGTH_BYTE(process_p + curr, len, HEADER_LEN_SIZE);
                
                if(len & HUFFMAN_ENCODE_PREFIX_LEN)
                {
                    *(process_p + curr) &= (~HUFFMAN_ENCODE_PREFIX_LEN);
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(buff, process_p + curr, len);
                    
                    hf_string_decode((unsigned char *)buff, len, name, HTTP_H_VALUE_SIZE);
                }
                else
                {
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(name, process_p + curr, len);
                    
                }
                curr += len;
                
                GET_DATA_LENGTH_BYTE(process_p + curr, len, HEADER_LEN_SIZE);
                
                if(len & HUFFMAN_ENCODE_PREFIX_LEN)
                {
                    *(process_p + curr) &= (~HUFFMAN_ENCODE_PREFIX_LEN);
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(buff, process_p + curr, len);
                    
                    hf_string_decode((unsigned char *)buff, len, value, HTTP_H_VALUE_SIZE);
                }
                else
                {
                    
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(value, process_p + curr, len);
                    
                }
                curr += len;
                if(http2_add_header_recv(info, name, value, err))
                {
                    return HTTP2_RETURN_ERROR;
                }
                continue;
            }
        }
        else
        {
            index = hf_integer_decode(process_p + curr, HEADER_TYPE_WITHOUT_INDEX_NBIT, &curr);
            if(index)
            {
                //Indexed name
                if(!(find_table_name_by_index(conn, index, name)))
                {
                    HTTP2_PRINT_ERROR(err, "Header Index [%d] not found in table", index);
                    http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_COMPRESSION_ERROR, "", err);
                    return HTTP2_RETURN_STREAM_CLOSE;
                }
                GET_DATA_LENGTH_BYTE(process_p + curr, len, HEADER_LEN_SIZE);
                
                if(len & HUFFMAN_ENCODE_PREFIX_LEN)
                {
                    *(process_p + curr) &= (~HUFFMAN_ENCODE_PREFIX_LEN);
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(buff, process_p + curr, len);
                    hf_string_decode((unsigned char *)buff, len, value, HTTP_H_VALUE_SIZE);
                }
                else
                {
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(value, process_p + curr, len);
                }
                curr += len;
                if(http2_add_header_recv(info, name, value, err))
                {
                    return HTTP2_RETURN_ERROR;
                }
                continue;
            }
            else
            {
                //New name
                GET_DATA_LENGTH_BYTE(process_p + curr, len, HEADER_LEN_SIZE);
                
                if(len & HUFFMAN_ENCODE_PREFIX_LEN)
                {
                    *(process_p + curr) &= (~HUFFMAN_ENCODE_PREFIX_LEN);
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(buff, process_p + curr, len);
                    hf_string_decode((unsigned char *)buff, len, name, HTTP_H_VALUE_SIZE);
                }
                else
                {
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(name, process_p + curr, len);
                }
                curr += len;
                
                GET_DATA_LENGTH_BYTE(process_p + curr, len, HEADER_LEN_SIZE);
                
                if(len & HUFFMAN_ENCODE_PREFIX_LEN)
                {
                    *(process_p + curr) &= (~HUFFMAN_ENCODE_PREFIX_LEN);
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(buff, process_p + curr, len);
                    hf_string_decode((unsigned char *)buff, len, value, HTTP_H_VALUE_SIZE);
                }
                else
                {
                    len = hf_integer_decode(process_p + curr, HUFFMAN_ENCODE_PREFIX_LEN_NBIT, &curr);
                    memcpy(value, process_p + curr, len);
                }
                curr += len;
                if(http2_add_header_recv(info, name, value, err))
                {
                    return HTTP2_RETURN_ERROR;
                }
                continue;
            }
        }
    }
    
    return (info->data_recv.stream_flag & FLAG_ENDSTREAM_TRUE)? HTTP2_RETURN_SUCCESS:HTTP2_RETURN_NEED_NEXT_DATA;
}

static int http2_extract_data(HTTP2_CONNECTION *conn, STREAM_INFO *info, char *process_p, int frame_len, int flag, char *err)
{
    if(!info)
    {
        HTTP2_PRINT_ERROR(err, "Recv data from stream id 0");
        return HTTP2_RETURN_ERROR;
    }
    if(frame_len == 0 && !(flag & FLAG_ENDSTREAM_TRUE))
    {
        HTTP2_PRINT_ERROR(err, "Recv header len 0 but not END_STREAM flag");
        http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_PROTOCOL_ERROR, "Receive data after end stream", err);
        return HTTP2_RETURN_ERROR;
    }
    if(frame_len == 0)
    {
        return HTTP2_RETURN_SUCCESS;
    }    
    if((info->data_recv.stream_flag & FLAG_ENDSTREAM_TRUE))
    {
        http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_FLOW_CONTROL_ERROR, "Receive data after end stream", err);
        return HTTP2_RETURN_STREAM_CLOSE;
    }
    
    info->data_recv.stream_flag |= flag;
    
    switch(info->state)
    {
        case FRAME_STATE_OPEN:
             info->state = (info->data_recv.stream_flag & FLAG_ENDSTREAM_TRUE) ? FRAME_STATE_REMOTE_HALF_CLOSE:info->state;
             break;
        case FRAME_STATE_LOCAL_HALF_CLOSE:
        case FRAME_STATE_REMOTE_HALF_CLOSE:
             info->state = (info->data_recv.stream_flag & FLAG_ENDSTREAM_TRUE) ? FRAME_STATE_CLOSE:info->state;
             break;
        default:
             HTTP2_PRINT_ERROR(err, "Recv data invalid state [%d]", info->state);
			 info->state = FRAME_STATE_CLOSE;
             http2_reset_stream_build(conn, info->stream_id, HTTP2_ERROR_CODE_FLOW_CONTROL_ERROR, "", err);
             return HTTP2_RETURN_STREAM_CLOSE;
    }
    
    if(http2_add_data_recv(info, process_p, frame_len, err))
    {
        return HTTP2_RETURN_ERROR;
    }
    printf("^^^^^^^^^^^^^^^^^^^^^^^Recv data[%.*s]^^^^^^^^^^^^^^^^^^\n", frame_len, process_p);
    return (info->data_recv.stream_flag & FLAG_ENDSTREAM_TRUE)? HTTP2_RETURN_SUCCESS:HTTP2_RETURN_NEED_NEXT_DATA;
}

//Return code follow enum HTTP2_RETURN_CODE
HTTP2_RETURN_CODE http2_decode(HTTP2_CONNECTION *conn, STREAM_INFO **info_ret, int *frame_type_ret, char *err)
{
    static char *buff = NULL;
    static int buff_size = 0;
    char *process_p;
    int ret = HTTP2_RETURN_ERROR;
    if(!buff)
    {
        buff = (char *) malloc(conn->http2_settings_send[SETTINGS_MAX_FRAME_SIZE].setting_value + OVERHEAD_FRAME_SIZE);
        buff_size = conn->http2_settings_send[SETTINGS_MAX_FRAME_SIZE].setting_value;
    }
    if(buff_size < conn->http2_settings_send[SETTINGS_MAX_FRAME_SIZE].setting_value)
    {
        buff = (char *) realloc(buff, conn->http2_settings_send[SETTINGS_MAX_FRAME_SIZE].setting_value + OVERHEAD_FRAME_SIZE);
        buff_size = conn->http2_settings_send[SETTINGS_MAX_FRAME_SIZE].setting_value;
    }
    
    int frame_type, frame_len, flag, padd_len;
    unsigned int stream_id;
    printf("recv len %d\n", conn->r_buffer->len);
    if(conn->r_buffer->len < OVERHEAD_FRAME_SIZE)
        return HTTP2_RETURN_NEED_MORE_DATA;
    
    int loop_count;
    for(loop_count = 0; loop_count < HTTP_1_1_METHOD_COUNT; loop_count++)
    {
        if(!memcmp(conn->r_buffer->data, http1_1_method[loop_count], http1_1_method_size[loop_count]))
        {
            if(strstr(conn->r_buffer->data, HTTP1_1_STRING))
            {
                HTTP2_PRINT_ERROR(err, "Not support HTTP/1 version");
                return HTTP2_RETURN_PROTOCOL_VERSION_NOT_SUPPORT;
            }
        }
    }
    
    if(conn->r_buffer->len >= sizeof(http2_magic))
    {
        if(!memcmp(conn->r_buffer->data, http2_magic, sizeof(http2_magic)))
        {
            HTTP2_PRINT_ERROR(err, "recv magic");
            memmove(conn->r_buffer->data, conn->r_buffer->data + sizeof(http2_magic), conn->r_buffer->len - sizeof(http2_magic));
            conn->r_buffer->len -= sizeof(http2_magic);
            return HTTP2_RETURN_SKIP_DATA;
        }
    }
    
    frame_type = frame_len = flag = padd_len = stream_id = 0;
    
    http2_extract_overhead(conn->r_buffer->data, &stream_id, &frame_type, &frame_len, &flag);
    HTTP2_PRINT_ERROR(err, "stream_id[%d] type[0x%02x] len[%d] flag[0x%02x] buffer_len[%d]", stream_id, frame_type, frame_len, flag, conn->r_buffer->len);
    if(conn->r_buffer->len < (frame_len + OVERHEAD_FRAME_SIZE))
        return HTTP2_RETURN_NEED_MORE_DATA;
       
    memcpy(buff, conn->r_buffer->data, frame_len + OVERHEAD_FRAME_SIZE);
    memmove(conn->r_buffer->data, conn->r_buffer->data + frame_len + OVERHEAD_FRAME_SIZE, conn->r_buffer->len - (frame_len + OVERHEAD_FRAME_SIZE));
    conn->r_buffer->len -= (frame_len + OVERHEAD_FRAME_SIZE);
    
    
    if(frame_len > conn->http2_settings_send[SETTINGS_MAX_FRAME_SIZE].setting_value)
    {
        http2_reset_stream_build(conn, stream_id, HTTP2_ERROR_CODE_FRAME_SIZE_ERROR, "Frame size exceed", err);
        return HTTP2_RETURN_SKIP_DATA;
    }
    
    if(flag & FLAG_PADDED_TRUE)
    {
        GET_DATA_LENGTH_BYTE(buff , padd_len, PADDED_LEN_SIZE);
        frame_len -= (PADDED_LEN_SIZE + padd_len);
        process_p = buff + OVERHEAD_FRAME_SIZE + PADDED_LEN_SIZE;
    }
    else
    {
        process_p = buff + OVERHEAD_FRAME_SIZE;
    }
    
    STREAM_INFO *info = NULL;
    if(stream_id != GLOBAL_STREAM_ID || frame_type == FRAME_TYPE_PUSH_PROMISE)
    {
        info = http2_find_stream_info(conn, stream_id);
        if(!info && frame_type != FRAME_TYPE_RST_STREAM)
        {
            switch(conn->mode)
            {
                case HTTP2_MODE_SERVER:
                     if(stream_id%2 == 0)
                     {
                         http2_reset_stream_build(conn, stream_id, (stream_id <= conn->last_stream_id_send)?HTTP2_ERROR_CODE_STREAM_CLOSED:HTTP2_ERROR_CODE_FLOW_CONTROL_ERROR, "Invalid stream id", err);
                         HTTP2_PRINT_ERROR(err, "[%u]Invalid stream id", stream_id);
                         return HTTP2_RETURN_SKIP_DATA;
                     }
                     //Recv from client
                     info = http2_stream_info_init(conn, &(stream_id), HTTP2_ID_CLIENT_INIT, &(conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].current_value), conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].setting_value, err);
                     if(!info)
                     {
                         if(conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].setting_value != DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS && conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].current_value >= conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].setting_value)
                         {
                             http2_reset_stream_build(conn, stream_id, HTTP2_ERROR_CODE_ENHANCE_YOUR_CALM, "Concurrent speed limit", err);
                             HTTP2_PRINT_ERROR(err, "[%u]Concurrent speed limit", stream_id);
                             return HTTP2_RETURN_SKIP_DATA;
                         }
                         return HTTP2_RETURN_ERROR;
                     }
                     conn->last_stream_id_recv = info->stream_id;
                     break;
                case HTTP2_MODE_CLIENT:
                     //Recv from server
                     if(stream_id%2 == 1 && frame_type != FRAME_TYPE_PUSH_PROMISE)
                     {
                         http2_reset_stream_build(conn, stream_id, (stream_id <= conn->last_stream_id_send)?HTTP2_ERROR_CODE_STREAM_CLOSED:HTTP2_ERROR_CODE_FLOW_CONTROL_ERROR, "Invalid stream id", err);
                         HTTP2_PRINT_ERROR(err, "[%u]Invalid stream id", stream_id);
                         return HTTP2_RETURN_SKIP_DATA;
                     }
                     info = http2_stream_info_init(conn, &(stream_id), HTTP2_ID_SERVER_INIT, &(conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].current_value), conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].setting_value, err);
                     if(!info)
                     {
                         if(conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].setting_value != DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS && conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].current_value >= conn->http2_settings_send[SETTINGS_MAX_CONCURRENT_STREAMS].setting_value)
                         {
                             http2_reset_stream_build(conn, stream_id, HTTP2_ERROR_CODE_ENHANCE_YOUR_CALM, "Concurrent speed limit", err);
                             HTTP2_PRINT_ERROR(err, "[%u]Concurrent speed limit", stream_id);
                             return HTTP2_RETURN_SKIP_DATA;
                         }
                         return HTTP2_RETURN_ERROR;
                     }
                     conn->last_stream_id_recv = info->stream_id;
                     break;
                default:
                     break;
            }
        }
        if (info) {
            info->active_time = http2_get_current_time();
            http2_stream_info_rotate(info);
        }
    }
    *info_ret = info;
    *frame_type_ret = frame_type;
    
    switch(frame_type)
    {
        case FRAME_TYPE_DATA:
             printf("recv FRAME_TYPE_DATA\n");
			 if(frame_len > 0){
				http2_window_update_build(conn, info->stream_id, frame_len);
				http2_window_update_build(conn, GLOBAL_STREAM_ID, frame_len);
			 }
             ret = http2_extract_data(conn, info, process_p, frame_len, flag, err);
             break;
        case FRAME_TYPE_HEADER:
             printf("recv FRAME_TYPE_HEADER\n");
             ret = http2_extract_header(conn, info, process_p, frame_len, flag, err);
             break;
        case FRAME_TYPE_PRIORITY:
             printf("recv FRAME_TYPE_PRIORITY\n");
             break;
        case FRAME_TYPE_RST_STREAM:
             printf("recv FRAME_TYPE_RST_STREAM\n");
             if(info) ret = HTTP2_RETURN_STREAM_CLOSE;
             else ret = HTTP2_RETURN_SKIP_DATA;
             break;
        case FRAME_TYPE_SETTING:
             printf("recv FRAME_TYPE_SETTING\n");
             ret = http2_extract_setting(conn, info, process_p, frame_len, flag, err);
             break;
        case FRAME_TYPE_PUSH_PROMISE:
             printf("recv FRAME_TYPE_PUSH_PROMISE\n");
             ret = http2_extract_push_promise(conn, info, process_p, frame_len, flag, err);
             break;
        case FRAME_TYPE_PING:
             if(!(flag & PING_ACK_FLAG))
             {
                 printf("recv FRAME_TYPE_PING\n");
                 http2_ping_build(conn, PING_ACK_FLAG, process_p, err);
             }
             else
             {
                 printf("recv FRAME_TYPE_PING_ACK\n");
             }
             ret = HTTP2_RETURN_SKIP_DATA;
             break;
        case FRAME_TYPE_GOAWAY:
             http2_extract_goaway(conn, info, process_p, frame_len, flag, err);
             ret = HTTP2_RETURN_CONNECTION_CLOSE;
             break;
        case FRAME_TYPE_WINDOW_UPDATE:
             printf("recv FRAME_TYPE_WINDOW_UPDATE\n");
             ret = http2_extract_window_update(conn, info, process_p, frame_len, flag, err);
             break;
        case FRAME_TYPE_CONTINUATION:
             printf("recv FRAME_TYPE_CONTINUATION\n");
             break;
        default:
             HTTP2_PRINT_ERROR(err, "recv FRAME_TYPE_UNKNOWN[0x%02x]\n", frame_type);
             return HTTP2_RETURN_ERROR;
    }
    
    return ret;
}

int http2_read(HTTP2_CONNECTION *conn, char *err)
{
    int read_len = 0;
    
    if(!conn->r_buffer || ((conn->r_buffer->size - conn->r_buffer->len) < OVERHEAD_FRAME_SIZE))
    {
        if(!conn->r_buffer || conn->r_buffer->size < conn->http2_settings_send[SETTINGS_INITIAL_WINDOW_SIZE].setting_value)
        {
            if(data_alloc(&(conn->r_buffer), (conn->http2_settings_send[SETTINGS_MAX_FRAME_SIZE].setting_value + OVERHEAD_FRAME_SIZE), err) != 0)
            {
                return -1;
            }
        }
    }
    
    if(conn->use_ssl)
    {
        int r = conn->ssl_read_callback(conn->sock, conn->r_buffer->data + conn->r_buffer->len, (conn->r_buffer->size - conn->r_buffer->len), &read_len, err);
        if(r == 1)
            return 1;
        else if(r < 0)
            return -1;
        
        conn->r_buffer->len += read_len;
    }
    else if(conn->r_buffer->size - conn->r_buffer->len > 0)
    {
        read_len = recv(conn->sock, conn->r_buffer->data + conn->r_buffer->len, (conn->r_buffer->size - conn->r_buffer->len), 0);
        if(read_len == 0)
        {
            HTTP2_PRINT_ERROR(err, "Socket [%d] version [%d] has benn close", conn->sock, conn->version);
            return -1;
        }
        if(read_len < 0)
        {
            HTTP2_PRINT_ERROR(err, "recv return error [%s]", strerror(errno));
            return -1;
        }
        conn->r_buffer->len += read_len;
    }
    else
    {
        HTTP2_PRINT_ERROR(err, "Max WINDOW_SIZE");
    }
    conn->active_time = http2_get_current_time();
    return read_len;
}

