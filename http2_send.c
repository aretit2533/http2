/*************************************************
HTTP2 Libraly for equinox
Referrence on RFC7540 and RFC7541
*************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>


#include "http2.h"
#include "huffman.h"
#include "linklist.h"
#include "http2_macro.h"

/*
    find_table_index will 
        - return table index if exist
        - return 0 if not found
*/
int find_table_index(HTTP2_CONNECTION *conn, char *f_index, char *name, char *value)
{
    if(!conn || !name || !value || !static_table)
        return 0;
    //First find static table
    *f_index = 0;
    int index;
    HTTP2_HEADER *h_buff = conn->dynamic_table_send;
    for(index = MAX_STATIC_TABLE_INDEX; (index - MAX_STATIC_TABLE_INDEX) < conn->dynamic_table_send_count; index++, h_buff = h_buff->next)
    {
        if(!h_buff)
            break;
        if((!strcmp(h_buff->name, name)) && (!strcmp(h_buff->value, value)))
        {
            *f_index = HEADER_TYPE_INDEXED;
            return index;
        }
    }
    for(index = 1; index < MAX_STATIC_TABLE_INDEX; index++)
    {
        if(!strcmp(static_table[index].header.name, name))
        {
            if(static_table[index].header.value[0] == '\0')
                return static_table[index].index;
            if(!strcmp(static_table[index].header.value, value))
            {
                *f_index = HEADER_TYPE_INDEXED;
                return static_table[index].index;
            }
        }
    }
    for(index = 1; index < MAX_STATIC_TABLE_INDEX; index++)
    {
        if(!strcmp(static_table[index].header.name, name))
        {
            return static_table[index].index;
        }
    }
    return 0;
}

int http2_magic_add(HTTP2_CONNECTION *conn, char *err)
{
    HTTP2_DATA *data_buff = NULL;
    if(data_alloc(&data_buff, MY_DATA_BUFFER, err) != 0)
    {
        return -1;
    }
    memcpy(data_buff->data, http2_magic, sizeof(http2_magic));
    data_buff->len = sizeof(http2_magic);
    LIST_APPEND(conn->w_buffer, data_buff);
    return 0;
}

STREAM_INFO* http2_init_stream_info_send(HTTP2_CONNECTION *conn, int init_id, char *err)
{
    return http2_stream_info_init(conn, &(conn->last_stream_id_send), init_id, &(conn->http2_settings_recv[SETTINGS_MAX_CONCURRENT_STREAMS].current_value), conn->http2_settings_recv[SETTINGS_MAX_CONCURRENT_STREAMS].setting_value, err);
}

/*
Overhead frame 

Len(3),Type(1), Flag(1), StreamId(4)

*/

#define OVERHEADER_ADD(_BUFF, _LEN, _FRAME_LEN, _FRAME_TYPE, _FRAME_FLAGE, _STREAM_ID)         \
    SET_DATA_LENGTH_BYTE(_FRAME_LEN, _BUFF + _LEN, FRAME_LEN_SIZE);                            \
    _LEN += FRAME_LEN_SIZE;                                                                    \
    SET_DATA_LENGTH_BYTE(_FRAME_TYPE, _BUFF + _LEN, TYPE_SIZE);                                \
    _LEN += TYPE_SIZE;                                                                         \
    SET_DATA_LENGTH_BYTE(_FRAME_FLAGE, _BUFF + _LEN, FLAG_SIZE);                               \
    _LEN += FLAG_SIZE;                                                                         \
    SET_DATA_LENGTH_BYTE(_STREAM_ID, _BUFF + _LEN, STREAM_ID_SIZE);                            \
    _LEN += STREAM_ID_SIZE

int http2_reset_stream_build(HTTP2_CONNECTION *conn, unsigned int stream_id, int err_code, char *diag, char *err)
{
    int l_len = (int)(ERROR_CODE_SIZE);
    
    HTTP2_DATA *data_buff = NULL;
    if(data_alloc(&data_buff, OVERHEAD_FRAME_SIZE + l_len, err) != 0)
    {
        return -1;
    }
    OVERHEADER_ADD(data_buff->data, data_buff->len, l_len, FRAME_TYPE_RST_STREAM, 0, stream_id);
    SET_DATA_LENGTH_BYTE(err_code, data_buff->data + data_buff->len, ERROR_CODE_SIZE);
    data_buff->len += ERROR_CODE_SIZE;

    LIST_APPEND(conn->w_buffer, data_buff);
    return 0;
}

int http2_window_update_build(HTTP2_CONNECTION *conn, unsigned int stream_id, int size)
{
    HTTP2_DATA *data_buff = NULL;
    if(data_alloc(&data_buff, OVERHEAD_FRAME_SIZE + SETTING_VAL_SIZE, NULL) != 0)
    {
        return -1;
    }
    
    OVERHEADER_ADD(data_buff->data, data_buff->len, SETTING_VAL_SIZE, FRAME_TYPE_WINDOW_UPDATE, 0, stream_id);
    SET_DATA_LENGTH_BYTE(size, data_buff->data + data_buff->len, SETTING_VAL_SIZE);
    data_buff->len += SETTING_VAL_SIZE;
    
    data_buff->frame_type = FRAME_TYPE_WINDOW_UPDATE;
    
    LIST_APPEND(conn->w_buffer, data_buff);    
    return 0;
}

int http2_goaway_build(HTTP2_CONNECTION *conn, unsigned int promised_stream_id, HTTP2_ERROR_CODE err_code, char *diag)
{
    if(conn->goaway_sent)
    {
        return 0;
    }
    HTTP2_DATA *data_buff = NULL;
    if(data_alloc(&data_buff, OVERHEAD_FRAME_SIZE + STREAM_ID_SIZE + ERROR_CODE_SIZE + strlen(diag), NULL) != 0)
    {
        return -1;
    }
    OVERHEADER_ADD(data_buff->data, data_buff->len, STREAM_ID_SIZE + ERROR_CODE_SIZE + strlen(diag), FRAME_TYPE_GOAWAY, 0, GLOBAL_STREAM_ID);
    SET_DATA_LENGTH_BYTE(promised_stream_id, data_buff->data + data_buff->len, STREAM_ID_SIZE);
    data_buff->len += STREAM_ID_SIZE;
    SET_DATA_LENGTH_BYTE(err_code, data_buff->data + data_buff->len, ERROR_CODE_SIZE);
    data_buff->len += ERROR_CODE_SIZE;
    memcpy(data_buff->data + data_buff->len, diag, strlen(diag));
    data_buff->len += strlen(diag);
    LIST_APPEND(conn->w_buffer, data_buff);
    conn->goaway_sent = 1;
    return 0;
}

int http2_ping_build(HTTP2_CONNECTION *conn, unsigned int flag, char *msg, char *err)
{
    HTTP2_DATA *data_buff = NULL;
    if(data_alloc(&data_buff, MY_DATA_BUFFER, err) != 0)
    {
        return -1;
    }
    SET_DATA_LENGTH_BYTE(PING_VALUE_SIZE, data_buff->data, FRAME_LEN_SIZE);
    data_buff->len += FRAME_LEN_SIZE;
    SET_DATA_LENGTH_BYTE(FRAME_TYPE_PING, data_buff->data + data_buff->len, TYPE_SIZE);
    data_buff->len += TYPE_SIZE;
    SET_DATA_LENGTH_BYTE(flag, data_buff->data + data_buff->len, FLAG_SIZE);
    data_buff->len += FLAG_SIZE;
    SET_DATA_LENGTH_BYTE(GLOBAL_STREAM_ID, data_buff->data + data_buff->len, STREAM_ID_SIZE);
    data_buff->len += STREAM_ID_SIZE;
    
    memcpy((data_buff->data + data_buff->len), msg, PING_VALUE_SIZE);
    data_buff->len += PING_VALUE_SIZE;
    
    data_buff->frame_type = FRAME_TYPE_PING;
    
    LIST_APPEND(conn->w_buffer, data_buff);
    return 0;
}

int http2_build_setting(HTTP2_CONNECTION *conn, HTTP2_SETTINGS *setting, char *err)
{
    HTTP2_DATA *data_buff = NULL;
    if(data_alloc(&data_buff, MY_DATA_BUFFER, err) != 0)
    {
        return -1;
    }
    data_buff->frame_type = FRAME_TYPE_SETTING;
    if(conn->mode == HTTP2_MODE_CLIENT && conn->last_stream_id_send == 1)
    {
        if(http2_magic_add(conn, err) != 0)
        {
            printf("Add magic fail\n");
            free(data_buff);
            return -1;
        }
    }

    int count;
    int data_size = 0;
    data_buff->len += FRAME_LEN_SIZE;
    SET_DATA_LENGTH_BYTE(FRAME_TYPE_SETTING, data_buff->data + data_buff->len, TYPE_SIZE);
    data_buff->len += TYPE_SIZE;
    SET_DATA_LENGTH_BYTE(SETTING_NORMAL_FLAG, data_buff->data + data_buff->len, FLAG_SIZE);
    data_buff->len += FLAG_SIZE;
    SET_DATA_LENGTH_BYTE(GLOBAL_STREAM_ID, data_buff->data + data_buff->len, STREAM_ID_SIZE);
    data_buff->len += STREAM_ID_SIZE;
    for(count = 1; count < MAX_SETTINGS_SIZE; count++)
    {
        //Skip setting send if value equal default
        switch(count)
        {
            case SETTINGS_HEADER_TABLE_SIZE:
                 if(setting[count].setting_value == DEFAULT_SETTINGS_HEADER_TABLE_SIZE)
                     continue;
                 break;
            case SETTINGS_ENABLE_PUSH:
                 if(setting[count].setting_value == DEFAULT_SETTINGS_ENABLE_PUSH)
                     continue;
                 break;
            case SETTINGS_MAX_CONCURRENT_STREAMS:
                 if(setting[count].setting_value == DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS)
                     continue;
                 break;
            case SETTINGS_INITIAL_WINDOW_SIZE:
                 if(setting[count].setting_value == DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE)
                     continue;
                 break;
            case SETTINGS_MAX_FRAME_SIZE:
                 if(setting[count].setting_value == DEFAULT_SETTINGS_MAX_FRAME_SIZE)
                     continue;
                 break;
            case SETTINGS_MAX_HEADER_LIST_SIZE:
                 if(setting[count].setting_value == DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE)
                     continue;
                 break;
            default:
                 break;
        }
        SET_DATA_LENGTH_BYTE(count, data_buff->data + data_buff->len, SETTING_ID_SIZE);
        data_buff->len += SETTING_ID_SIZE;
        data_size += SETTING_ID_SIZE;
        
        SET_DATA_LENGTH_BYTE(setting[count].setting_value, data_buff->data + data_buff->len, SETTING_VAL_SIZE);
        data_buff->len += SETTING_VAL_SIZE;
        data_size += SETTING_VAL_SIZE;
    }
    SET_DATA_LENGTH_BYTE(data_size, data_buff->data, FRAME_LEN_SIZE);
    data_buff->frame_type = FRAME_TYPE_SETTING;
    
    LIST_APPEND(conn->w_buffer, data_buff);
    conn->sent_setting_f = 1;
    
    return 0;
}

int http2_build_setting_ack(HTTP2_CONNECTION *conn, char *err)
{
    HTTP2_DATA *data_buff = NULL;
    if(data_alloc(&data_buff, MY_DATA_BUFFER, err) != 0)
    {
        return -1;
    }
    SET_DATA_LENGTH_BYTE(0, data_buff->data, FRAME_LEN_SIZE);
    data_buff->len += FRAME_LEN_SIZE;
    SET_DATA_LENGTH_BYTE(FRAME_TYPE_SETTING, data_buff->data + data_buff->len, TYPE_SIZE);
    data_buff->len += TYPE_SIZE;
    SET_DATA_LENGTH_BYTE(SETTING_ACK_FLAG, data_buff->data + data_buff->len, FLAG_SIZE);
    data_buff->len += FLAG_SIZE;
    SET_DATA_LENGTH_BYTE(GLOBAL_STREAM_ID, data_buff->data + data_buff->len, STREAM_ID_SIZE);
    data_buff->len += STREAM_ID_SIZE;
    
    data_buff->frame_type = FRAME_TYPE_SETTING;
    
    LIST_APPEND(conn->w_buffer, data_buff);
    
    return 0;
}

int http2_build_header(STREAM_INFO *info, int end_stream, char *err)
{
    unsigned char buff_endcode[HTTP_H_VALUE_SIZE];
    int s_out = 0, s_len = 0;
    
#define ENDCODE_HUFFMAN(_DATA, _LEN)                                \
    do                                                              \
    {                                                               \
        s_out = 0;                                                  \
        s_len = hf_string_encode_len((unsigned char *)_DATA, _LEN); \
        if(s_len < _LEN)                                            \
        {                                                           \
            memset(buff_endcode, 0, s_len);                         \
            hf_string_encode(_DATA, _LEN, 0, buff_endcode, &s_out); \
        }                                                           \
    }while(0)
        
#define ENDCODE_LEN(_LEN, _BUFF, _CURR, _FLAG, _NBITS)              \
    s_len = hf_integer_encode(_LEN, _NBITS, (unsigned char *)_BUFF + _CURR);         \
    *(_BUFF + _CURR) |= _FLAG;                                      \
    _CURR += s_len
    
    switch(info->state)
    {
        case FRAME_STATE_IDLE:
             info->state = FRAME_STATE_OPEN;
             break;
        case FRAME_STATE_REMOTE_HALF_CLOSE:
             info->state = FRAME_STATE_CLOSE;
        default:
             break;
    }
    if(!info->data_send.first_header_list)
    {
        HTTP2_PRINT_ERROR(err, "Header not found");
        return -1;
    }
    if(info->data_send.data_len)
    {
        sprintf((char*)buff_endcode, "%d", info->data_send.data_len);
        if(http2_add_header(info, "content-length", (char*)buff_endcode, err) != 0)
            return -1;
    }
    HTTP2_DATA *data_buff = NULL;
    if(data_alloc(&data_buff, info->conn->http2_settings_recv[SETTINGS_MAX_FRAME_SIZE].setting_value + OVERHEAD_FRAME_SIZE, err) != 0)
    {
        return -1;
    }
    
    data_buff->frame_type = FRAME_TYPE_HEADER;
    data_buff->len += FRAME_LEN_SIZE;
    SET_DATA_LENGTH_BYTE(FRAME_TYPE_HEADER, data_buff->data + data_buff->len, TYPE_SIZE);
    data_buff->len += TYPE_SIZE;
    //Skip flag insert as after process
    data_buff->len += FLAG_SIZE;
    SET_DATA_LENGTH_BYTE(info->stream_id, data_buff->data + data_buff->len, STREAM_ID_SIZE);
    data_buff->len += STREAM_ID_SIZE;
    
    HTTP2_HEADER *h = info->data_send.first_header_list;
    HTTP2_HEADER *h_temp;
    int table_index = 0;
    char f_index = 0;
    while(h)
    {
        table_index = 0;
        f_index = 0;
        table_index = find_table_index(info->conn, &f_index, h->name, h->value);
        if(!table_index)
        {
            if((((data_buff->len - OVERHEAD_FRAME_SIZE) + strlen(h->name) + strlen(h->value)) + (HEADER_LEN_SIZE * 2)) < 
              info->conn->http2_settings_recv[SETTINGS_MAX_FRAME_SIZE].setting_value)
            {
                SET_DATA_LENGTH_BYTE(HEADER_TYPE_INCREMENTAL_INDEX, data_buff->data + data_buff->len, HEADER_INDEX_SIZE);
                data_buff->len += HEADER_INDEX_SIZE;
                POP_HEADER(h, h_temp);
                ///////////////////////HEADER////////////////
                ENDCODE_HUFFMAN(h_temp->name, (int)strlen(h_temp->name));
                if(s_out == 0)
                {
                    ENDCODE_LEN(strlen(h_temp->name), data_buff->data, data_buff->len, 0, HUFFMAN_ENCODE_PREFIX_LEN_NBIT);
                    memcpy(data_buff->data + data_buff->len, h_temp->name, strlen(h_temp->name));
                    data_buff->len += strlen(h_temp->name);
                }
                else
                {
                    ENDCODE_LEN(s_out, data_buff->data, data_buff->len, HUFFMAN_ENCODE_PREFIX_LEN, HUFFMAN_ENCODE_PREFIX_LEN_NBIT);
                    memcpy(data_buff->data + data_buff->len, buff_endcode, s_out);
                    data_buff->len += s_out;
                }
                ///////////////////////VALUE////////////////
                ENDCODE_HUFFMAN(h_temp->value, (int)strlen(h_temp->value));
                if(s_out == 0)
                {
                    ENDCODE_LEN(strlen(h_temp->value), data_buff->data, data_buff->len, 0, HUFFMAN_ENCODE_PREFIX_LEN_NBIT);
                    memcpy(data_buff->data + data_buff->len, h_temp->value, strlen(h_temp->value));
                    data_buff->len += strlen(h_temp->value);
                }
                else
                {
                    ENDCODE_LEN(s_out, data_buff->data, data_buff->len, HUFFMAN_ENCODE_PREFIX_LEN, HUFFMAN_ENCODE_PREFIX_LEN_NBIT);
                    memcpy(data_buff->data + data_buff->len, buff_endcode, s_out);
                    data_buff->len += s_out;
                }
                /////////////////////////////////////
                if(http2_dynamic_table_add(&(info->conn->dynamic_table_send), &(info->conn->dynamic_table_send_count), h_temp->name, h_temp->value, info->conn->http2_settings_send[SETTINGS_HEADER_TABLE_SIZE].setting_value, err) != 0)
                {
                    free(data_buff);
                    return -1;
                }
                free(h_temp);
            }
            else
            {
                break;
            }
        }
        else
        {
            if(f_index)
            {
                if(((data_buff->len - OVERHEAD_FRAME_SIZE) + HEADER_INDEX_SIZE) > 
                info->conn->http2_settings_recv[SETTINGS_MAX_FRAME_SIZE].setting_value)
                {
                    break;
                }
                ENDCODE_LEN(table_index, data_buff->data, data_buff->len, HEADER_TYPE_INDEXED, HEADER_TYPE_INDEXED_NBIT);
            }
            else
            {
                if(((data_buff->len - OVERHEAD_FRAME_SIZE) + HEADER_INDEX_SIZE + HEADER_LEN_SIZE + strlen(h->value)) > 
                info->conn->http2_settings_recv[SETTINGS_MAX_FRAME_SIZE].setting_value)
                {
                    break;
                }
                if((table_index == IDX_PATH && strchr(h->value, '?')) ||
                  (table_index == IDX_CONTENT_LENGTH))
                {
                    ENDCODE_LEN(table_index , data_buff->data, data_buff->len, HEADER_TYPE_WITHOUT_INDEX, HEADER_TYPE_WITHOUT_INDEX_NBIT);
                }
                else
                {
                    ENDCODE_LEN(table_index , data_buff->data, data_buff->len, HEADER_TYPE_INCREMENTAL_INDEX, HEADER_TYPE_INCREMENTAL_INDEX_NBIT);
                    if(http2_dynamic_table_add(&(info->conn->dynamic_table_send), &(info->conn->dynamic_table_send_count), h->name, h->value, info->conn->http2_settings_send[SETTINGS_HEADER_TABLE_SIZE].setting_value, err) != 0)
                    {
                        free(data_buff);
                        return -1;
                    }
                }
            }
            POP_HEADER(h, h_temp);
            if(!(f_index))
            {
                ENDCODE_HUFFMAN(h_temp->value, (int)strlen(h_temp->value));
                if(s_out == 0)
                {
                    ENDCODE_LEN(strlen(h_temp->value), data_buff->data, data_buff->len, 0, HUFFMAN_ENCODE_PREFIX_LEN_NBIT);
                    memcpy(data_buff->data + data_buff->len, h_temp->value, strlen(h_temp->value));
                    data_buff->len += strlen(h_temp->value);
                }
                else
                {
                    ENDCODE_LEN(s_out, data_buff->data, data_buff->len, HUFFMAN_ENCODE_PREFIX_LEN, HUFFMAN_ENCODE_PREFIX_LEN_NBIT);
                    memcpy(data_buff->data + data_buff->len, buff_endcode, s_out);
                    data_buff->len += s_out;
                }
            }
            free(h_temp);
        }
    }
    info->data_send.first_header_list = h;
    LIST_APPEND(info->conn->w_buffer, data_buff);
    char f_set = 0;
    SET_DATA_LENGTH_BYTE(data_buff->len - OVERHEAD_FRAME_SIZE, data_buff->data, FRAME_LEN_SIZE);
    if(info->data_send.first_header_list)
    {
        //Header not end recursive 
        SET_DATA_LENGTH_BYTE(f_set, data_buff->data + FRAME_LEN_SIZE + TYPE_SIZE, FLAG_SIZE);
        return http2_build_header(info, end_stream, err);
    }
    else
    {
        //end of header
        f_set = FLAG_ENDHEADER_TRUE;
        if(!info->data_send.data_len && end_stream)
        {
            f_set |= FLAG_ENDSTREAM_TRUE;
            if (info->state == FRAME_STATE_OPEN) info->state = FRAME_STATE_LOCAL_HALF_CLOSE;
        }
        SET_DATA_LENGTH_BYTE(f_set, data_buff->data + FRAME_LEN_SIZE + TYPE_SIZE, FLAG_SIZE);
    }
    return 0;
}

int http2_build_data(STREAM_INFO *info, int p_curr, int end_stream, char *err)
{
    if(info->data_send.data_len <= 0)
        return 0;
    HTTP2_DATA *data_buff = NULL;
    int use_len = 0;
    int f_set = 0;
    int curr = p_curr;
    if((info->data_send.data_len - curr) > info->conn->http2_settings_recv[SETTINGS_MAX_FRAME_SIZE].setting_value)
    {
        use_len = info->conn->http2_settings_recv[SETTINGS_MAX_FRAME_SIZE].setting_value;
        if(data_alloc(&data_buff, info->conn->http2_settings_recv[SETTINGS_MAX_FRAME_SIZE].setting_value + OVERHEAD_FRAME_SIZE, err) != 0)
        {
            return -1;
        }
    }
    else
    {
        use_len = info->data_send.data_len - curr;
        if(end_stream)
        {
            f_set |= FLAG_ENDSTREAM_TRUE;
            info->state = FRAME_STATE_LOCAL_HALF_CLOSE;
        }
        if(data_alloc(&data_buff, (info->data_send.data_len - curr) + OVERHEAD_FRAME_SIZE, err) != 0)
        {
            return -1;
        }
    }
    
    data_buff->frame_type = FRAME_TYPE_DATA;
    
    SET_DATA_LENGTH_BYTE(use_len, data_buff->data, FRAME_LEN_SIZE);
    data_buff->len += FRAME_LEN_SIZE;
    SET_DATA_LENGTH_BYTE(FRAME_TYPE_DATA, data_buff->data + data_buff->len, TYPE_SIZE);
    data_buff->len += TYPE_SIZE;
    SET_DATA_LENGTH_BYTE(f_set, data_buff->data + data_buff->len, FLAG_SIZE);
    data_buff->len += FLAG_SIZE;
    SET_DATA_LENGTH_BYTE(info->stream_id, data_buff->data + data_buff->len, STREAM_ID_SIZE);
    data_buff->len += STREAM_ID_SIZE;
    
    memcpy(data_buff->data + data_buff->len, info->data_send.data + curr, use_len);
    data_buff->len += use_len;
    curr += use_len;
    
    LIST_APPEND(info->conn->w_buffer, data_buff);
    if(curr < info->data_send.data_len)
    {
        return http2_build_data(info, curr, end_stream, err);
    }
    free(info->data_send.data);
    info->data_send.data = NULL;
    info->data_send.data_len = 0;
    return 0;
}

int http2_create_msg(STREAM_INFO *info, int end_stream, char *err)
{
    if(!(http2_build_header(info, end_stream, err)))
    {
        if(info->data_send.data_len > 0 && !(http2_build_data(info, 0, end_stream, err)))
        {
            info->active_time = http2_get_current_time();
            return 0;
        }
        else if(info->data_send.data_len > 0)
        {
            return -1;
        }
    }    
    return -1;
    
}

int http2_add_header(STREAM_INFO *info, char *name, char *value, char *err)
{
    HTTP2_HEADER *header = (HTTP2_HEADER *) malloc(sizeof(HTTP2_HEADER));
    if(!header)
    {
        HTTP2_PRINT_ERROR(err, "Can not allocate memory size (%lu)", sizeof(HTTP2_HEADER));
        return -1;
    }
    strcpy(header->name, name);
    strcpy(header->value, value);
    
    APPEND_HEADER(info->data_send.first_header_list, info->data_send.last_header, header);
    
    return 0;
}

int http2_add_header_decode(HTTP2_DECODE_DATA *decode_data, char *name, char *value, int append_f, char *err)
{
    HTTP2_HEADER *header = (HTTP2_HEADER *) malloc(sizeof(HTTP2_HEADER));
    if(!header)
    {
        HTTP2_PRINT_ERROR(err, "Can not allocate memory size (%lu)", sizeof(HTTP2_HEADER));
        return -1;
    }
    strcpy(header->name, name);
    strcpy(header->value, value);
    
    if(append_f) APPEND_HEADER(decode_data->first_header_list, decode_data->last_header, header);
    else PUSH_HEADER(decode_data->first_header_list, header);
    
    return 0;
}

int http2_add_decode_to_stream_info(STREAM_INFO *info, HTTP2_DECODE_DATA **decode_data)
{
    if(info->data_send.data)
    {
        free(info->data_send.data);
    }
    if(info->data_send.first_header_list)
    {
        HTTP2_HEADER *h_tmp;
        while(info->data_send.first_header_list)
        {
            POP_HEADER(info->data_send.first_header_list, h_tmp);
            free(h_tmp);
        }
    }
    
    memcpy(&(info->data_send), *decode_data, sizeof(HTTP2_DECODE_DATA));
    free(*decode_data);
    *decode_data = NULL;
    
    return 0;
}

int http2_free_decode_data(HTTP2_DECODE_DATA **decode_data, char *err)
{
    if(!decode_data || !(*decode_data)) return 0;
    HTTP2_DECODE_DATA *decode_temp = *decode_data;

    if(decode_temp->data)
    {
        free(decode_temp->data);
    }
    if(decode_temp->data)
    {
        free(decode_temp->data);
    }
    if(decode_temp->first_header_list)
    {
        HTTP2_HEADER *h_tmp;
        while(decode_temp->first_header_list)
        {
            POP_HEADER(decode_temp->first_header_list, h_tmp);
            free(h_tmp);
        }
    }
    if(decode_temp->first_header_list)
    {
        HTTP2_HEADER *h_tmp;
        while(decode_temp->first_header_list)
        {
            POP_HEADER(decode_temp->first_header_list, h_tmp);
            free(h_tmp);
        }
    }
    free(decode_temp);
    *decode_data = NULL;
    
    return 0;
}

int http2_add_data(STREAM_INFO *info, char *data, int len, char *err)
{
    if(info->data_send.data != NULL)
    {
        char *x_buff = (char *) realloc(info->data_send.data, info->data_send.data_len + len);
        if(!x_buff)
        {
            HTTP2_PRINT_ERROR(err, "Can not allocate memory size (%d)", info->data_send.data_len + len);
            return -1;
        }
        info->data_send.data = x_buff;
    }
    else
    {
        info->data_send.data = (char*)malloc(len);
        info->data_send.data_len = 0;
    }
    
    memcpy(info->data_send.data + info->data_send.data_len, data, len);
    
    info->data_send.data_len += len;
    return 0;
}

int http2_add_data_decode(HTTP2_DECODE_DATA *decode_data, char *data, int len, char *err)
{
    if(decode_data->data != NULL)
    {
        char *x_buff = (char *) realloc(decode_data->data, decode_data->data_len + len);
        if(!x_buff)
        {
            HTTP2_PRINT_ERROR(err, "Can not allocate memory size (%d)", decode_data->data_len + len);
            return -1;
        }
        decode_data->data = x_buff;
    }
    else
    {
        decode_data->data = (char*)malloc(len);
        decode_data->data_len = 0;
    }
    
    memcpy(decode_data->data + decode_data->data_len, data, len);
    
    decode_data->data_len += len;
    return 0;
}


int http2_need_write(HTTP2_CONNECTION *conn)
{
    if(conn->w_buffer == NULL)
        return 0;
    return 1;
}

int http2_can_write(HTTP2_CONNECTION *conn)
{
    if(conn->w_buffer == NULL)
        return 0;
    if(conn->http2_settings_recv[SETTINGS_INITIAL_WINDOW_SIZE].current_value + conn->w_buffer->len - OVERHEAD_FRAME_SIZE > conn->http2_settings_recv[SETTINGS_INITIAL_WINDOW_SIZE].setting_value)
    {
        return 0;
    }
    return 1;
}

int http2_write(HTTP2_CONNECTION *conn, char *err)
{
    int sent_len = 0;
    if(!conn->w_buffer)
        return 0;
    if(conn->w_buffer_curr == 0 && conn->w_buffer->frame_type == FRAME_TYPE_DATA)
    {
        if(conn->http2_settings_recv[SETTINGS_INITIAL_WINDOW_SIZE].current_value + conn->w_buffer->len - OVERHEAD_FRAME_SIZE > conn->http2_settings_recv[SETTINGS_INITIAL_WINDOW_SIZE].setting_value)
        {
            HTTP2_PRINT_ERROR(err, "Max window size send [%u] [%u]", conn->http2_settings_recv[SETTINGS_INITIAL_WINDOW_SIZE].current_value, conn->http2_settings_recv[SETTINGS_INITIAL_WINDOW_SIZE].setting_value);
            return 0;
        }
        conn->http2_settings_recv[SETTINGS_INITIAL_WINDOW_SIZE].current_value += (conn->w_buffer->len - OVERHEAD_FRAME_SIZE);
    }
    
    printf("sent frame type [%d]\n", conn->w_buffer->frame_type);
    
    if(conn->use_ssl)
    {
        int r = conn->ssl_write_callback(conn->sock, conn->w_buffer->data + conn->w_buffer_curr, conn->w_buffer->len - conn->w_buffer_curr, &sent_len, err);
        if(r == 1)
            return 0;
        else if(r < 0)
            return -1;
    }
    else
    {
        sent_len = send(conn->sock, conn->w_buffer->data + conn->w_buffer_curr, conn->w_buffer->len - conn->w_buffer_curr, 0);
    }
    if(sent_len < 0)
    {
        HTTP2_PRINT_ERROR(err, "send return error [%s]", strerror(errno));
        return -1;
    }
    if(conn->goaway_sent)
    {
        HTTP2_PRINT_ERROR(err, "Sent goaway socket [%d]", conn->sock);
        return -1;
    }
    conn->active_time = http2_get_current_time();
    conn->w_buffer_curr += sent_len;
    if(conn->w_buffer_curr >= conn->w_buffer->len)
    {
        HTTP2_DATA *w_buff_rm = conn->w_buffer;
        LIST_REMOVE(conn->w_buffer, w_buff_rm);
        free(w_buff_rm);
        conn->w_buffer_curr = 0;
    }
    return sent_len;
}

