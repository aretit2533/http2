#ifdef _HTTP1_H_
#undef _HTTP1_H_
#endif
#ifndef _HTTP1_H_
#define _HTTP1_H_

#define MY_MAX_BODY_SIZE    (32*1024*1024)

//From HTTP2 use this for backward compatibility
HTTP2_RETURN_CODE http1_decode(HTTP2_CONNECTION *conn, STREAM_INFO **info, char *err);
int http1_create_msg(STREAM_INFO *info, int to_upper, char *describe, char *err);
int http1_create_msg_chunke(STREAM_INFO *info, int to_upper, char *describe, int is_end, char *err);
char *http1_code_to_string(char *code);


#endif