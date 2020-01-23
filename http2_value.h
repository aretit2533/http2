#define MY_DATA_BUFFER                      1024
#define MAX_VERSION_COUNT                   0x7FFFFFFF

#define MAX_STREAM_INFO_LIST                100

#define HEADER_TYPE_INDEXED                     0x80
#define HEADER_TYPE_INDEXED_NBIT                0x07
#define HEADER_TYPE_INCREMENTAL_INDEX           0x40
#define HEADER_TYPE_INCREMENTAL_INDEX_NBIT      0x06
#define HEADER_DYNAMIC_TABLE_SIZE_UPDATE        0x20
#define HEADER_DYNAMIC_TABLE_SIZE_UPDATE_NBIT   0x05
#define HEADER_TYPE_NERVER_INDEX                0x10
#define HEADER_TYPE_NERVER_INDEX_NBIT           0x04
#define HEADER_TYPE_WITHOUT_INDEX               0x00
#define HEADER_TYPE_WITHOUT_INDEX_NBIT          0x04

#define HUFFMAN_ENCODE_PREFIX_LEN           0x80
#define HUFFMAN_ENCODE_PREFIX_LEN_NBIT      0x07

/*
Setting value as below.
+------------------------+------+---------------+---------------+
| Name                   | Code | Initial Value | Specification |
+------------------------+------+---------------+---------------+
| HEADER_TABLE_SIZE      | 0x1  | 4096          | Section 6.5.2 |
| ENABLE_PUSH            | 0x2  | 1             | Section 6.5.2 |
| MAX_CONCURRENT_STREAMS | 0x3  | (infinite)    | Section 6.5.2 |
| INITIAL_WINDOW_SIZE    | 0x4  | 65535         | Section 6.5.2 |
| MAX_FRAME_SIZE         | 0x5  | 16384         | Section 6.5.2 |
| MAX_HEADER_LIST_SIZE   | 0x6  | (infinite)    | Section 6.5.2 |
+------------------------+------+---------------+---------------+
*/
#define DEFAULT_SETTINGS_HEADER_TABLE_SIZE      0x1000
#define DEFAULT_SETTINGS_ENABLE_PUSH            0x01
#define DEFAULT_SETTINGS_MAX_CONCURRENT_STREAMS 0x00 //RFC7540 define (infinite) but lib set defualt as 100
#define DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE    0xFFFF
#define DEFAULT_SETTINGS_MAX_FRAME_SIZE         0x4000
#define MAX_SETTINGS_MAX_FRAME_SIZE             0xFFFFFF //(2^24) -1
#define DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE   0x00

#define MAX_SETTING_LENGTH                      0x7FFFFFFF //(2^31)

#define HTTP_H_NAME_SIZE    256
#define HTTP_H_VALUE_SIZE   2048

#define GLOBAL_STREAM_ID    0

//Byte Length
#define FRAME_LEN_SIZE      3
#define TYPE_SIZE           1
#define FLAG_SIZE           1
#define STREAM_ID_SIZE      4
#define PADDED_LEN_SIZE     1
#define SETTING_ID_SIZE     2
#define SETTING_VAL_SIZE    4
#define HEADER_LEN_SIZE     1
#define HEADER_INDEX_SIZE   1
#define ERROR_CODE_SIZE     4
#define DYNAMIC_TABLE_SIZE  5
#define PING_VALUE_SIZE     8

#define SETTING_NORMAL_FLAG 0x00
#define SETTING_ACK_FLAG    0x01
#define PING_ACK_FLAG       0x01

#define FLAG_ENDSTREAM_TRUE 0x01 //0000 0001
#define FLAG_ENDHEADER_TRUE 0x04 //0000 0100
#define FLAG_PADDED_TRUE    0x08 //0000 1000
#define FLAG_PRIORYTY_TRUE  0x20 //0010 0000

#define MAX_STREAM_ID       0x7FFFFFFF //31 bit

#define OVERHEAD_FRAME_SIZE 0x09
#define OVERHEAD_TABLE_SIZE 0x20


/*

                                +--------+
                        send PP |        | recv PP
                       ,--------|  idle  |--------.
                      /         |        |         \
                     v          +--------+          v
              +----------+          |           +----------+
              |          |          | send H /  |          |
       ,------| reserved |          | recv H    | reserved |------.
       |      | (local)  |          |           | (remote) |      |
       |      +----------+          v           +----------+      |
       |          |             +--------+             |          |
       |          |     recv ES |        | send ES     |          |
       |   send H |     ,-------|  open  |-------.     | recv H   |
       |          |    /        |        |        \    |          |
       |          v   v         +--------+         v   v          |
       |      +----------+          |           +----------+      |
       |      |   half   |          |           |   half   |      |
       |      |  closed  |          | send R /  |  closed  |      |
       |      | (remote) |          | recv R    | (local)  |      |
       |      +----------+          |           +----------+      |
       |           |                |                 |           |
       |           | send ES /      |       recv ES / |           |
       |           | send R /       v        send R / |           |
       |           | recv R     +--------+   recv R   |           |
       | send R /  `----------->|        |<-----------'  send R / |
       | recv R                 | closed |               recv R   |
       `----------------------->|        |<----------------------'
                                +--------+

          send:   endpoint sends this frame
          recv:   endpoint receives this frame

          H:  HEADERS frame (with implied CONTINUATIONs)
          PP: PUSH_PROMISE frame (with implied CONTINUATIONs)
          ES: END_STREAM flag
          R:  RST_STREAM frame

*/

