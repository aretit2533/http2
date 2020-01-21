#ifndef _HTTP2_MACRO_H
#define _HTTP2_MACRO_H

#define ADD_HEADER(_TABLE, _INDEX, _NAME, _VALUE) \
    _TABLE[_INDEX].index = _INDEX;\
    _TABLE[_INDEX].header.next = NULL;\
    strcpy(_TABLE[_INDEX].header.name, _NAME);\
    strcpy(_TABLE[_INDEX].header.value, _VALUE)

#define PUSH_HEADER(_FIRST, _ITEM)\
    do\
    {\
        if(_FIRST == NULL)\
        {\
            _FIRST = _ITEM;\
            _FIRST->next = NULL;\
        }\
        else\
        {\
            _ITEM->next = _FIRST;\
            _FIRST = _ITEM;\
        }\
    }while(0)
        
#define POP_HEADER(_FIRST, _ITEM)\
    do\
    {\
        if(_FIRST == NULL)\
        {\
            _ITEM = NULL;\
        }\
        else\
        {\
            _ITEM = _FIRST;\
            _FIRST = _FIRST->next;\
        }\
    }while(0)

#define APPEND_HEADER(_FIRST, _LAST, _ITEM)\
    do\
    {\
        if(_FIRST == NULL)\
        {\
            _FIRST = _LAST = _ITEM;\
            _FIRST->next = NULL;\
        }\
        else\
        {\
            _LAST->next = _ITEM;\
            _LAST = _ITEM;\
            _LAST->next = NULL;\
        }\
    }while(0)
        
#define GET_DATA_LENGTH_BYTE(_s,_t,_b)                    \
{                                                         \
    int __m;                                              \
    register unsigned char *s_ = (unsigned char *)(_s);   \
    register unsigned int t_ = 0;                         \
    for(__m = 0; __m < _b; __m++)                         \
    {                                                     \
        t_ <<= 8;                                         \
        t_ |= (s_[__m] & 0xFF);                           \
    }                                                     \
    _t = t_;                                              \
}

#define SET_DATA_LENGTH_BYTE(_s,_t,_b)                    \
{                                                         \
    int __m = _b-1;                                       \
    register unsigned char *t_ = (unsigned char *)(_t);   \
    register unsigned int s_ = (unsigned int)(_s);        \
    for(; __m >= 0; __m--)                                \
    {                                                     \
        t_[__m] = s_&0xFF;                                \
        s_ >>= 8;                                         \
    }                                                     \
}

#define ADJUST_SIZE(_l, _s)         \
{                                   \
    register int _r_ = (_l) % (_s); \
    if (_r_ > 0) {                  \
        (_l) += (_s) - _r_;         \
    }                               \
}

#define HTTP2_PRINT_ERROR(__err, ...)                                       \
{                                                                           \
    int __log_curr = 0;                                                     \
    if(__err)                                                               \
    {                                                                       \
        __log_curr = sprintf(__err, "%s:%d:", __func__, __LINE__);          \
        sprintf(__err + __log_curr, __VA_ARGS__);                           \
    }                                                                       \
}

#endif

