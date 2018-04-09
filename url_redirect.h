struct gbuffer{  
 
    u8  *buf;  
 
    u32 len;  
 
};  
 
   
 
typedef struct gbuffer gbuffer;  
 
typedef struct gbuffer gbuffer_t;  
 
   
 
static inline void gbuffer_init(gbuffer *p)  
 
{  
 
    p->len = 0;  
 
    p->buf = NULL;  
 
}  
 
   
 
static inline void __gbuffer_init(gbuffer *p, u8 *buf, u32 len)  
 
{  
 
    p->len = len;  
 
    p->buf = buf;  
 
}  
 
   
 
static inline int gbuffer_empty(gbuffer *p)  
 
{  
 
    return ( p->buf == NULL );  
 
}  
 
   
 
static inline void gbuffer_free(gbuffer *p)  
 
{  
 
    if ( NULL == p )  
 
        return;  
 
   
 
#ifdef __KERNEL__  
 
    if ( likely( p->buf != NULL ) ){  
 
        kfree( p->buf );  
 
        p->buf = NULL;  
 
    }  
 
#else   
 
    if ( NULL != p->buf ) {  
 
        free( p->buf );  
 
    }  
 
#endif  
 
    p->len = 0;  
 
}  
 
   
 
static inline void _gbuffer_free(gbuffer *p)  
 
{  
 
    if ( NULL == p )  
 
        return;  
 
   
 
#ifdef __KERNEL__  
 
    if ( likely( p->buf != NULL ) ){  
 
        kfree( p->buf );  
 
        p->buf = NULL;  
 
    }  
 
    kfree( p );  
 
#else   
 
    if ( NULL != p->buf ) {  
 
        free( p->buf );  
 
    }  
 
    free( p );  
 
#endif  
 
}  
 
   
 
static inline gbuffer_t* __gbuffer_alloc(void)  
 
{  
 
    gbuffer_t *p = NULL;  
 
#ifdef __KERNEL__  
 
    p = kzalloc( sizeof(*p), GFP_KERNEL );  
 
    if ( unlikely( NULL == p ) ){  
 
        return NULL;  
 
    }  
 
#else  
 
    p = malloc( sizeof(*p) );  
 
    if ( NULL == p )  
 
        return NULL;  
 
#endif  
 
    p->buf = NULL;  
 
    p->len = 0;  
 
   
 
    return p;  
 
}  
 
   
 
static inline gbuffer_t* _gbuffer_alloc(u32 len)  
 
{  
 
    gbuffer_t *p = NULL;  
 
   
 
#ifdef __KERNEL__  
 
    p = kzalloc( sizeof(*p), GFP_KERNEL );  
 
    if ( unlikely( NULL == p ) ){  
 
        return NULL;  
 
    }  
 
       
 
    p->buf = kzalloc( len, GFP_KERNEL );  
 
    if ( unlikely( NULL == p->buf ) ){  
 
        kfree( p );  
 
        return NULL;  
 
    }  
 
#else  
 
    p = malloc( sizeof(*p) );  
 
    if ( NULL == p )  
 
        return NULL;  
 
           
 
    p->buf = malloc( len );  
 
    if ( NULL == p->buf ){  
 
        free( p );  
 
        return -1;  
 
    }  
 
#endif  
 
    p->len = len;  
 
    return p;  
 
}  
 
   
 
static inline int gbuffer_alloc( gbuffer *p, u32 len )  
 
{  
 
    if ( NULL == p )  
 
        return -1;  
 
   
 
#ifdef __KERNEL__  
 
    p->buf = kzalloc( len, GFP_KERNEL );  
 
    if ( unlikely( NULL == p->buf ) ){  
 
        return -1;  
 
    }  
 
#else  
 
    p->buf = malloc( len );  
 
    if ( NULL == p->buf ){  
 
        return -1;  
 
    }  
 
#endif  
 
    p->len = len;  
 
    return 0;  
 
} 