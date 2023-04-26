#ifndef _PHYTIUM_CE_LOG_H_
#define _PHYTIUM_CE_LOG_H_

#include <stdint.h>


#define PCE_ENABLE_LOG


#ifdef __cplusplus
extern "C" {
#endif

#define API __attribute__((visibility("default")))

#define PCE_LOG_MSG_LEN_START 256

#ifdef PCE_ENABLE_LOG

#define PCE_LOG_ALWAYS(...) pce_log_always(__VA_ARGS__)
#define PCE_LOG_ERR(...) pce_log(PCE_LOG_LL_ERR, __VA_ARGS__)
#define PCE_LOG_WRN(...) pce_log(PCE_LOG_LL_WRN, __VA_ARGS__)
#define PCE_LOG_INF(...) pce_log(PCE_LOG_LL_INF, __VA_ARGS__)
#define PCE_LOG_DBG(...) pce_log(PCE_LOG_LL_DBG, __VA_ARGS__)

#else

#define PCE_LOG_ALWAYS(...) do {\
    fprintf(stdout, __VA_ARGS__);\
}while(0)

#define PCE_LOG_ERR(...)  fprintf(stderr, __VA_ARGS__)
#define PCE_LOG_WRN(...)  
#define PCE_LOG_INF(...)  
#define PCE_LOG_DBG(...)  

#endif


typedef enum {
    PCE_LOG_LL_NONE = 0, /**< Do not print any messages. */
    PCE_LOG_LL_ERR,      /**< Print only error messages. */
    PCE_LOG_LL_WRN,      /**< Print error and warning messages. */
    PCE_LOG_LL_INF,      /**< Besides errors and warnings, print some other
                         informational messages. */
    PCE_LOG_LL_DBG,      /**< Print all messages including some development debug
                         messages. */
} pce_log_level_t;

typedef void (*pce_log_cb)(pce_log_level_t level, const char *message);

API void pce_log_msg(pce_log_level_t ll, const char *msg);

API void pce_log(pce_log_level_t ll, const char *format, ...);

void pce_log_set_stderr(pce_log_level_t log_level);

pce_log_level_t pce_log_get_stderr(void);

void pce_log_always(const char *format, ...);

//#define PCE_LOG_SYSLOG

#ifndef PCE_LOG_DISABLE_SYSLOG
#define PCE_LOG_SYSLOG
#else
#ifdef PCE_LOG_SYSLOG
#undef PCE_LOG_SYSLOG
#endif

#endif


#ifdef PCE_LOG_SYSLOG

void pce_log_set_syslog(const char *app_name, pce_log_level_t log_level);

pce_log_level_t pce_log_get_syslog(void);

#endif

void pce_log_set_cb(pce_log_cb log_callback);


#ifdef __cplusplus
}
#endif

#endif




