#ifndef _PHYTIUM_CE_LOG_H_
#define _PHYTIUM_CE_LOG_H_

#include <stdint.h>

#ifdef CMAKE_CONFIG
#include "config.h"
#else
#define PCE_ENABLE_LOG
#endif


// compatable with c++
#ifdef __cplusplus
extern "C" {
#endif

#define API __attribute__((visibility("default")))

/** initial length of message buffer (B) */
#define PCE_LOG_MSG_LEN_START 256

// /* enabled output log to syslog */
// #define PCE_ENABLE_LOG // for test

#ifdef PCE_ENABLE_LOG

#define PCE_LOG_ALWAYS(...) pce_log_always(__VA_ARGS__)
#define PCE_LOG_ERR(...) pce_log(PCE_LOG_LL_ERR, __VA_ARGS__)
#define PCE_LOG_WRN(...) pce_log(PCE_LOG_LL_WRN, __VA_ARGS__)
#define PCE_LOG_INF(...) pce_log(PCE_LOG_LL_INF, __VA_ARGS__)
#define PCE_LOG_DBG(...) pce_log(PCE_LOG_LL_DBG, __VA_ARGS__)

#else

#define PCE_LOG_ALWAYS(...) do {\
    fprintf(stderr, __VA_ARGS__);\
}while(0)

#define PCE_LOG_ERR(...)  fprintf(stderr, __VA_ARGS__)
#define PCE_LOG_WRN(...)  
#define PCE_LOG_INF(...)  
#define PCE_LOG_DBG(...)  

#endif


/**
 * @brief Log levels used to determine if message of certain severity should be
 * printed.
 */
typedef enum {
    PCE_LOG_LL_NONE = 0, /**< Do not print any messages. */
    PCE_LOG_LL_ERR,      /**< Print only error messages. */
    PCE_LOG_LL_WRN,      /**< Print error and warning messages. */
    PCE_LOG_LL_INF,      /**< Besides errors and warnings, print some other
                         informational messages. */
    PCE_LOG_LL_DBG,      /**< Print all messages including some development debug
                         messages. */
} pce_log_level_t;

/**
 * @brief Sets callback that will be called when a log entry would be populated.
 *
 * @param[in] level Verbosity level of the log entry.
 * @param[in] message Message of the log entry.
 */
typedef void (*pce_log_cb)(pce_log_level_t level, const char *message);

/**
 * @brief Log a message.
 *
 * @param[in] ll Log level (severity).
 * @param[in] msg Message.
 */
API void pce_log_msg(pce_log_level_t ll, const char *msg);

/**
 * @brief Log a message with variable arguments.
 *
 * @param[in] ll Log level (severity).
 * @param[in] format Message format.
 * @param[in] ... Format arguments.
 */
API void pce_log(pce_log_level_t ll, const char *format, ...);

/**
 * @brief Enables / disables / changes log level (verbosity) of logging to
 * standard error output.
 *
 * By default, logging to stderr is disabled. Setting log level to any value
 * other than ::PCE_LOG_LL_NONE enables the logging to stderr. Setting log level
 * back to ::PCE_LOG_LL_NONE disables the logging to stderr.
 *
 *
 * @param[in] log_level Requested log level (verbosity).
 */
void pce_log_set_stderr(pce_log_level_t log_level);

/**
 * @brief Learn current standard error output log level.
 *
 * @return stderr log level.
 */
pce_log_level_t pce_log_get_stderr(void);

void pce_log_always(const char *format, ...);

//#define PCE_LOG_SYSLOG // for test


#ifndef PCE_LOG_DISABLE_SYSLOG
#define PCE_LOG_SYSLOG
#else
#ifdef PCE_LOG_SYSLOG
#undef PCE_LOG_SYSLOG
#endif

#endif


#ifdef PCE_LOG_SYSLOG

/**
 * @brief Enables / disables / changes log level (verbosity) of logging to
 * system log.
 *
 * By default, logging into syslog is disabled. Setting log level to any value
 * other than ::PCE_LOG_LL_NONE enables the logging into syslog. Setting log level
 * back to ::PCE_LOG_LL_NONE disables the logging into syslog.
 *
 * Library messages are logged with LOG_USER facility and plugin
 * (syrepo-plugind) messages are logged with LOG_DAEMON facility.
 *
 * @note Please note that enabling logging into syslog will overwrite your
 * syslog connection settings (calls openlog), if you are connected to syslog
 * already.
 *
 * @param[in] app_name Name of the application. If not set, "sysrepo" will be
 * used.
 * @param[in] log_level Requested log level (verbosity).
 */
void pce_log_set_syslog(const char *app_name, pce_log_level_t log_level);

/**
 * @brief Learn current system log log level.
 *
 * @return syslog log level.
 */
pce_log_level_t pce_log_get_syslog(void);

#endif

/**
 * @brief Sets callback that will be called when a log entry would be populated.
 * Callback will be called for every message __regardless__ of any log level.
 *
 * @param[in] log_callback Callback to be called when a log entry would
 * populated.
 */
void pce_log_set_cb(pce_log_cb log_callback);


#ifdef __cplusplus
}
#endif

#endif




