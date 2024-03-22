#ifndef _LOGGING_H_
#define _LOGGING_H_

/* ##############   Includes   ############## */
#include <stdio.h>

/* #########   Macros   ######## */
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT __FILE__ ":" TOSTRING(__LINE__)

#define NORMAL "\033[0m"
#define RED "\033[0;31m"
#define BLUE "\033[0;94m"
#define GREEN "\033[0;32m"

#ifndef NDEBUG

#define LOGD(fmt, ...) \
    printf(GREEN "[+] %16s -- " fmt "\n" NORMAL, AT, ##__VA_ARGS__)
#define LOGI(fmt, ...) \
    printf(BLUE "[*] %16s -- " fmt "\n" NORMAL, AT, ##__VA_ARGS__)
#define LOGE(fmt, ...) \
    printf(RED "[-] %16s -- " fmt "\n" NORMAL, AT, ##__VA_ARGS__)

#else

#define LOGD(...)
#define LOGI(...)
#define LOGE(...)

#endif /* NDEBUG */

#endif  // _LOGGING_H_
