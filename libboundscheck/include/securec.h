/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2021. All rights reserved.
 * Licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: The user of this secure c library should include this header file in you source code.
 *              This header file declare all supported API prototype of the library,
 *              such as nvx_memcpy_s, nvx_strcpy_s, nvx_wcscpy_s,nvx_strcat_s, nvx_strncat_s, nvx_sprintf_s, nvx_scanf_s, and so on.
 * Create: 2014-02-25
 * Notes: Do not modify this file by yourself.
 */

#ifndef SECUREC_H_5D13A042_DC3F_4ED9_A8D1_882811274C27
#define SECUREC_H_5D13A042_DC3F_4ED9_A8D1_882811274C27

#include "securectype.h"
#ifndef SECUREC_HAVE_STDARG_H
#define SECUREC_HAVE_STDARG_H 1
#endif

#if SECUREC_HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifndef SECUREC_HAVE_ERRNO_H
#define SECUREC_HAVE_ERRNO_H 1
#endif

/* EINVAL ERANGE may defined in errno.h */
#if SECUREC_HAVE_ERRNO_H
#if SECUREC_IN_KERNEL
#include <linux/errno.h>
#else
#include <errno.h>
#endif
#endif

/* Define error code */
#if defined(SECUREC_NEED_ERRNO_TYPE) || !defined(__STDC_WANT_LIB_EXT1__) || \
    (defined(__STDC_WANT_LIB_EXT1__) && (!__STDC_WANT_LIB_EXT1__))
#ifndef SECUREC_DEFINED_ERRNO_TYPE
#define SECUREC_DEFINED_ERRNO_TYPE
/* Just check whether macrodefinition exists. */
#ifndef errno_t
typedef int errno_t;
#endif
#endif
#endif

/* Success */
#ifndef EOK
#define EOK 0
#endif

#ifndef EINVAL
/* The src buffer is not correct and destination buffer can not be reset */
#define EINVAL 22
#endif

#ifndef EINVAL_AND_RESET
/* Once the error is detected, the dest buffer must be reset! Value is 22 or 128 */
#define EINVAL_AND_RESET 150
#endif

#ifndef ERANGE
/* The destination buffer is not long enough and destination buffer can not be reset */
#define ERANGE 34
#endif

#ifndef ERANGE_AND_RESET
/* Once the error is detected, the dest buffer must be reset! Value is 34 or 128 */
#define ERANGE_AND_RESET  162
#endif

#ifndef EOVERLAP_AND_RESET
/* Once the buffer overlap is detected, the dest buffer must be reset! Value is 54 or 128 */
#define EOVERLAP_AND_RESET 182
#endif

/* If you need export the function of this library in Win32 dll, use __declspec(dllexport) */
#ifndef SECUREC_API
#if defined(SECUREC_DLL_EXPORT)
#define SECUREC_API __declspec(dllexport)
#elif defined(SECUREC_DLL_IMPORT)
#define SECUREC_API __declspec(dllimport)
#else
/*
 * Standardized function declaration. If a security function is declared in the your code,
 * it may cause a compilation alarm,Please delete the security function you declared.
 * Adding extern under windows will cause the system to have functions to expand,
 * so do not add the extern in default
 */
#if defined(_MSC_VER)
#define SECUREC_API
#else
#define SECUREC_API  extern
#endif
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Description: The GetHwSecureCVersion function get SecureC Version string and version number.
 * Parameter: verNumber - to store version number (for example value is 0x500 | 0xa)
 * Return:   version string
 */
SECUREC_API const char *GetHwSecureCVersion(unsigned short *verNumber);

#if SECUREC_ENABLE_MEMSET
/*
 * Description: The nvx_memset_s function copies the value of c (converted to an unsigned char) into each of
 * the first count characters of the object pointed to by dest.
 * Parameter: dest - destination address
 * Parameter: destMax - The maximum length of destination buffer
 * Parameter: c - the value to be copied
 * Parameter: count - copies count bytes of value to dest
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t  nvx_memset_s(void *dest, size_t destMax, int c, size_t count);
#endif

#ifndef SECUREC_ONLY_DECLARE_MEMSET
#define SECUREC_ONLY_DECLARE_MEMSET     0
#endif

#if !SECUREC_ONLY_DECLARE_MEMSET

#if SECUREC_ENABLE_MEMMOVE
/*
 * Description: The nvx_memmove_s function copies n characters from the object pointed to by src
 * into the object pointed to by dest.
 * Parameter: dest - destination  address
 * Parameter: destMax - The maximum length of destination buffer
 * Parameter: src - source address
 * Parameter: count - copies count bytes from the src
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_memmove_s(void *dest, size_t destMax, const void *src, size_t count);
#endif

#if SECUREC_ENABLE_MEMCPY
/*
 * Description: The nvx_memcpy_s function copies n characters from the object pointed to
 * by src into the object pointed to by dest.
 * Parameter: dest - destination  address
 * Parameter: destMax - The maximum length of destination buffer
 * Parameter: src - source address
 * Parameter: count - copies count bytes from the  src
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_memcpy_s(void *dest, size_t destMax, const void *src, size_t count);
#endif

#if SECUREC_ENABLE_STRCPY
/*
 * Description: The nvx_strcpy_s function copies the string pointed to by strSrc (including
 * the terminating null character) into the array pointed to by strDest
 * Parameter: strDest - destination  address
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null character)
 * Parameter: strSrc - source address
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_strcpy_s(char *strDest, size_t destMax, const char *strSrc);
#endif

#if SECUREC_ENABLE_STRNCPY
/*
 * Description: The nvx_strncpy_s function copies not more than n successive characters (not including
 * the terminating null character) from the array pointed to by strSrc to the array pointed to by strDest.
 * Parameter: strDest - destination  address
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null character)
 * Parameter: strSrc - source  address
 * Parameter: count - copies count characters from the src
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_strncpy_s(char *strDest, size_t destMax, const char *strSrc, size_t count);
#endif

#if SECUREC_ENABLE_STRCAT
/*
 * Description: The nvx_strcat_s function appends a copy of the string pointed to by strSrc (including
 * the terminating null character) to the end of the string pointed to by strDest.
 * Parameter: strDest - destination  address
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null wide character)
 * Parameter: strSrc - source address
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_strcat_s(char *strDest, size_t destMax, const char *strSrc);
#endif

#if SECUREC_ENABLE_STRNCAT
/*
 * Description: The nvx_strncat_s function appends not more than n successive characters (not including
 * the terminating null character)
 * from the array pointed to by strSrc to the end of the string pointed to by strDest.
 * Parameter: strDest - destination address
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null character)
 * Parameter: strSrc - source address
 * Parameter: count - copies count characters from the src
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_strncat_s(char *strDest, size_t destMax, const char *strSrc, size_t count);
#endif

#if SECUREC_ENABLE_VSPRINTF
/*
 * Description: The vnvx_sprintf_s function is equivalent to the vsprintf function except for the parameter destMax
 * and the explicit runtime-constraints violation
 * Parameter: strDest -  produce output according to a format,write to the character string strDest.
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null wide character)
 * Parameter: format - format string
 * Parameter: argList - instead of a variable number of arguments
 * Return:    the number of characters printed(not including the terminating null byte '\0'),
 * If an error occurred Return: -1.
 */
SECUREC_API int vnvx_sprintf_s(char *strDest, size_t destMax, const char *format,
                           va_list argList) SECUREC_ATTRIBUTE(3, 0);
#endif

#if SECUREC_ENABLE_SPRINTF
/*
 * Description: The nvx_sprintf_s function is equivalent to the sprintf function except for the parameter destMax
 * and the explicit runtime-constraints violation
 * Parameter: strDest -  produce output according to a format ,write to the character string strDest.
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null byte '\0')
 * Parameter: format - format string
 * Return:    the number of characters printed(not including the terminating null byte '\0'),
 * If an error occurred Return: -1.
*/
SECUREC_API int nvx_sprintf_s(char *strDest, size_t destMax, const char *format, ...) SECUREC_ATTRIBUTE(3, 4);
#endif

#if SECUREC_ENABLE_VSNPRINTF
/*
 * Description: The vnvx_snprintf_s function is equivalent to the vsnprintf function except for
 * the parameter destMax/count and the explicit runtime-constraints violation
 * Parameter: strDest -  produce output according to a format ,write to the character string strDest.
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null  byte '\0')
 * Parameter: count - do not write more than count bytes to strDest(not including the terminating null  byte '\0')
 * Parameter: format - format string
 * Parameter: argList - instead of  a variable number of arguments
 * Return:    the number of characters printed(not including the terminating null byte '\0'),
 * If an error occurred Return: -1.Pay special attention to returning -1 when truncation occurs.
 */
SECUREC_API int vnvx_snprintf_s(char *strDest, size_t destMax, size_t count, const char *format,
                            va_list argList) SECUREC_ATTRIBUTE(4, 0);
#endif

#if SECUREC_ENABLE_SNPRINTF
/*
 * Description: The nvx_snprintf_s function is equivalent to the snprintf function except for
 * the parameter destMax/count and the explicit runtime-constraints violation
 * Parameter: strDest - produce output according to a format ,write to the character string strDest.
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null  byte '\0')
 * Parameter: count - do not write more than count bytes to strDest(not including the terminating null  byte '\0')
 * Parameter: format - format string
 * Return:    the number of characters printed(not including the terminating null byte '\0'),
 * If an error occurred Return: -1.Pay special attention to returning -1 when truncation occurs.
 */
SECUREC_API int nvx_snprintf_s(char *strDest, size_t destMax, size_t count, const char *format,
                           ...) SECUREC_ATTRIBUTE(4, 5);
#endif

#if SECUREC_SNPRINTF_TRUNCATED
/*
 * Description: The vnvx_snprintf_truncated_s function is equivalent to the vnvx_snprintf_s function except
 * no count parameter and return value
 * Parameter: strDest -  produce output according to a format ,write to the character string strDest
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null  byte '\0')
 * Parameter: format - format string
 * Parameter: argList - instead of  a variable  number of arguments
 * Return:    the number of characters printed(not including the terminating null byte '\0'),
 * If an error occurred Return: -1.Pay special attention to returning destMax - 1 when truncation occurs
*/
SECUREC_API int vnvx_snprintf_truncated_s(char *strDest, size_t destMax, const char *format,
                                      va_list argList) SECUREC_ATTRIBUTE(3, 0);

/*
 * Description: The nvx_snprintf_truncated_s function is equivalent to the nvx_snprintf_s function except
 * no count parameter and return value
 * Parameter: strDest - produce output according to a format,write to the character string strDest.
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null byte '\0')
 * Parameter: format - format string
 * Return:    the number of characters printed(not including the terminating null byte '\0'),
 * If an error occurred Return: -1.Pay special attention to returning destMax - 1 when truncation occurs.
 */
SECUREC_API int nvx_snprintf_truncated_s(char *strDest, size_t destMax,
                                     const char *format, ...) SECUREC_ATTRIBUTE(3, 4);
#endif

#if SECUREC_ENABLE_SCANF
/*
 * Description: The nvx_scanf_s function is equivalent to fnvx_scanf_s with the argument stdin
 * interposed before the arguments to nvx_scanf_s
 * Parameter: format - format string
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int nvx_scanf_s(const char *format, ...);
#endif

#if SECUREC_ENABLE_VSCANF
/*
 * Description: The vnvx_scanf_s function is equivalent to nvx_scanf_s, with the variable argument list replaced by argList
 * Parameter: format - format string
 * Parameter: argList - instead of a variable number of arguments
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int vnvx_scanf_s(const char *format, va_list argList);
#endif

#if SECUREC_ENABLE_SSCANF
/*
 * Description: The snvx_scanf_s function is equivalent to fnvx_scanf_s, except that input is obtained from a
 * string (specified by the argument buffer) rather than from a stream
 * Parameter: buffer - read character from buffer
 * Parameter: format - format string
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int snvx_scanf_s(const char *buffer, const char *format, ...);
#endif

#if SECUREC_ENABLE_VSSCANF
/*
 * Description: The vsnvx_scanf_s function is equivalent to snvx_scanf_s, with the variable argument list
 * replaced by argList
 * Parameter: buffer -  read character from buffer
 * Parameter: format - format string
 * Parameter: argList - instead of a variable number of arguments
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int vsnvx_scanf_s(const char *buffer, const char *format, va_list argList);
#endif

#if SECUREC_ENABLE_FSCANF
/*
 * Description: The fnvx_scanf_s function is equivalent to fscanf except that the c, s, and [ conversion specifiers
 * apply to a pair of arguments (unless assignment suppression is indicated by a *)
 * Parameter: stream - stdio file stream
 * Parameter: format - format string
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int fnvx_scanf_s(FILE *stream, const char *format, ...);
#endif

#if SECUREC_ENABLE_VFSCANF
/*
 * Description: The vfnvx_scanf_s function is equivalent to fnvx_scanf_s, with the variable argument list
 * replaced by argList
 * Parameter: stream - stdio file stream
 * Parameter: format - format string
 * Parameter: argList - instead of a variable number of arguments
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int vfnvx_scanf_s(FILE *stream, const char *format, va_list argList);
#endif

#if SECUREC_ENABLE_STRTOK
/*
 * Description: The nvx_strtok_s function parses a string into a sequence of strToken,
 * replace all characters in strToken string that match to strDelimit set with 0.
 * On the first call to nvx_strtok_s the string to be parsed should be specified in strToken.
 * In each subsequent call that should parse the same string, strToken should be NULL
 * Parameter: strToken - the string to be delimited
 * Parameter: strDelimit - specifies a set of characters that delimit the tokens in the parsed string
 * Parameter: context - is a pointer to a char * variable that is used internally by nvx_strtok_s function
 * Return:  On the first call returns the address of the first non \0 character, otherwise NULL is returned.
 * In subsequent calls, the strtoken is set to NULL, and the context set is the same as the previous call,
 * return NULL if the *context string length is equal 0, otherwise return *context.
 */
SECUREC_API char *nvx_strtok_s(char *strToken, const char *strDelimit, char **context);
#endif

#if SECUREC_ENABLE_GETS && !SECUREC_IN_KERNEL
/*
 * Description: The nvx_gets_s function reads at most one less than the number of characters specified
 * by destMax from the stream pointed to by stdin, into the array pointed to by buffer
 * Parameter: buffer - destination address
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null character)
 * Return:    buffer if there was no runtime-constraint violation,If an error occurred Return: NULL.
 */
SECUREC_API char *nvx_gets_s(char *buffer, size_t destMax);
#endif

#if SECUREC_ENABLE_WCHAR_FUNC
#if SECUREC_ENABLE_MEMCPY
/*
 * Description: The wnvx_memcpy_s function copies n successive wide characters from the object pointed to
 * by src into the object pointed to by dest.
 * Parameter: dest - destination  address
 * Parameter: destMax - The maximum length of destination buffer
 * Parameter: src - source address
 * Parameter: count - copies count wide characters from the  src
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t wnvx_memcpy_s(wchar_t *dest, size_t destMax, const wchar_t *src, size_t count);
#endif

#if SECUREC_ENABLE_MEMMOVE
/*
 * Description: The wnvx_memmove_s function copies n successive wide characters from the object
 * pointed to by src into the object pointed to by dest.
 * Parameter: dest - destination  address
 * Parameter: destMax - The maximum length of destination buffer
 * Parameter: src - source address
 * Parameter: count - copies count wide characters from the  src
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t wnvx_memmove_s(wchar_t *dest, size_t destMax, const wchar_t *src, size_t count);
#endif

#if SECUREC_ENABLE_STRCPY
/*
 * Description: The nvx_wcscpy_s function copies the wide string pointed to by strSrc(including the terminating
 * null wide character) into the array pointed to by strDest
 * Parameter: strDest - destination address
 * Parameter: destMax - The maximum length of destination buffer
 * Parameter: strSrc - source address
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_wcscpy_s(wchar_t *strDest, size_t destMax, const wchar_t *strSrc);
#endif

#if SECUREC_ENABLE_STRNCPY
/*
 * Description: The nvx_wcsncpy_s function copies not more than n successive wide characters (not including the
 * terminating null wide character) from the array pointed to by strSrc to the array pointed to by strDest
 * Parameter: strDest - destination address
 * Parameter: destMax - The maximum length of destination buffer(including the terminating wide character)
 * Parameter: strSrc - source address
 * Parameter: count - copies count wide characters from the src
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_wcsncpy_s(wchar_t *strDest, size_t destMax, const wchar_t *strSrc, size_t count);
#endif

#if SECUREC_ENABLE_STRCAT
/*
 * Description: The nvx_wcscat_s function appends a copy of the wide string pointed to by strSrc (including the
 * terminating null wide character) to the end of the wide string pointed to by strDest
 * Parameter: strDest - destination  address
 * Parameter: destMax - The maximum length of destination buffer(including the terminating wide character)
 * Parameter: strSrc - source address
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_wcscat_s(wchar_t *strDest, size_t destMax, const wchar_t *strSrc);
#endif

#if SECUREC_ENABLE_STRNCAT
/*
 * Description: The nvx_wcsncat_s function appends not more than n successive wide characters (not including the
 * terminating null wide character) from the array pointed to by strSrc to the end of the wide string pointed to
 * by strDest.
 * Parameter: strDest - destination  address
 * Parameter: destMax - The maximum length of destination buffer(including the terminating wide character)
 * Parameter: strSrc - source  address
 * Parameter: count - copies count wide characters from the  src
 * Return:    EOK if there was no runtime-constraint violation
 */
SECUREC_API errno_t nvx_wcsncat_s(wchar_t *strDest, size_t destMax, const wchar_t *strSrc, size_t count);
#endif

#if SECUREC_ENABLE_STRTOK
/*
 * Description: The nvx_wcstok_s function is the wide-character equivalent of the nvx_strtok_s function
 * Parameter: strToken - the string to be delimited
 * Parameter: strDelimit - specifies a set of characters that delimit the tokens in the parsed string
 * Parameter: context - is a pointer to a char * variable that is used internally by nvx_strtok_s function
 * Return:    a pointer to the first character of a token, or a null pointer if there is no token
 * or there is a runtime-constraint violation.
 */
SECUREC_API wchar_t *nvx_wcstok_s(wchar_t *strToken, const wchar_t *strDelimit, wchar_t **context);
#endif

#if SECUREC_ENABLE_VSPRINTF
/*
 * Description: The nvx_vswprintf_s function is the wide-character equivalent of the vnvx_sprintf_s function
 * Parameter: strDest - produce output according to a format,write to the character string strDest
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null)
 * Parameter: format - format string
 * Parameter: argList - instead of a variable number of arguments
 * Return:    the number of characters printed(not including the terminating null wide character),
 * If an error occurred Return: -1.
 */
SECUREC_API int nvx_vswprintf_s(wchar_t *strDest, size_t destMax, const wchar_t *format, va_list argList);
#endif

#if SECUREC_ENABLE_SPRINTF
/*
 * Description: The swprintf_s function is the wide-character equivalent of the nvx_sprintf_s function
 * Parameter: strDest - produce output according to a format,write to the character string strDest
 * Parameter: destMax - The maximum length of destination buffer(including the terminating null)
 * Parameter: format - format string
 * Return:    the number of characters printed(not including the terminating null wide character),
 * If an error occurred Return: -1.
 */
SECUREC_API int swprintf_s(wchar_t *strDest, size_t destMax, const wchar_t *format, ...);
#endif

#if SECUREC_ENABLE_FSCANF
/*
 * Description: The fwnvx_scanf_s function is the wide-character equivalent of the fnvx_scanf_s function
 * Parameter: stream - stdio file stream
 * Parameter: format - format string
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int fwnvx_scanf_s(FILE *stream, const wchar_t *format, ...);
#endif

#if SECUREC_ENABLE_VFSCANF
/*
 * Description: The vfwnvx_scanf_s function is the wide-character equivalent of the vfnvx_scanf_s function
 * Parameter: stream - stdio file stream
 * Parameter: format - format string
 * Parameter: argList - instead of  a variable number of arguments
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int vfwnvx_scanf_s(FILE *stream, const wchar_t *format, va_list argList);
#endif

#if SECUREC_ENABLE_SCANF
/*
 * Description: The wnvx_scanf_s function is the wide-character equivalent of the nvx_scanf_s function
 * Parameter: format - format string
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int wnvx_scanf_s(const wchar_t *format, ...);
#endif

#if SECUREC_ENABLE_VSCANF
/*
 * Description: The vwnvx_scanf_s function is the wide-character equivalent of the vnvx_scanf_s function
 * Parameter: format - format string
 * Parameter: argList - instead of  a variable number of arguments
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int vwnvx_scanf_s(const wchar_t *format, va_list argList);
#endif

#if SECUREC_ENABLE_SSCANF
/*
 * Description: The swnvx_scanf_s function is the wide-character equivalent of the snvx_scanf_s function
 * Parameter: buffer - read character from buffer
 * Parameter: format - format string
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int swnvx_scanf_s(const wchar_t *buffer, const wchar_t *format, ...);
#endif

#if SECUREC_ENABLE_VSSCANF
/*
 * Description: The vswnvx_scanf_s function is the wide-character equivalent of the vsnvx_scanf_s function
 * Parameter: buffer -  read character from  buffer
 * Parameter: format - format string
 * Parameter: argList - instead of  a variable number of arguments
 * Return:    the number of input items assigned, If an error occurred Return: -1.
 */
SECUREC_API int vswnvx_scanf_s(const wchar_t *buffer, const wchar_t *format, va_list argList);
#endif
#endif /* SECUREC_ENABLE_WCHAR_FUNC */
#endif

/* Those functions are used by macro,must declare hare, also for without function declaration warning */
extern errno_t strncpy_error(char *strDest, size_t destMax, const char *strSrc, size_t count);
extern errno_t strcpy_error(char *strDest, size_t destMax, const char *strSrc);

#if SECUREC_WITH_PERFORMANCE_ADDONS
/* Those functions are used by macro */
extern errno_t nvx_memset_sOptAsm(void *dest, size_t destMax, int c, size_t count);
extern errno_t nvx_memset_sOptTc(void *dest, size_t destMax, int c, size_t count);
extern errno_t nvx_memcpy_sOptAsm(void *dest, size_t destMax, const void *src, size_t count);
extern errno_t nvx_memcpy_sOptTc(void *dest, size_t destMax, const void *src, size_t count);

/* The nvx_strcpy_sp is a macro, not a function in performance optimization mode. */
#define nvx_strcpy_sp(dest, destMax, src)  ((__builtin_constant_p((destMax)) && \
    __builtin_constant_p((src))) ?  \
    SECUREC_STRCPY_SM((dest), (destMax), (src)) : \
    nvx_strcpy_s((dest), (destMax), (src)))

/* The nvx_strncpy_sp is a macro, not a function in performance optimization mode. */
#define nvx_strncpy_sp(dest, destMax, src, count)  ((__builtin_constant_p((count)) && \
    __builtin_constant_p((destMax)) && \
    __builtin_constant_p((src))) ?  \
    SECUREC_STRNCPY_SM((dest), (destMax), (src), (count)) : \
    nvx_strncpy_s((dest), (destMax), (src), (count)))

/* The nvx_strcat_sp is a macro, not a function in performance optimization mode. */
#define nvx_strcat_sp(dest, destMax, src) ((__builtin_constant_p((destMax)) && \
    __builtin_constant_p((src))) ?  \
    SECUREC_STRCAT_SM((dest), (destMax), (src)) : \
    nvx_strcat_s((dest), (destMax), (src)))

/* The nvx_strncat_sp is a macro, not a function in performance optimization mode. */
#define nvx_strncat_sp(dest, destMax, src, count) ((__builtin_constant_p((count)) &&  \
    __builtin_constant_p((destMax)) && \
    __builtin_constant_p((src))) ?  \
    SECUREC_STRNCAT_SM((dest), (destMax), (src), (count)) : \
    nvx_strncat_s((dest), (destMax), (src), (count)))

/* The nvx_memcpy_sp is a macro, not a function in performance optimization mode. */
#define nvx_memcpy_sp(dest, destMax, src, count)  (__builtin_constant_p((count)) ? \
    (SECUREC_MEMCPY_SM((dest), (destMax), (src), (count))) : \
    (__builtin_constant_p((destMax)) ? \
    (((size_t)(destMax) > 0 && \
    (((unsigned long long)(destMax) & (unsigned long long)(-2)) < SECUREC_MEM_MAX_LEN)) ? \
    nvx_memcpy_sOptTc((dest), (destMax), (src), (count)) : ERANGE) : \
    nvx_memcpy_sOptAsm((dest), (destMax), (src), (count))))

/* The nvx_memset_sp is a macro, not a function in performance optimization mode. */
#define nvx_memset_sp(dest, destMax, c, count)  (__builtin_constant_p((count)) ? \
    (SECUREC_MEMSET_SM((dest), (destMax), (c), (count))) : \
    (__builtin_constant_p((destMax)) ? \
    (((((unsigned long long)(destMax) & (unsigned long long)(-2)) < SECUREC_MEM_MAX_LEN)) ? \
    nvx_memset_sOptTc((dest), (destMax), (c), (count)) : ERANGE) : \
    nvx_memset_sOptAsm((dest), (destMax), (c), (count))))

#endif

#ifdef __cplusplus
}
#endif
#endif

