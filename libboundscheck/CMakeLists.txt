cmake_minimum_required(VERSION 3.16)
project(nvx_boundscheck)

include_directories(include)
include_directories(check_src)


set(check_src
        src/fwscanf_s.c
        src/secureinput_w.c
        src/sscanf_s.c
        src/swprintf_s.c
        src/vsprintf_s.c
        src/wcscpy_s.c
        src/wscanf_s.c
        src/gets_s.c
        src/scanf_s.c
        src/secureprintoutput_a.c
        src/strcat_s.c
        src/swscanf_s.c
        src/vsscanf_s.c
        src/snprintf_s.c
        src/vsnprintf_s.c
        src/memset_s.c
        src/wcsncat_s.c
        src/strcpy_s.c
        src/vfscanf_s.c
        src/vswprintf_s.c
        src/wcsncpy_s.c
        src/memcpy_s.c
        src/securecutil.c
        src/secureprintoutput_w.c
        src/strncat_s.c
        src/vfwscanf_s.c
        src/vswscanf_s.c
        src/wcstok_s.c
        src/memmove_s.c
        src/snprintf_s.c
        src/strncpy_s.c
        src/vscanf_s.c
        src/vwscanf_s.c
        src/wmemcpy_s.c)

add_library(nvx_boundscheck STATIC ${check_src})

#add_custom_command(TARGET nvx_boundscheck
#    POST_BUILD
#    COMMAND mkdir -p ${CMAKE_PROJECT_ROOT_PATH}/dist
#    COMMAND cp -f ${CMAKE_PROJECT_ROOT_PATH}/libboundscheck/lib/libnvx_boundscheck.a ${CMAKE_PROJECT_ROOT_PATH}/dist
#)

