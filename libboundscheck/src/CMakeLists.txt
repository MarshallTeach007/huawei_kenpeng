cmake_minimum_required(VERSION 3.16)
project(nvx_boundscheck)

include_directories(.)
set(src fscanf_s.c   memset_s.c     secureinput_a.c        sprintf_s.c  strtok_s.c    vsnprintf_s.c  wcscat_s.c   wmemmove_s.c
        fwscanf_s.c  secureinput_w.c        sscanf_s.c   swprintf_s.c  vsprintf_s.c   wcscpy_s.c   wscanf_s.c
        gets_s.c     scanf_s.c      secureprintoutput_a.c  strcat_s.c   swscanf_s.c   vsscanf_s.c    wcsncat_s.c
        input.inl    strcpy_s.c   vfscanf_s.c   vswprintf_s.c  wcsncpy_s.c
        memcpy_s.c   securecutil.c  secureprintoutput_w.c  strncat_s.c  vfwscanf_s.c  vswscanf_s.c   wcstok_s.c
        memmove_s.c  snprintf_s.c           strncpy_s.c  vscanf_s.c    vwscanf_s.c    wmemcpy_s.c)

add_library(nvx_boundscheck STATIC ${src})


