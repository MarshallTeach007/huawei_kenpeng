//
// Created by dongbo on 2022/11/25.
//


#include <sdf.h>
#include <sdb_sdf.h>
#include <sdf_type.h>
#include <sdf_dev_manage.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <iostream>
#include <unistd.h>


extern "C" int EVDF_DestroySessionKeyInfo(void        *hSessionHandle,
                                          unsigned int uiType,
                                          unsigned int uiParam1,
                                          unsigned int uiParam2);

int main()
{
  {
    u32           r;
    void         *hDevcieHandle= NULL;
    void         *hSessionHandle= NULL;
    unsigned char firm_version[64]= {0};

    r= SDF_OpenDevice(&hDevcieHandle);
    if (r)
    {
      printf("SDF_OpenDevice failed:%x\n", r);
      return r;
    }

    r= SDF_OpenSession(hDevcieHandle, &hSessionHandle);
    if (r)
    {
      printf("SDF_OpenSession failed:%x\n", r);
      return r;
    }

    r= EVDF_GetFirmwareVersion(hSessionHandle, firm_version);
    if (r)
    {
      printf("SDF_OpenSession fail:%x\n", r);
      return r;
    }

    EVDF_DestroySessionKeyInfo(hSessionHandle, 0, 0, 0);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(hDevcieHandle);
  }


  if (access("./clean_time", R_OK) != 0)
  {
    u32           r;
    void         *hDevcieHandle= NULL;
    void         *hSessionHandle= NULL;
    unsigned char firm_version[64]= {0};

    r= SDF_OpenDevice(&hDevcieHandle);
    if (r)
    {
      printf("SDF_OpenDevice failed:%x\n", r);
      return r;
    }

    r= SDF_OpenSession(hDevcieHandle, &hSessionHandle);
    if (r)
    {
      printf("SDF_OpenSession failed:%x\n", r);
      return r;
    }

    r= EVDF_GetFirmwareVersion(hSessionHandle, firm_version);
    if (r)
    {
      printf("SDF_OpenSession fail:%x\n", r);
      return r;
    }
    u32         uiMasterKeyBits= MASTER_KEY_LEN;
    std::string admin_pin= "11111111";

    r= EVDF_InitKeyFileSystem(hSessionHandle, (char *)admin_pin.data(), NULL,
                              128, (char *)admin_pin.data(),
                              (char *)admin_pin.data());
    if (r)
    {
      printf("SDF_InitKeyFileSystem fail:%x\n", r);
      return r;
    }


    for (unsigned int i= 1; i < 16; i++)
    {
      r= SDF_GetPrivateKeyAccessRight(hSessionHandle, i,
                                      (unsigned char *)admin_pin.data(),
                                      admin_pin.length());
      if (r)
      {
        printf("get access right %d failed:%x\n", i, r);
        return r;
      }

      //            int EVDF_ImportKEK(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucKey, unsigned int uiKeyBits);
      r= EVDF_CreateKEK(hSessionHandle, i, uiMasterKeyBits);
      if (r)
      {
        printf("create master key[%d] failed:%x\n", i, r);
      }
    }

    std::cout << "init key ok ..." << std::endl;

    int         t= time(0);
    std::string cmd= "echo " + std::to_string(t) + "> ./clean_time";
    system(cmd.c_str());
    sleep(1);

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(hDevcieHandle);
  }
  else
  {
    std::cout << "No need clean" << std::endl;
  }


  return 0;
}
