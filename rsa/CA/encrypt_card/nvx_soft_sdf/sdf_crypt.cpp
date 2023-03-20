//
// Created by dongbo on 2023/1/14.
//

#include "sdf_crypt.h"

int SDF_OpenDevice(void **phDeviceHandle) { return 0; }

int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle) { return 0; }

int SDF_GetPrivateKeyAccessRight(void          *hSessionHandle,
                                 unsigned int   uiKeyIndex,
                                 unsigned char *pucPassword,
                                 unsigned int   uiPwdLength)
{
  return 0;
}

int SDF_GenerateKeyWithKEK(void *hSessionHandle, unsigned int uiKeyBits,
                           unsigned int uiAlgID, unsigned int uiKEKIndex,
                           unsigned char *pucKey, unsigned int *puiKeyLength,
                           void **phKeyHandle)
{
  return 0;
}
int SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID,
                         unsigned int uiKEKIndex, unsigned char *pucKey,
                         unsigned int puiKeyLength, void **phKeyHandle)
{
  return 0;
}

/*symm*/
int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
                unsigned char *pucIV, unsigned char *pucData,
                unsigned int uiDataLength, unsigned char *pucEncData,
                unsigned int *puiEncDataLength)
{


  return 0;
}
int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
                unsigned char *pucIV, unsigned char *pucEncData,
                unsigned int uiEncDataLength, unsigned char *pucData,
                unsigned int *puiDataLength)
{
  return 0;
}

int EVDF_GetFirmwareVersion(void *hSessionHandle, unsigned char *pstFirmInfo)
{
  return 0;
}


int EVDF_DestroySessionKeyInfo(void *hSessionHandle, unsigned int uiType,
                               unsigned int uiParam1, unsigned int uiParam2)
{
  return 0;
}


int SDF_CloseDevice(void *hDeviceHandle) { return 0; }

int SDF_CloseSession(void *hSessionHandle) { return 0; }


int EVDF_InitKeyFileSystem(void *hSessionHandle, char *AdminPin,
                           unsigned char *pucRootKey, unsigned int uiKeyBits,
                           char *NewAdminPin, char *NewUserPIN)
{
  return 0;
}

int EVDF_CreateKEK(void *hSessionHandle, unsigned int uiKeyIndex,
                   unsigned int uiKeyBits)
{
  return 0;
}
