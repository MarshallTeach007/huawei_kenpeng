//
// Created by dongbo on 2023/1/14.
//

#ifndef ENCRYPT_CARD_SOFT_CARD_H
#define ENCRYPT_CARD_SOFT_CARD_H
#include <unistd.h>
#include <string.h>

extern "C" {
int SDF_OpenDevice(void **phDeviceHandle);

int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);

int SDF_GetPrivateKeyAccessRight(void          *hSessionHandle,
                                 unsigned int   uiKeyIndex,
                                 unsigned char *pucPassword,
                                 unsigned int   uiPwdLength);

int SDF_GenerateKeyWithKEK(void *hSessionHandle, unsigned int uiKeyBits,
                           unsigned int uiAlgID, unsigned int uiKEKIndex,
                           unsigned char *pucKey, unsigned int *puiKeyLength,
                           void **phKeyHandle);

int SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID,
                         unsigned int uiKEKIndex, unsigned char *pucKey,
                         unsigned int puiKeyLength, void **phKeyHandle);

/*symm*/
int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
                unsigned char *pucIV, unsigned char *pucData,
                unsigned int uiDataLength, unsigned char *pucEncData,
                unsigned int *puiEncDataLength);

int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
                unsigned char *pucIV, unsigned char *pucEncData,
                unsigned int uiEncDataLength, unsigned char *pucData,
                unsigned int *puiDataLength);


int EVDF_GetFirmwareVersion(void *hSessionHandle, unsigned char *pstFirmInfo);


int SDF_CloseDevice(void *hDeviceHandle);

int SDF_CloseSession(void *hSessionHandle);

int EVDF_InitKeyFileSystem(void *hSessionHandle, char *AdminPin,
                           unsigned char *pucRootKey, unsigned int uiKeyBits,
                           char *NewAdminPin, char *NewUserPIN);

int EVDF_DestroySessionKeyInfo(void *hSessionHandle, unsigned int uiType,
                               unsigned int uiParam1, unsigned int uiParam2);

int EVDF_CreateKEK(void *hSessionHandle, unsigned int uiKeyIndex,
                   unsigned int uiKeyBits);
}

#endif  //ENCRYPT_CARD_SOFT_CARD_H
