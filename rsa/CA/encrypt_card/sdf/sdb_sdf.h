#include "base_type.h"
#include "sdf_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_KEY_INDEX 0x0F
#define MASTER_KEY_ALG SGD_SMS4_ECB
#define MASTER_KEY_LEN 128
#define DEK_ALG SGD_SMS4_CBC
#define DEK_LEN 128
#define ADMIN_PIN "11111111"
#define ADMIN_PIN_LEN 8

// System Manage
int InitKeyFileSystem(void *hSessionHandle, char *AdminPin,
                      unsigned char *pucRootKey, unsigned int uiKeyBits,
                      char *NewAdminPin, char *NewUserPIN);

int ChangePIN(void *hSessionHandle, unsigned int uiKeyIndex,
              unsigned int uiPINType, char *OldPIN, char *NewPIN,
              unsigned int *puiRetry);
int UnlockPIN(void *hSessionHandle, unsigned int uiKeyIndex, char *AdminPIN,
              char *NewUserPIN, unsigned int *puiRetry);


int CreateMasterKey(void *hSessionHandle, unsigned int uiKeyIndex,
                    unsigned int uiKeyBits);
int ImportMasterKey(void *hSessionHandle, unsigned int uiKeyIndex,
                    unsigned char *pucKey, unsigned int uiKeyBits);
int DeleteMasterKey(void *hSessionHandle, unsigned int uiKeyIndex,
                    char *AdminPIN);

int GenerateDEK(void *hSessionHandle, unsigned int uiKeyBits,
                unsigned int uiAlgID, unsigned int uiKEKIndex,
                unsigned char *pucKey, unsigned int *puiKeyLength,
                void **phKeyHandle);
int ImportEncryptedDEK(void *hSessionHandle, unsigned int uiAlgID,
                       unsigned int uiKEKIndex, unsigned char *pucKey,
                       unsigned int puiKeyLength, void **phKeyHandle);
int ImportDEK(void *hSessionHandle, unsigned char *pucKey,
              unsigned int uiKeyLength, void **phKeyHandle);

int DEKEncrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
               unsigned char *pucIV, unsigned char *pucData,
               unsigned int uiDataLength, unsigned char *pucEncData,
               unsigned int *puiEncDataLength);

int DEKDecrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
               unsigned char *pucIV, unsigned char *pucEncData,
               unsigned int uiEncDataLength, unsigned char *pucData,
               unsigned int *puiDataLength);

int DestroyDEK(void *hSessionHandle, void *hKeyHandle);


#ifdef __cplusplus
};
#endif
