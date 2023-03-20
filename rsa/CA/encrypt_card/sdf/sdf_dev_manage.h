#ifndef __SDF_DEV_MANAGE_H__
#define __SDF_DEV_MANAGE_H__

#include "base_type.h"
#include "sdf_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int EVDF_CreateKeyPair_ECC(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
int EVDF_ImportKeyPair_ECC(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex,  ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
int EVDF_ImportEncKeyPair_ECC(void *hSessionHandle, unsigned int uiKeyIndex, PENVELOPEDKEYBLOB pBlob);
int EVDF_DeleteInternalKeyPair_ECC (void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, char *AdminPIN);
int EVDF_CreateKeyPair_RSA(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, unsigned int uiBitLen, RSArefPublicKey *pucPublicKey);
int EVDF_ImportKeyPair_RSA(void *hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, RSArefPrivateKey *pucPrivateKey);
int EVDF_ImportEncKeyPair_RSA (void *hSessionHandle, unsigned int uiKeyIndex, unsigned int ulSymmAlgID, unsigned char *pbWrappedKey, 
								unsigned int ulWrappedKeyLen, unsigned char *pbEncryptedData, unsigned int ulEncryptedDataLen);
int EVDF_DeleteInternalKeyPair_RSA (void *hSessionHandle, unsigned int uiSignFlag,unsigned int uiKeyIndex, char *AdminPIN);
int EVDF_CreateKEK(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiKeyBits);
int EVDF_ImportKEK(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucKey, unsigned int uiKeyBits);
int EVDF_DeleteInternalKEK (void *hSessionHandle, unsigned int uiKeyIndex, char *AdminPIN);
int EVDF_GetPINInfo(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiPINType, 
						unsigned int *puiMaxRetryCount, unsigned int *puiRemainRetryCount);
int EVDF_ChangePIN(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiPINType, 
						char *OldPIN, char *NewPIN, unsigned int *puiRetry);
int EVDF_UnlockPIN(void *hSessionHandle, unsigned int uiKeyIndex, char *AdminPIN, char *NewUserPIN, unsigned int *puiRetry);
int EVDF_GetKeySlotInfo(void *hSessionHandle, unsigned int uiKeyIndex, SlotKeyInfo *pInfo);
int EVDF_GetFirmwareVersion(void *hSessionHandle, unsigned char *pstFirmInfo);
/**
 * Initialize the file system and set root key & admin pin & user pin
 * @arg hSessionHandle		A pointer to the handle of session
 * @arg AdminPin			A pointer to the admin pin and be verified in cos(if no file system initialized in cos, not be verified)
 * @arg pucRootKey			A pointer to the rootkey to be set, if NULL create rootkey using random data in cos
 * @arg uiKeyBits			the bits size of rootkey
 * @arg NewAdminPin		A pointer to the new admin pin
 * @arg NewUserPIN			A pointer to the nw user pin
 *
 * Initialize root key, admin pin, user pin, and file system.
 *
 * @return error code or 0.
 */
int EVDF_InitKeyFileSystem(void *hSessionHandle, char *AdminPin, unsigned char *pucRootKey, unsigned int uiKeyBits, char *NewAdminPin, char*NewUserPIN);
int EVDF_RestoreFactorySetting(void *hSessionHandle, char *AdminPin);
//int SDF_KeyDistributionPrepare(void *hSessionHandle, char *AdminPin, unsigned char ucStoreKeyNum, unsigned char ucRestoreKeyNum);
//int SDF_KeyDistributionStore(void *hSessionHandle, char *AdminPin, unsigned char ucStoreKeyIndex);
//int SDF_KeyDistributionRestore(void *hSessionHandle, char *AdminPin, unsigned char ucRestoreKeyIndex);

#define SDF_CreateKeyPair_ECC EVDF_CreateKeyPair_ECC
#define SDF_ImportKeyPair_ECC EVDF_ImportKeyPair_ECC
#define SDF_CreateKeyPair_RSA EVDF_CreateKeyPair_RSA
#define SDF_ImportKeyPair_RSA EVDF_ImportKeyPair_RSA
#define SDF_CreateKEK EVDF_CreateKEK
#define SDF_ImportKEK EVDF_ImportKEK
#define SDF_GetPINInfo EVDF_GetPINInfo
#define SDF_ChangePIN EVDF_ChangePIN
#define SDF_UnlockPIN EVDF_UnlockPIN
#define SDF_GetKeySlotInfo EVDF_GetKeySlotInfo
#define SDF_GetFirmwareVersion EVDF_GetFirmwareVersion
#define SDF_InitKeyFileSystem EVDF_InitKeyFileSystem
#define SDF_RestoreFactorySetting EVDF_RestoreFactorySetting
#ifdef __cplusplus
};
#endif

#endif  /*__SDF_DEV_MANAGE_H__*/

