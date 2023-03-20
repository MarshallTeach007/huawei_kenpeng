#include <sdf.h>
#include <sdb_sdf.h>
#include <sdf_type.h>
#include <sdf_dev_manage.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <malloc.h>

#define LOG

#define LOG_DATA(d, l)          \
  do                            \
  {                             \
    int i;                      \
    for (i= 0; i < l; i++)      \
    {                           \
      if ((i + 1) % 16)         \
        printf("%02X ", d[i]);  \
      else                      \
        printf("%02X\n", d[i]); \
    }                           \
    if (i % 16)                 \
      printf("\n");             \
  } while (0)

void print_data(const char *string, unsigned char *data, int size)
{
  int i;

  printf("---------------------------------------------\n");
  printf("%s:\n", string);
  for (i= 0; i < size; i++)
  {
    printf("%02x ", data[i]);
    if ((i % 16) == 15)
      printf("\n");
  }
  if (size % 16)
    printf("\n");
  printf("---------------------------------------------\n");
}

u32 GetAccessRight(void *hSessionHandle, unsigned int uiPinIndex,
                   unsigned char *uiPin, unsigned int uiPinLength)
{
  u32 r;
#ifdef LOG
  printf("get access right; index:%d\n", uiPinIndex);
#endif
  r= SDF_GetPrivateKeyAccessRight(hSessionHandle, uiPinIndex, uiPin,
                                  uiPinLength);
  if (r)
  {
    printf("get access right failed:%x\n", r);
    return r;
  }

  return 0;
}

int main()
{
  u32   r;
  void *hDevcieHandle= NULL;
  void *hSessionHandle= NULL;

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
#ifdef LOG
  printf("open session ok\n");
#endif

  u32   uiMasterKeyBits, uiDEKBits, uiAlgID, uiKEKIndex;
  u8    ucKey[16]= {0};
  u8    uciv[16]= {0};
  u8    iv[16]= {0};
  u32   uiKeyLength;
  u32   i= 0;
  u32   j= 0;
  void *hKeyHandle_0;
  void *hKeyHandle_1;

  BYTE *src_data= NULL;
  BYTE *enc_data= NULL;
  BYTE *dec_data= NULL;

  u32 enc_datalen;
  u32 dec_datalen;
  u32 datalen;

  uiMasterKeyBits= MASTER_KEY_LEN;
  uiDEKBits= DEK_LEN;
  uiAlgID= MASTER_KEY_ALG;
  uiKEKIndex= 3;
  unsigned char admin_pin[ADMIN_PIN_LEN]= ADMIN_PIN;
  unsigned int  admin_pin_len= ADMIN_PIN_LEN;

  //InitKeyFileSystem(hSessionHandle, (char*)admin_pin, NULL, 128, (char *)admin_pin, (char *)admin_pin);

  //for(i=1; i<=(SDF_MAX_KEY_INDEX); i++) {
  //    r = GetAccessRight(hSessionHandle, i, admin_pin, admin_pin_len);
  //    if(r)
  //    {
  //        printf("GetAccessRight failed:%x\n", r);
  //    }
  //}
  GetAccessRight(hSessionHandle, 1, admin_pin, admin_pin_len);
  GetAccessRight(hSessionHandle, 2, admin_pin, admin_pin_len);

  //CreateMasterKey(hSessionHandle, 1, uiMasterKeyBits);

  //unsigned char sm1_standard_ecb_enc_key0[]    = {0xAF,0x86,0x18,0x23,0x8C,0x94,0xA1,0x19,0xAE,0x6D,0xE9,0x22,0xDB,0xB9,0x35,0x4D};

  //ImportMasterKey(hSessionHandle, 2, sm1_standard_ecb_enc_key0, uiMasterKeyBits);

  //DeleteMasterKey(hSessionHandle, 2, admin_pin);

  GenerateDEK(hSessionHandle, uiDEKBits, uiAlgID, 1, ucKey, &uiKeyLength,
              &hKeyHandle_0);

  ImportEncryptedDEK(hSessionHandle, uiAlgID, 2, ucKey, uiKeyLength,
                     &hKeyHandle_1);

  DestroyDEK(hSessionHandle, hKeyHandle_1);


  uiAlgID= DEK_ALG;

  datalen= 0x8000;
  if (datalen == 0)
    datalen= 16;
#ifdef LOG
  printf("datalen = %d\n", datalen);
#endif

  src_data= malloc(datalen);
  enc_data= malloc(datalen);
  dec_data= malloc(datalen);

  for (i= 0; i < 16; i++)
  {
    //iv[i] = rand();
    iv[i]= 0x55;
  }

  u32 sector_len= 0x400;
  for (j= 0; j < 32; j++)
  {
    for (i= 0; i < sector_len; i++)
    {
      //src_data[i] = rand();
      src_data[j * 0x400 + i]= 0x11 + j;
    }
  }

  for (i= 0; i < 16; i++)
  {
    uciv[i]= iv[i];
  }
  DEKEncrypt(hSessionHandle, hKeyHandle_0, uiAlgID, uciv, src_data, datalen,
             enc_data, &enc_datalen);
  for (i= 0; i < 16; i++)
  {
    uciv[i]= iv[i];
  }
  DEKDecrypt(hSessionHandle, hKeyHandle_0, uiAlgID, uciv, enc_data,
             enc_datalen, dec_data, &dec_datalen);
#ifdef LOG
  printf("%x, %d, %d\n", *src_data, datalen, enc_datalen);
  printf("%x, %d\n", *dec_data, dec_datalen);
#endif
  if ((dec_datalen != datalen) || (memcmp(dec_data, src_data, datalen)))
  {
    printf("source data != dec data \n");
    return -1;
  }

  return r;
}

int InitKeyFileSystem(void *hSessionHandle, char *AdminPin,
                      unsigned char *pucRootKey, unsigned int uiKeyBits,
                      char *NewAdminPin, char *NewUserPIN)
{
  int r;
#ifdef LOG
  printf("init key file system\n");
#endif
  r= EVDF_InitKeyFileSystem(hSessionHandle, AdminPin, pucRootKey, uiKeyBits,
                            NewAdminPin, NewUserPIN);
  if (r)
  {
    printf("SDF_InitKeyFileSystem failed:%x\n", r);
  }
  return r;
}

int ChangePIN(void *hSessionHandle, unsigned int uiKeyIndex,
              unsigned int uiPINType, char *OldPIN, char *NewPIN,
              unsigned int *puiRetry)
{
  int r;
  r= EVDF_ChangePIN(hSessionHandle, uiKeyIndex, uiPINType, OldPIN, NewPIN,
                    puiRetry);
  if (r)
  {
    printf("SDF_ChangePIN failed:%x\n", r);
  }
#ifdef LOG
  printf("change pin info - MaxRetryCount:%d\n", *puiRetry);
#endif
  return r;
}

int UnlockPIN(void *hSessionHandle, unsigned int uiKeyIndex, char *AdminPIN,
              char *NewUserPIN, unsigned int *puiRetry)
{
  int r;
  r= EVDF_UnlockPIN(hSessionHandle, uiKeyIndex, AdminPIN, NewUserPIN,
                    puiRetry);
  if (r)
  {
    printf("SDF_UnlockPIN test fail:%x\n", r);
  }
  printf("unlock pin info - MaxRetryCount:%d\n", *puiRetry);
  return r;
}

/*Master Key*/
int CreateMasterKey(void *hSessionHandle, unsigned int uiKeyIndex,
                    unsigned int uiKeyBits)
{
  int r;
#ifdef LOG
  printf("create master key index:%x\n", uiKeyIndex);
#endif
  r= EVDF_CreateKEK(hSessionHandle, uiKeyIndex, uiKeyBits);
  if (r)
  {
    printf("create master key[%d] failed:%x\n", uiKeyIndex, r);
  }
  return r;
}

int ImportMasterKey(void *hSessionHandle, unsigned int uiKeyIndex,
                    unsigned char *pucKey, unsigned int uiKeyBits)
{
  int r;
#ifdef LOG
  printf("import master key index:%x\n", uiKeyIndex);
#endif
  r= EVDF_ImportKEK(hSessionHandle, uiKeyIndex, pucKey, uiKeyBits);
  if (r)
  {
    printf("import master key[%d] failed:%x\n", uiKeyIndex, r);
  }
  return r;
}

int DeleteMasterKey(void *hSessionHandle, unsigned int uiKeyIndex,
                    char *AdminPIN)
{
  int r;
#ifdef LOG
  printf("delete master key index:%x\n", uiKeyIndex);
#endif
  r= EVDF_DeleteInternalKEK(hSessionHandle, uiKeyIndex, AdminPIN);
  if (r)
  {
    printf("delete master key[%d] failed:%x\n", uiKeyIndex, r);
  }
  return r;
}

/*DEK*/
int GenerateDEK(void *hSessionHandle, unsigned int uiKeyBits,
                unsigned int uiAlgID, unsigned int uiKEKIndex,
                unsigned char *pucKey, unsigned int *puiKeyLength,
                void **phKeyHandle)
{
  int r;
#ifdef LOG
  printf("generate dek index:%d\n", uiKEKIndex);
#endif
  r= SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, uiAlgID, uiKEKIndex,
                            pucKey, puiKeyLength, phKeyHandle);
  if (r)
  {
    printf("generate dek failed:%x\n", r);
  }
  return r;
}

int ImportEncryptedDEK(void *hSessionHandle, unsigned int uiAlgID,
                       unsigned int uiKEKIndex, unsigned char *pucKey,
                       unsigned int puiKeyLength, void **phKeyHandle)
{
  int r;
#ifdef LOG
  printf("import encrypted dek index:%x\n", uiKEKIndex);
#endif
  r= SDF_ImportKeyWithKEK(hSessionHandle, uiAlgID, uiKEKIndex, pucKey,
                          puiKeyLength, phKeyHandle);
  if (r)
  {
    printf("import encrypted dek failed:%x\n", r);
  }
  return r;
}

int DEKEncrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
               unsigned char *pucIV, unsigned char *pucData,
               unsigned int uiDataLength, unsigned char *pucEncData,
               unsigned int *puiEncDataLength)
{
  int r;
#ifdef LOG
  printf("dek encrypt\n");
#endif
  r= SDF_Encrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData,
                 uiDataLength, pucEncData, puiEncDataLength);
  if (r)
  {
    printf("Encrypt failed:%x\n", r);
  }
  return r;
}

int DEKDecrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID,
               unsigned char *pucIV, unsigned char *pucEncData,
               unsigned int uiEncDataLength, unsigned char *pucData,
               unsigned int *puiDataLength)
{
  int r;
#ifdef LOG
  printf("dek decrypt\n");
#endif
  r= SDF_Decrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucEncData,
                 uiEncDataLength, pucData, puiDataLength);
  if (r)
  {
    printf("Decrypt failed:%x\n", r);
  }
  return r;
}

int DestroyDEK(void *hSessionHandle, void *hKeyHandle)
{
  int r;
#ifdef LOG
  printf("destroy dek\n");
#endif
  r= SDF_DestroyKey(hSessionHandle, hKeyHandle);
  if (r)
  {
    printf("destroy DEK failed:%x\n", r);
  }
  return r;
}
