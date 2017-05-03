//
//  CmacAesCipher.h
//  CMAC
//
//
#import "CmacBlockCipher.h"
#import <CommonCrypto/CommonCryptor.h>

/**
 * AES Cipher implementation
 */
@interface CmacAesCipher : NSObject <CmacBlockCipher>

// Supported AES Key lengths
typedef enum {
    kCmacKeySize128 = kCCKeySizeAES128,
    kCmacKeySize192 = kCCKeySizeAES192,
    kCmacKeySize256 = kCCKeySizeAES256
} CmacAesKeySize;

// Operation mode
typedef enum {
    kCmacEncrypt = kCCEncrypt,
    kCmacDecrypt = kCCDecrypt,
} CmacAesOperationMode;


/**
 * Create AES CBC no padding cipher
 * @param operationMode to basic cipher operations mode (encrypt or decrypt)
 * @param key the AES cipher key to use
 * @param keySize the size of the crypto key
 * @param iv decryption initialization vector, default value is nil
 * @return the cipher or nil if an error occured
 */
+(id<CmacBlockCipher>) createCipherAesCbcNoPaddingForOperation:(CmacAesOperationMode) operationMode withKey:(NSData *)key keySize:(CmacAesKeySize) keySize andIv: (NSData *) iv;

@end
