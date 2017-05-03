//
//  CmacAesCipher
//  CMAC
//
//

#import <Foundation/Foundation.h>
#import "CmacAesCipher.h"
#import <CommonCrypto/CommonCryptor.h>

@interface CmacAesCipher ()

@property (nonatomic) CCCryptorRef cryptor;
@property (nonatomic) NSData *iv;
@property (nonatomic) CmacAesKeySize keySize;
    
//Create cipher with encrypt or decrypt operation
-(BOOL) createCipherWithOperation:(CCOperation)operation key:(NSData *)key iv:(NSData *)iv andPadding:(CCPadding)padding;
    
@end

@implementation CmacAesCipher
    
+ (id<CmacBlockCipher>) createCipherAesCbcNoPaddingForOperation:(CmacAesOperationMode) operationMode withKey:(NSData *)key keySize:(CmacAesKeySize) keySize andIv:(NSData *)iv {
    CmacAesCipher * cipher = [[CmacAesCipher alloc] init];
    cipher.keySize = keySize;
    BOOL success = [cipher createCipherWithOperation:operationMode key:key iv:iv andPadding:ccNoPadding];
    if(!success) {
        cipher.cryptor = nil;
        cipher = nil;
    }
    return cipher;
}
    
    
- (NSData *) processData:(NSData *)inputData {
    // Alloc Data Out
    size_t bufferLength = CCCryptorGetOutputLength(self.cryptor, [inputData length], true);
    
    NSMutableData *buffer = [NSMutableData dataWithLength:bufferLength];
    NSMutableData *cipherData = [NSMutableData data];
    
    //alloc number of bytes written to data Out
    size_t outLength;
    
    //Update Cryptor
    CCCryptorStatus updateDecrypt = CCCryptorUpdate(_cryptor,
                                                    inputData.bytes, //const void *dataIn,
                                                    inputData.length,  //size_t dataInLength,
                                                    buffer.mutableBytes, //void *dataOut,
                                                    buffer.length, // size_t dataOutAvailable,
                                                    &outLength); // size_t *dataOutMoved)
    
    if (updateDecrypt == kCCSuccess) {
        //Cut Data Out with nedded length
        [cipherData appendBytes:buffer.bytes length:outLength];
        return cipherData;
    }
    return nil;
}
    
- (NSData *) doFinal: (NSData *)encryptedData {
    // Data to String
    NSMutableData *output = [NSMutableData dataWithData:encryptedData];
    NSUInteger length = CCCryptorGetOutputLength(_cryptor, [output length], true);
    [output setLength:length];
    //alloc number of bytes written to data Out
    size_t outLengthDecrypt;
    
    //Final Cryptor
    CCCryptorStatus final = CCCryptorFinal(_cryptor, //CCCryptorRef cryptorRef,
                                           output.mutableBytes, //void *dataOut,
                                           output.length, // size_t dataOutAvailable,
                                           &outLengthDecrypt); // size_t *dataOutMoved)
    
    if (final == kCCSuccess) {
        self.iv = nil;
    }
    
    return output;
}
    
    
- (void) reset {
    if(_cryptor) {
        CCCryptorReset(_cryptor, [self.iv bytes]);
    }
}
    
- (void) dispose {
    if(_cryptor) {
        CCCryptorRelease(_cryptor);
        self.cryptor = nil;
    }
}
    
//AES block size (currently, only 128-bit blocks are supported).
- (NSUInteger) blockSize {
    return kCCBlockSizeAES128;
}
    
-(BOOL) createCipherWithOperation:(CCOperation)operation key:(NSData *)key iv:(NSData *)iv andPadding:(CCPadding)padding {
    NSMutableData *paddedKey = [[NSMutableData alloc] initWithLength:self.keySize + 1];
    [paddedKey replaceBytesInRange:NSMakeRange(0, key.length) withBytes:[key bytes]];
    
    NSMutableData *paddedIv = [[NSMutableData alloc] initWithLength:self.keySize];
    [paddedIv replaceBytesInRange:NSMakeRange(0, iv.length) withBytes:[iv bytes]];
    self.iv = paddedIv;
    CCCryptorStatus createDecrypt = CCCryptorCreate(operation, // operation
                                                    kCCAlgorithmAES128, // Algorithm
                                                    padding, // padding
                                                    paddedKey.bytes, // key
                                                    self.keySize, // keylength
                                                    paddedIv.bytes, // can be NULL, because null is full of zeros
                                                    &_cryptor); //CCCryptorRef *cryptorRef
    return (createDecrypt == kCCSuccess);
    
}

@end
