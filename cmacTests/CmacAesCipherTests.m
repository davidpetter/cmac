//
//  CmacAesCipherTests.m
//  CmacTests
//
//


#import <XCTest/XCTest.h>
#import "NSData+HexString.h"
#import "CmacAesCipher.h"
#import <objc/runtime.h>

@interface CmacAesCipherTests : XCTestCase
    @end

@implementation CmacAesCipherTests
    
- (void)setUp {
    [super setUp];
}
    
- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}
    
//Case #1: Encrypting 16 bytes (1 block) using AES-CBC with 128-bit key
-(void) testAes128CbcCipherRfc3602TestVector16bytes {
    NSData *key = [NSData dataWithHexString: @"06a9214036b8a15b512e03d534120006"];
    NSData *iv = [NSData dataWithHexString: @"3dafba429d9eb430b422da802c9fac41"];
    NSData *plain = [@"Single block msg" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *expected = [NSData dataWithHexString: @"e353779c1079aeb82708942dbe77181a"];
    [self verifyAes128CbcCipherwithKey: key andIv:iv withPlainInData:plain andExpectedCipherData:expected];
}

//Case #2: Encrypting 32 bytes (2 blocks) using AES-CBC with 128-bit key
-(void) testAes128CbcCipherRfc3602TestVector32bytes {
    NSData *key = [NSData dataWithHexString: @"c286696d887c9aa0611bbb3e2025a45a"];
    NSData *iv = [NSData dataWithHexString: @"562e17996d093d28ddb3ba695a2e6f58"];
    NSData *plain = [NSData dataWithHexString: @"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"];
    NSData *expected = [NSData dataWithHexString: @"d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1"];
    [self verifyAes128CbcCipherwithKey: key andIv:iv withPlainInData:plain andExpectedCipherData:expected];
}
    
// Case #3: Encrypting 48 bytes (3 blocks) using AES-CBC with 128-bit key
-(void) testAes128CbcCipherRfc3602TestVector48bytes {
    NSData *key = [NSData dataWithHexString: @"6c3ea0477630ce21a2ce334aa746c2cd"];
    NSData *iv = [NSData dataWithHexString: @"c782dc4c098c66cbd9cd27d825682c81"];
    NSData *plain = [@"This is a 48-byte message (exactly 3 AES blocks)" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *expected = [NSData dataWithHexString: @"d0a02b3836451753d493665d33f0e8862dea54cdb293abc7506939276772f8d5021c19216bad525c8579695d83ba2684"];
    [self verifyAes128CbcCipherwithKey: key andIv:iv withPlainInData:plain andExpectedCipherData:expected];
}
    
// Case #4: Encrypting 64 bytes (4 blocks) using AES-CBC with 128-bit key
-(void) testAes128CbcCipherRfc3602TestVector64bytes {
    NSData *key = [NSData dataWithHexString: @"56e47a38c5598974bc46903dba290349"];
    NSData *iv = [NSData dataWithHexString: @"8ce82eefbea0da3c44699ed7db51b7d9"];
    NSData *plain = [NSData dataWithHexString: @"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"];
    NSData *expected = [NSData dataWithHexString: @"c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55"];
        [self verifyAes128CbcCipherwithKey: key andIv:iv withPlainInData:plain andExpectedCipherData:expected];
    }
    
- (void) verifyAes128CbcCipherwithKey:(NSData *)key andIv:(NSData *)iv withPlainInData:(NSData *)plainInData andExpectedCipherData:(NSData *)expectedCipherData {
    
    //Encrypt
    id<CmacBlockCipher> blockCipher = [CmacAesCipher createCipherAesCbcNoPaddingForOperation: kCmacEncrypt withKey:key keySize:kCmacKeySize128 andIv:iv];
    
    NSData *cipherOutData = [blockCipher processData: plainInData];
    cipherOutData = [blockCipher doFinal: cipherOutData];
    [blockCipher dispose];
    XCTAssertEqualObjects(expectedCipherData, cipherOutData);
        
    //Decrypt
    blockCipher = [CmacAesCipher createCipherAesCbcNoPaddingForOperation: kCmacDecrypt withKey:key keySize:kCmacKeySize128 andIv:iv];
    NSData *plainData = [blockCipher processData: cipherOutData];
    plainData = [blockCipher doFinal: plainData];
    [blockCipher dispose];
    XCTAssertEqualObjects(plainInData, plainData);
    
}
    
@end
