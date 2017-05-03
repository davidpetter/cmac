//
//  CmacCipherTests.m
//  CmacTests
//
//

#import <XCTest/XCTest.h>
#import "NSData+HexString.h"
#import "CmacAesCipher.h"
#import "CmacCipher.h"
#import "TestTuple.h"
#import <objc/runtime.h>

@interface CmacCipherTests : XCTestCase

@end

@implementation CmacCipherTests


- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testCmacSPd800d38bTestSet1Vector1NilInput {
    [self signAndVerifyData: nil key:@"2b7e151628aed2a6abf7158809cf4f3c" keySize:kCmacKeySize128 expected:@"bb1d6929e95937287fa37d129b756746" ];
}

- (void)testCmacSPd800d38bTestSet1Vector1 {
    [self signAndVerifyData: @"" key:@"2b7e151628aed2a6abf7158809cf4f3c" keySize:kCmacKeySize128 expected:@"bb1d6929e95937287fa37d129b756746" ];
}

- (void)testCmacSPd800d38bTestSet1Vector2 {
    [self signAndVerifyData: @"6bc1bee22e409f96e93d7e117393172a" key:@"2b7e151628aed2a6abf7158809cf4f3c" keySize:kCmacKeySize128 expected:@"070a16b46b4d4144f79bdd9dd04a287c" ];
}

- (void)testCmacSPd800d38bTestSet1Vector3 {
    [self signAndVerifyData: @"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411" key:@"2b7e151628aed2a6abf7158809cf4f3c" keySize:kCmacKeySize128 expected:@"dfa66747de9ae63030ca32611497c827" ];
}

- (void) testCmacSPd800d38bTestSet1 {
    NSArray *testInputOutputValues = [NSArray arrayWithObjects:
                                      [[TestTuple alloc]
                                       initWithInput:@""
                                       andExpectedOutput:@"bb1d6929e95937287fa37d129b756746"],
                                      [[TestTuple alloc]
                                       initWithInput:@"6bc1bee22e409f96e93d7e117393172a"
                                       andExpectedOutput:@"070a16b46b4d4144f79bdd9dd04a287c"],
                                      [[TestTuple alloc] initWithInput:@"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411" andExpectedOutput:@"dfa66747de9ae63030ca32611497c827"],
                                      [[TestTuple alloc]
                                       initWithInput:nil
                                       andExpectedOutput:@"bb1d6929e95937287fa37d129b756746"],
                                      nil];
    
    CmacCipher * cmac = [[CmacCipher alloc] initWithCipher: [CmacAesCipher createCipherAesCbcNoPaddingForOperation: kCCEncrypt withKey:[NSData dataWithHexString:@"2b7e151628aed2a6abf7158809cf4f3c"] keySize:kCmacKeySize128 andIv:nil]];
    for (TestTuple *testInputOutput in testInputOutputValues) {
        [cmac update: [NSData dataWithHexString: testInputOutput.input]];
        NSData *fullMac = [cmac doFinal];
        XCTAssertEqualObjects([NSData dataWithHexString: testInputOutput.expectedOutput],fullMac);
    }
}

- (void)testCmacSPd800d38bTestSet1Vector4 {
    [self signAndVerifyData: @"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710" key:@"2b7e151628aed2a6abf7158809cf4f3c" keySize:kCmacKeySize128 expected:@"51f0bebf7e3b9d92fc49741779363cfe" ];
}


- (void)testCmacSPd800d38bTestSet2Vector1 {
    [self signAndVerifyData: @"" key:@"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" keySize:kCmacKeySize192 expected:@"d17ddf46adaacde531cac483de7a9367" ];
}

- (void)testCmacSPd800d38bTestSet2Vector2 {
    [self signAndVerifyData: @"6bc1bee22e409f96e93d7e117393172a" key:@"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" keySize:kCmacKeySize192 expected:@"9e99a7bf31e710900662f65e617c5184" ];
}

- (void)testCmacSPd800d38bTestSet2Vector3{
    [self signAndVerifyData: @"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411" key:@"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" keySize:kCmacKeySize192 expected:@"8a1de5be2eb31aad089a82e6ee908b0e" ];
}


- (void)testCmacSPd800d38bTestSet2Vector4 {
    [self signAndVerifyData: @"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710" key:@"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" keySize:kCmacKeySize192 expected:@"a1d5df0eed790f794d77589659f39a11" ];
}


- (void)testCmacSPd800d38bTestSet3Vector1 {
    [self signAndVerifyData: @"" key:@"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" keySize:kCmacKeySize256 expected:@"028962f61b7bf89efc6b551f4667d983" ];
}

- (void)testCmacSPd800d38bTestSet3Vector2 {
    [self signAndVerifyData: @"6bc1bee22e409f96e93d7e117393172a" key:@"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" keySize:kCmacKeySize256 expected:@"28a7023f452e8f82bd4bf28d8c37c35c" ];
}

- (void)testCmacSPd800d38bTestSet3Vector3 {
    [self signAndVerifyData: @"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411" key:@"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" keySize:kCmacKeySize256 expected:@"aaf3d8f1de5640c232f5b169b9c911e6" ];
}

- (void)testCmacSPd800d38bTestSet3Vector4 {
    [self signAndVerifyData: @"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710" key:@"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" keySize:kCmacKeySize256 expected:@"e1992190549f6ed5696a2c056c315410" ];
}


- (void) signAndVerifyData:(NSString *)data key:(NSString *)key keySize:(CmacAesKeySize)keySize  expected:(NSString*)expected {
    CmacCipher * cmac = [[CmacCipher alloc] initWithCipher: [CmacAesCipher createCipherAesCbcNoPaddingForOperation: kCCEncrypt withKey:[NSData dataWithHexString:key] keySize:keySize andIv:nil]];
    [cmac update: [NSData dataWithHexString: data]];
    NSData *fullMac = [cmac doFinal];
    XCTAssertEqualObjects([NSData dataWithHexString: expected],fullMac);
}

@end


