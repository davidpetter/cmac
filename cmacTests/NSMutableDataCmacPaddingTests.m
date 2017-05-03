//
//  NSMutableDataCmacPaddingTests.m
//  CmacTests
//
//

#import <XCTest/XCTest.h>
#import "NSMutableData+CmacPadding.h"
#import "NSData+HexString.h"
#import <objc/runtime.h>

@interface NSMutableDataCmacPaddingTests : XCTestCase

@end

@implementation NSMutableDataCmacPaddingTests

- (void)testEmpty {
    NSMutableData *testData = [NSMutableData new];
    [testData appendIso7816d4Padding : 2];
    XCTAssertEqualObjects([NSData dataWithHexString: @"8000"],testData);
}

- (void)testTwo {
    NSMutableData *testData = [[NSData dataWithHexString:@"1337"] mutableCopy];
    [testData appendIso7816d4Padding : 8];
    XCTAssertEqualObjects([NSData dataWithHexString: @"1337800000000000"],testData);
}


@end
