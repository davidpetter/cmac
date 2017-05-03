//
//  TestTuple.m
//  CmacTests
//
//

#import <Foundation/Foundation.h>
#import "TestTuple.h"

@implementation TestTuple

- (instancetype) initWithInput:(NSString *)input andExpectedOutput:(NSString *)expectedOutput {
    self = [super init];
    if(self) {
        self.input = input;
        self.expectedOutput = expectedOutput;
    }
    return self;
}

@end
