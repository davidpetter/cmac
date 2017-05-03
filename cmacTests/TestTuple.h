//
//  TestTuple.h
//  CmacTests
//
//

@interface TestTuple : NSObject

@property (nonatomic) NSString * input;
@property (nonatomic) NSString * expectedOutput;
- (instancetype) initWithInput:(NSString *)input andExpectedOutput:(NSString *)expectedOutput;
@end

