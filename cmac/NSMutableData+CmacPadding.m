//
//  NSData+CmacISO7816d4Padding.m
//  CMAC
//
//

#import "NSMutableData+CmacPadding.h"

@implementation NSMutableData (CmacPadding)
    
    static unsigned char const kIso7816d4PaddingFlagConst = 0x80;
    
- (void) appendIso7816d4Padding:(NSUInteger)blockSize {
    @synchronized(self) {
        if(self.length == 0 || self.length % blockSize != 0) {
            [self appendBytes: (&kIso7816d4PaddingFlagConst) length:sizeof(kIso7816d4PaddingFlagConst)];
            NSUInteger paddingSize = (blockSize - [self length]) % blockSize;
            [self increaseLengthBy:paddingSize];
        }
    }
}
    
@end
