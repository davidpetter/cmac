//
//  NSData+CmacPadding
//  CMAC
//
//

#import <Foundation/Foundation.h>

@interface NSMutableData (CmacPadding)

/**
 * Append padding to data according to ISO 7816-4
 * @param blockSize the size of each padding block
 */
- (void) appendIso7816d4Padding: (NSUInteger) blockSize;

@end
