//
//  CmacCipher.h
//  CMAC
//
//
#import "CmacBlockCipher.h"

/**
 * CMAC or OCMAC1 - as specified at www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
 */
@interface CmacCipher : NSObject

/**
 * Instantiate the CMAC with a cipher instance.
 * @param blockCipher a block cipher instance used to calculate CMAC
 */
- (instancetype)initWithCipher: (id<CmacBlockCipher>)blockCipher;

/**
 * Instantiate the CMAC with a cipher instance and MAC size
 * @param blockCipher a block cipher instance used to calculate CMAC
 * @param macSizeInBytes the size of the MAC in bytes, use size less or equal to the block size of the 
 * underlying cipher.
 */
- (instancetype)initWithCipher:(id<CmacBlockCipher>) blockCipher andSize: (NSUInteger) macSizeInBytes;

/**
 * The block size of the underlying cipher
 */
- (NSUInteger) blockSize;

/**
 * Update the MAC with input data
 * @param inData the data containing the input.
 */
- (void)update: (NSData *)inData;

/**
 * Compute the final stage of the MAC and returning the output
 * <p>
 * Note that doFinal restores the initial mode of the mac (@see reset)
 * @return the calculated MAC.
 */
- (NSData *)doFinal;

/**
 * Reset the CMAC. Restores the initial mode of the CMAC.
 * <p>
 * Note that this will also reset the underlying block cipher
 */
- (void)reset;
    
/**
 * Dispose of the CMAC and the underlying block cipher.
 * <p>
 * Make sure to call this when done with the MAC
 */
- (void)dispose;

@end
