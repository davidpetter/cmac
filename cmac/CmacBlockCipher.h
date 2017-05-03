//
//  CmacAesCipher.h
//  CMAC
//
//

/**
 * Block cipher interface
 */
@protocol CmacBlockCipher <NSObject>

/**
 * Process (encrypt, decrypt) some data and get the result back
 * @param inputData  data to process
 * @return processed data
 */
- (NSData *) processData: (NSData *) inputData;

/**
 * Finish an encrypt or decrypt operation, and obtain the final data output. 
 *
 * @param inputData processed data to finalize
 * @return final processed data
 */
- (NSData *) doFinal: (NSData *) inputData;

/**
 * Cipher block size
 */
- (NSUInteger) blockSize;
    
/**
 * Restire the cipher with the initial parameters
 */
- (void) reset;

/**
 * Disposes the cipher.
 * <p>
 * Note make sure to call this when finished with the encryption
 */
- (void) dispose;


@end
