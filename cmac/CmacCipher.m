//
//  CmacCipher.m
//  CMAC
//
//

#import <Foundation/Foundation.h>
#import "CmacCipher.h"
#import "NSMutableData+CmacPadding.h"
#import "CmacBlockCipher.h"

@interface CmacCipher ()
@property (nonatomic) NSData *mac;
@property (nonatomic) NSUInteger macSize;
@property (nonatomic) NSData *buffer;
@property (nonatomic) NSUInteger bufferOffset;
@property (nonatomic) unsigned char polynomial;
@property (nonatomic) NSData *zeroes;
@property (nonatomic) NSData *L;
@property (nonatomic) NSData *Lu;
@property (nonatomic) NSData *Lu2;
@property (nonatomic) id<CmacBlockCipher> blockCipher;
@end

@implementation CmacCipher

- (instancetype)initWithCipher:(id<CmacBlockCipher>)blockCipher {
    return [self initWithCipher:blockCipher andSize: ([blockCipher blockSize])];
}

- (instancetype)initWithCipher:(id<CmacBlockCipher>)blockCipher andSize: (NSUInteger) macSizeInBytes {
    if (macSizeInBytes == 0) {
        @throw[NSException exceptionWithName:@"Illegal argument"
                                      reason:@"MAC size must be greater than 0"
                                    userInfo:nil];
    }
    
    if (macSizeInBytes > ([blockCipher blockSize])) {
        
        @throw [NSException exceptionWithName:@"Illegal argument"
                                       reason:[NSString stringWithFormat:@"MAC size must be less or equal to cipher block size, i.e less or equal to %lu", [blockCipher blockSize]]
                                     userInfo:nil];
    }
    
    self = [super init];
    if(self) {
        self.blockCipher = blockCipher;
        self.macSize = macSizeInBytes;
        const NSUInteger blockSize = [blockCipher blockSize];
        self.polynomial = [CmacCipher polynomial: blockSize];
        self.zeroes = [NSMutableData dataWithLength: blockSize];
        self.mac = [NSMutableData dataWithLength: blockSize];
        self.buffer = [NSMutableData dataWithLength: blockSize];
        self.L = [self.blockCipher processData: self.zeroes];
        self.Lu =[CmacCipher doubleLu:self.L andPolynomial: self.polynomial];
        self.Lu2 =[CmacCipher doubleLu:self.Lu andPolynomial: self.polynomial];
        [self reset];
    }
    return self;
}

- (NSUInteger) blockSize {
    return [self.blockCipher blockSize];
}

- (void)update: (NSData *)inData {
    
    const NSUInteger gaplength = self.blockSize - self.bufferOffset; //Gap between buffer and block size
    NSUInteger inLength = [inData length];
    NSUInteger inOffset = 0; //Position of first unprocessed in data
    
    if(inLength > gaplength) { // Update MAC if we have enough data
        
        // Prepare data to update MAC
        NSMutableData *inBuffer = [NSMutableData dataWithData:self.buffer];
        [inBuffer appendData:[inData subdataWithRange:NSMakeRange(0, gaplength)]];
        
        // Update MAC
        self.mac = [self.blockCipher processData: inBuffer];
        
        inLength -= gaplength; // Update with new input length
        inOffset += gaplength; // Update input starting position
        
        while (inLength > self.blockSize) { // Do we have more data that fills an entire block?
            
            inBuffer = [[inData subdataWithRange:NSMakeRange(inOffset, self.blockSize)] mutableCopy]; // Update
            
            self.mac = [self.blockCipher processData: inBuffer]; // Update MAC
            
            
            inLength -= self.blockSize; // Update with new input length
            inOffset += self.blockSize; // Update input starting position
        }
    }
    
    // Add remaining data to buffer
    self.buffer = [[inData subdataWithRange:NSMakeRange(inOffset, inLength)] copy];
    self.bufferOffset += inLength; // Update length of buffer
}

- (NSData *)doFinal {
    
    NSMutableData * remainingBuffer = [self.buffer mutableCopy];
    NSData * macKey;
    if(self.bufferOffset == self.blockSize) { // Buffer is a full block
        macKey = self.Lu;
    } else {
        [remainingBuffer appendIso7816d4Padding: self.blockSize];
        macKey = self.Lu2;
    }
    
    unsigned char* remainingBufferByte = (unsigned char*)[remainingBuffer mutableBytes];
    const unsigned char *macKeyBytes = (const unsigned char*)[macKey bytes];
    
    for(NSUInteger i = 0; i < [self.mac length]; i++) {
        remainingBufferByte[i] ^= macKeyBytes[i];
    }
    
    const NSData *signature = [self.blockCipher processData: remainingBuffer];
    [self reset];
    return [signature subdataWithRange:NSMakeRange(0, self.macSize)]; // return mac (possibly truncted)
}

- (void)reset {
    self.mac = [self.zeroes copy];
    self.buffer = nil;
    self.bufferOffset = 0;
    
    // reset the underlying cipher.
    [self.blockCipher reset];
}
    
- (void)dispose {
    [self reset];
    [self.blockCipher dispose];
}

    
+ (unsigned char)shiftLeftWithInput:(NSData *)input toOutPut:(NSMutableData *)output {
    if(output.length != input.length) {
        @throw [NSException exceptionWithName:@"Illegal argument"
                                       reason:[NSString stringWithFormat:@"Make sure that input length and output length are equal"]
                                     userInfo:nil];
    }
    
    unsigned char bit = 0;
    const unsigned char* inBytes = (const unsigned char*)[input bytes];
    unsigned char *outBytes = (unsigned char*)[output mutableBytes];
    for (NSInteger i = [input length] -1 ; i >= 0; i--) { // Reverse iteration
        unsigned char aByte = (unsigned char)inBytes[i] & 0xFF; // get byte
        outBytes[i] = (unsigned char)((aByte << 1) | bit);
        bit = (aByte >> 7) & 1; //significant bit
    }
    return bit;
}

/*
 * Compute the double LU
 *
 */
+ (NSMutableData *) doubleLu:(NSData *)input andPolynomial: (unsigned char) polynomial{
    NSUInteger inLength = [input length];
    NSMutableData *output = [NSMutableData dataWithLength:inLength];
    unsigned char carry = [self shiftLeftWithInput:input toOutPut:output];
    unsigned char xor = 0xff & polynomial;
    unsigned char *outputBytes = (unsigned char*)[output mutableBytes];
    
    NSUInteger lastIndex = inLength-1;
    outputBytes[lastIndex] ^= (xor >> (unsigned char)((1 - carry) << 3));
    return output;
}

/*
 * Lookup the polynomial related to the cipher block size
 */
+ (unsigned char) polynomial: (NSUInteger)blockSizeInBytes {
    int polynomialXor;
    switch (blockSizeInBytes) {
        case 8:
            polynomialXor = 0x1B;
            break;
        case 16:
            polynomialXor = 0x87;
            break;
        case 20:
            polynomialXor = 0x2D;
            break;
        case 24:
            polynomialXor = 0x87;
            break;
        case 28:
            polynomialXor = 0x309;
            break;
        case 32:
            polynomialXor = 0x425;
            break;
        case 40:
            polynomialXor = 0x1B;
            break;
        case 48:
            polynomialXor = 0x100D;
            break;
        case 56:
            polynomialXor = 0x851;
            break;
        case 64:
            polynomialXor = 0x125;
            break;
        case 96:
            polynomialXor = 0xA0011;
            break;
        case 128:
            polynomialXor = 0x80043;
            break;
        case 256:
            polynomialXor = 0x86001;
            break;
        default:
            @throw [NSException
                    exceptionWithName:@"Illegal block size"
                    reason:[NSString stringWithFormat:@"Unsupported block size for CMAC %lu", blockSizeInBytes]
                    
                    userInfo:nil];
    }
    return polynomialXor;
}

@end
