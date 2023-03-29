#import "Utils.h"


@implementation NSError (Utils)

- (void)copyToSepError:(nonnull sep_error_t*)seperror {
    // Get location
    NSDictionary<NSErrorUserInfoKey,id>* userInfo = [self userInfo];
    NSString* description = [userInfo valueForKey:NSLocalizedDescriptionKey];
    NSString* location = [userInfo valueForKey:NSFilePathErrorKey];
    
    // Write info into C error struct
    seperror->code = [self code];
    [[description dataWithNullUsingEncoding:NSUTF8StringEncoding allowLossyConversion:true] copyToSepBuf:&seperror->description];
    [[location dataWithNullUsingEncoding:NSUTF8StringEncoding allowLossyConversion:true] copyToSepBuf:&seperror->location];
}

@end


@implementation NSData (Utils)

- (instancetype)initWithSepBuf:(nonnull const sep_buf_t*)sepbuf {
    // Validate the length
    if (sepbuf->len > sizeof(sepbuf->bytes)) {
        NSLog(@"Fatal error: Buffer is larger than buffer size (%ld vs %ld bytes)", sepbuf->len, sizeof(sepbuf->bytes));
        exit(1);
    }
    
    // Copy the data
    return [self initWithBytes:sepbuf->bytes length:sepbuf->len];
}

- (void)copyToSepBuf:(nonnull sep_buf_t*)sepbuf {
    // Validate the length
    if ([self length] > sizeof(sepbuf->bytes)) {
        NSLog(@"Fatal error: Data cannot fit into buffer (%ld vs %ld bytes)", [self length], sizeof(sepbuf->bytes));
        exit(1);
    }
    
    // Copy the data
    memcpy(sepbuf->bytes, [self bytes], [self length]);
    sepbuf->len = [self length];
}

@end


@implementation NSString (Utils)

- (nonnull NSData*)dataWithNullUsingEncoding:(NSStringEncoding)encoding allowLossyConversion:(BOOL)allowLossyConversion {
    // Create a mutable byte copy of self
    NSData* bytes = [self dataUsingEncoding:encoding allowLossyConversion:allowLossyConversion];
    NSMutableData* mutableBytes = [[NSMutableData alloc] initWithData:bytes];
    
    // Append a NULL byte
    const uint8_t nullByte[1] = { 0 };
    [mutableBytes appendBytes:nullByte length:1];
    return mutableBytes;
}

@end
