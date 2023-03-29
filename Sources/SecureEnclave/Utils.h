#include "include/SecureEnclave.h"

@import Foundation;


@interface NSData (Utils)

/**
 * @brief Creates a new `NSData` instance from the given `sepbuf`
 * 
 * @param sepbuf The `sep_buf_t` containing the data to copy
 * @return The newly created `NSData` instance
 */
- (nonnull instancetype)initWithSepBuf:(nonnull const sep_buf_t*)sepbuf;

/**
 * @brief Copies `self` into the given `sepbuf`
 * 
 * @param sepbuf The `sep_buf_t` to copy `self` into
 */
- (void)copyToSepBuf:(nonnull sep_buf_t*)sepbuf;

@end


@interface NSError (Utils)

/**
 * @brief Copies `self` into the given `seperror`
 * 
 * @param seperror The `sep_error_t` to copy `self` into
 */
- (void)copyToSepError:(nonnull sep_error_t*)seperror;

@end


@interface NSString (Utils)

/**
 * @brief Creates a null-terminated `NSData` object from `self` using the given encoding
 * 
 * @param encoding The encoding to use
 * @param allowLossyConversion Whether to allow lossy conversion or to fail if `self` cannot be represented using the given
 *                             encoding
 * @return The newly created `NSData` instance
 */
- (nonnull NSData*)dataWithNullUsingEncoding:(NSStringEncoding)encoding allowLossyConversion:(BOOL)allowLossyConversion;

@end
