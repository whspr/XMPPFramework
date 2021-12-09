//
//  XMPPXTokenAuthentication.h
//  Pods
//
//  Created by Igor Boldin on 13/06/2019.
//

#import <Foundation/Foundation.h>
#import "XMPPSASLAuthentication.h"
#import "XMPPStream.h"

NS_ASSUME_NONNULL_BEGIN
@interface HOTPAuth : NSObject <XMPPSASLAuthentication>

-(instancetype)initWithStream:(XMPPStream *)stream
                        secret:(NSString *)HOTPSecret
                        counter:(uint64_t)counter;

@end



@interface XMPPStream (HOTPAuth)


@property (nonatomic, readonly) BOOL supportsHOTPAuthentication;

- (BOOL)authenticateWithHOTPSecret:(NSString *)secret counter:(uint64_t)counter error:(NSError **)errPtr;

@end
NS_ASSUME_NONNULL_END
