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
@interface XMPPXTokenAuth : NSObject <XMPPSASLAuthentication>

-(instancetype)initWithStream:(XMPPStream *)stream
                  token:(NSString *)token;

@end



@interface XMPPStream (XMPPXTokenAuth)


@property (nonatomic, readonly) BOOL supportsXTokenAuthentication;

- (BOOL)authenticateWithXabberToken:(NSString *)token error:(NSError **)errPtr;

@end
NS_ASSUME_NONNULL_END
