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

//- (id)initWithStream:(XMPPStream *)stream token:(NSString *)XToken couner:(UInt64)counter

@end



@interface XMPPStream (XMPPXTokenAuth)


@property (nonatomic, readonly) BOOL supportsXTokenAuthentication;

- (BOOL)authenticateWithXabberToken:(NSString *)token counter:(UInt64)counter error:(NSError **)errPtr;

@end
NS_ASSUME_NONNULL_END
