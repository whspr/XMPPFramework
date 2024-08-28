//
//  DevicesOCRAAuthentication.h
//  XMPPFramework
//
//  Created by Игорь Болдин on 13.08.2024.
//  Copyright © 2024 XMPPFramework. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "XMPPSASLAuthentication.h"
#import "XMPPStream.h"

NS_ASSUME_NONNULL_BEGIN
@interface DevicesOCRA : NSObject <XMPPSASLAuthentication>

- (instancetype)initWithStream:(XMPPStream *)stream
                        secret:(NSString *)secret
                        validationKey:(NSString *)validationKey
                        counter:(uint64_t)counter
                      deviceId:(NSString *)deviceId;

- (NSString *)generateClientChallenge;

@end



@interface XMPPStream (DevicesOCRA)


@property (nonatomic, readonly) BOOL supportsOCRAAuthentication;

- (BOOL)authenticateWithOCRASecret:(NSString *)secret validationKey:(NSString *)validationKey deviceId:(NSString *)deviceId counter:(uint64_t)counter error:(NSError **)errPtr;

@end
NS_ASSUME_NONNULL_END
