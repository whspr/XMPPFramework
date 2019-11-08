//
//  XMPPXTokenAuthentication.m
//  Alamofire
//
//  Created by Igor Boldin on 13/06/2019.
//

#import <XMPPXTokenAuthentication.h>
#import "XMPP.h"
#import "XMPPLogging.h"
#import "XMPPInternal.h"
#import "NSData+XMPP.h"
#import "NSXMLElement+XMPP.h"

#if ! __has_feature(objc_arc)
    #warning This file must be compiled with ARC. Use -fobjc-arc flag (or convert project to ARC).
#endif

// Log levels: off, error, warn, info, verbose
#if DEBUG
    static const int xmppLogLevel = XMPP_LOG_LEVEL_INFO; // | XMPP_LOG_FLAG_TRACE;
#else
    static const int xmppLogLevel = XMPP_LOG_LEVEL_INFO; // during debug, change to warn after
#endif

@implementation XMPPXTokenAuth
{
#if __has_feature(objc_arc_weak)
    __weak XMPPStream *xmppStream;
#else
    __unsafe_unretained XMPPStream *xmppStream;
#endif
    
    NSString *token;
}

+ (NSString *)mechanismName
{
    return @"X-TOKEN";
}

- (id)initWithStream:(XMPPStream *)stream password:(NSString *)password
{
    if ((self = [super init]))
    {
        xmppStream = stream;
    }
    return self;
}

- (id)initWithStream:(XMPPStream *)stream token:(NSString *)XToken
{
    if (self = [super init]) {
        xmppStream = stream;
        token = XToken;
    }
    return self;
}

- (BOOL)start:(NSError **)errPtr
{
    if (!token)
    {
        NSString *errMsg = @"Missing xabber auth token.";
        NSDictionary *info = @{NSLocalizedDescriptionKey : errMsg};
        
        NSError *err = [NSError errorWithDomain:XMPPStreamErrorDomain code:XMPPStreamInvalidState userInfo:info];
        
        if (errPtr) *errPtr = err;
        return NO;
    }
    XMPPLogTrace();
    
    // From RFC 4616 - PLAIN SASL Mechanism:
    
    NSString *username = [xmppStream.myJID user];
    
    NSString *payload = [NSString stringWithFormat:@"\0%@\0%@", username, token];
    NSString *base64 = [[payload dataUsingEncoding:NSUTF8StringEncoding] xmpp_base64Encoded];
    
    // <auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="X-TOKEN">Base-64-Info</auth>
    
    NSXMLElement *auth = [NSXMLElement elementWithName:@"auth" xmlns:@"urn:ietf:params:xml:ns:xmpp-sasl"];
    [auth addAttributeWithName:@"mechanism" stringValue:@"X-TOKEN"];
    [auth setStringValue:base64];
    
    [xmppStream sendAuthElement:auth];
    
    return YES;
}

- (XMPPHandleAuthResponse)handleAuth:(NSXMLElement *)authResponse
{
    XMPPLogTrace();
    
    // We're expecting a success response.
    // If we get anything else we can safely assume it's the equivalent of a failure response.
    
    if ([[authResponse name] isEqualToString:@"success"])
    {
        return XMPPHandleAuthResponseSuccess;
    }
    else
    {
        return XMPPHandleAuthResponseFailed;
    }
}


@end

@implementation XMPPStream(XMPPXTokenAuth)

- (BOOL)supportsXTokenAuthentication
{
    return [self supportsAuthenticationMechanism:[XMPPXTokenAuth mechanismName]];
}

- (BOOL)authenticateWithXabberToken:(NSString *)token error:(NSError **)errPtr
{
    XMPPLogTrace();
    
    __block BOOL result = YES;
    __block NSError *err = nil;
    
    dispatch_block_t block = ^{ @autoreleasepool {
        
        if ([self supportsXTokenAuthentication])
        {
            XMPPXTokenAuth * xabberAuth = [[XMPPXTokenAuth alloc] initWithStream:self
                                                                           token:token];
            
            result = [self authenticate:xabberAuth error:&err];
        }
        else
        {
            NSString *errMsg = @"The server does not support X-TOKEN authentication.";
            NSDictionary *info = @{NSLocalizedDescriptionKey : errMsg};
            
            err = [NSError errorWithDomain:XMPPStreamErrorDomain code:XMPPStreamUnsupportedAction userInfo:info];
            
            result = NO;
        }
    }};
    
    if (dispatch_get_specific(self.xmppQueueTag))
    block();
    else
    dispatch_sync(self.xmppQueue, block);
    
    if (errPtr)
    *errPtr = err;
    
    return result;
}

@end
