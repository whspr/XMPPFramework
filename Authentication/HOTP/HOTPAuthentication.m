//
//  HOTPAuthentication.m
//  Pods
//
//  Created by Igor Boldin on 15.11.2021.
//

#import <HOTPAuthentication.h>
#import "XMPP.h"
#import "XMPPLogging.h"
#import "XMPPInternal.h"
#import "NSData+XMPP.h"
#import "NSXMLElement+XMPP.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

#if ! __has_feature(objc_arc)
    #warning This file must be compiled with ARC. Use -fobjc-arc flag (or convert project to ARC).
#endif

// Log levels: off, error, warn, info, verbose
#if DEBUG
    static const int xmppLogLevel = XMPP_LOG_LEVEL_INFO; // | XMPP_LOG_FLAG_TRACE;
#else
    static const int xmppLogLevel = XMPP_LOG_LEVEL_INFO; // during debug, change to warn after
#endif

@implementation HOTPAuth
{
#if __has_feature(objc_arc_weak)
    __weak XMPPStream *xmppStream;
#else
    __unsafe_unretained XMPPStream *xmppStream;
#endif
    
    NSString *secret;
    uint64_t auth_counter;
}

+ (NSString *)mechanismName
{
    return @"HOTP";
}

- (id)initWithStream:(XMPPStream *)stream secret:(NSString *)HOTPSecret counter:(uint64_t)counter
{
    if (self = [super init]) {
        xmppStream = stream;
        secret = HOTPSecret;
        auth_counter = counter;
    }
    return self;
}

- (BOOL)start:(NSError **)errPtr
{
    if (!secret)
    {
        NSString *errMsg = @"Missing HOTP secret.";
        NSDictionary *info = @{NSLocalizedDescriptionKey : errMsg};
        
        NSError *err = [NSError errorWithDomain:XMPPStreamErrorDomain code:XMPPStreamInvalidState userInfo:info];
        
        if (errPtr) *errPtr = err;
        return NO;
    }
    XMPPLogTrace();
    
    // From RFC 4616 - PLAIN SASL Mechanism:
    
    NSString *username = [xmppStream.myJID user];
    
    //HMAC HOTP
    CCHmacAlgorithm alg = kCCHmacAlgSHA1;
    NSUInteger hashLength = CC_SHA1_DIGEST_LENGTH;

    NSMutableData *hash = [NSMutableData dataWithLength:hashLength];
//    NSString *secretD = @"MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=";
    NSData *secret_ = [[NSData alloc] initWithBase64EncodedString: secret options:
                       NSDataBase64DecodingIgnoreUnknownCharacters];
    uint64_t counter_mod = NSSwapHostLongLongToBig(auth_counter);
//    NSData *counterData = [NSData dataWithBytes:&counter_mod
//                                   length:CC_SHA1_BLOCK_LONG];
    
    CCHmac(alg, secret_.bytes, secret_.length, &counter_mod, sizeof(counter_mod), hash.mutableBytes);

    const char *ptr = hash.bytes;
    unsigned char offset = ptr[hashLength-1] & 0x0f;
    
    const void *truncatedHashPtr = &ptr[offset];
    unsigned int truncatedHash = *(unsigned int *)truncatedHashPtr;
    truncatedHash = NSSwapBigIntToHost(truncatedHash);
    truncatedHash &= 0x7fffffff;
    unsigned long pinValue = truncatedHash % 100000000;
    

    NSString *payload = [NSString stringWithFormat:@"\0%@\0%08lu", username, pinValue];
    NSString *base64 = [[payload dataUsingEncoding:NSUTF8StringEncoding] xmpp_base64Encoded];
    
    // <auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="X-TOKEN">Base-64-Info</auth>
    
    NSXMLElement *auth = [NSXMLElement elementWithName:@"auth" xmlns:@"urn:ietf:params:xml:ns:xmpp-sasl"];
    [auth addAttributeWithName:@"mechanism" stringValue:@"HOTP"];
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

- (nonnull instancetype)initWithStream:(nonnull XMPPStream *)stream password:(nonnull NSString *)password {
    if ((self = [super init]))
    {
        xmppStream = stream;
    }
    return self;
}



@end

@implementation XMPPStream(HOTPAuth)

- (BOOL)supportsHOTPAuthentication
{
    return [self supportsAuthenticationMechanism:[HOTPAuth mechanismName]];
}

- (BOOL)authenticateWithHOTPSecret:(NSString *)secret counter:(uint64_t)counter error:(NSError **)errPtr
{
    XMPPLogTrace();
    
    __block BOOL result = YES;
    __block NSError *err = nil;
    
    dispatch_block_t block = ^{ @autoreleasepool {
        
        if ([self supportsHOTPAuthentication])
        {
            HOTPAuth *hotpAuth = [[HOTPAuth alloc] initWithStream:self secret:secret counter:counter];
            result = [self authenticate:hotpAuth error:&err];
        }
        else
        {
            NSString *errMsg = @"The server does not support HOTP authentication.";
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
