//
//  DevicesOCRAAuthentication.m
//  XMPPFramework
//
//  Created by Игорь Болдин on 13.08.2024.
//  Copyright © 2024 XMPPFramework. All rights reserved.
//
#import <DevicesOCRAAuthentication.h>
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
    static const int xmppLogLevel = XMPP_LOG_LEVEL_VERBOSE; // | XMPP_LOG_FLAG_TRACE;
#else
    static const int xmppLogLevel = XMPP_LOG_LEVEL_INFO; // during debug, change to warn after
#endif


typedef NS_ENUM(NSInteger, XMPPOCRAAuthState) {
    STATE_OCRA_START,
    STATE_OCRA_CHALLENGE,
    STATE_OCRA_RESPONSE,
    STATE_OCRA_END,
    STATE_OCRA_FAILED
};

@implementation DevicesOCRA
{
#if __has_feature(objc_arc_weak)
    __weak XMPPStream *xmppStream;
#else
    __unsafe_unretained XMPPStream *xmppStream;
#endif
    
    NSString *deviceId;
    NSString *secret;
    NSString *validationKey;
    uint64_t authCounter;
    NSString *clientOCRASuit;
    NSString *serverOCRASuit;
    NSString *clientChallengeQuestion;
    XMPPOCRAAuthState ocra_state;
}


+ (NSString *)mechanismName
{
    return @"DEVICES-OCRA";
}

- (id)initWithStream:(XMPPStream *)stream secret:(NSString *)s validationKey:(NSString *)valKey counter:(uint64_t)counter deviceId:(NSString *)devId
{
    if (self = [super init]) {
        xmppStream = stream;
        secret = s;
        validationKey = valKey;
        authCounter = counter;
        deviceId = devId;
        ocra_state = STATE_OCRA_START;
        clientOCRASuit = @"OCRA-1:HOTP-SHA256-8:QA10";
    }
    return self;
}


-(NSString *) generateClientChallenge
{
    int len = 10;
    NSString *letters = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSMutableString *randomString = [NSMutableString stringWithCapacity: len];

    for (int i=0; i<len; i++) {
         [randomString appendFormat: @"%C", [letters characterAtIndex: arc4random_uniform([letters length])]];
    }
    
    return randomString;
}

- (NSString *)clientInitialResponse
{
    clientChallengeQuestion = [self generateClientChallenge];
    NSString *username = [[xmppStream myJID] user];
    
//    NSData *message1Data = [[NSString stringWithFormat:@"n,,\0%@\0%@\0%@\0%@\0%@", username, deviceId, clientOCRASuit, clientChallengeQuestion, validationKey] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *message1Data = [[NSString stringWithFormat:@"n,,\0%@\0%@\0%@\0%@\0%@", username, deviceId, clientOCRASuit, clientChallengeQuestion, validationKey] dataUsingEncoding:NSUTF8StringEncoding];
    
    return [message1Data xmpp_base64Encoded];
}

- (CCHmacAlgorithm) cryptoFunction:(NSString *)OCRASuit
{
    NSString *cryptoFunction = [[OCRASuit componentsSeparatedByString:@":"] objectAtIndex:1];
    NSString *algo = [[cryptoFunction componentsSeparatedByString:@"-"] objectAtIndex:1];
    if ([algo  isEqual: @"SHA1"])
    {
        return kCCHmacAlgSHA1;
    }
    if ([algo  isEqual: @"SHA256"])
    {
        return kCCHmacAlgSHA256;
    }
    if ([algo  isEqual: @"SHA512"])
    {
        return kCCHmacAlgSHA512;
    }
    return kCCHmacAlgSHA1;
}

- (NSUInteger)hashLength:(NSString *)OCRASuit
{
    NSString *cryptoFunction = [[OCRASuit componentsSeparatedByString:@":"] objectAtIndex:1];
    
    CCHmacAlgorithm alg = [self cryptoFunction:OCRASuit];
    if (alg == kCCHmacAlgSHA1)
    {
        return CC_SHA1_DIGEST_LENGTH;
    }
    if (alg == kCCHmacAlgSHA256)
    {
        return CC_SHA256_DIGEST_LENGTH;
    }
    if (alg == kCCHmacAlgSHA512)
    {
        return CC_SHA512_DIGEST_LENGTH;
    }
    NSUInteger hashLength = CC_SHA1_DIGEST_LENGTH;
    return hashLength;
}

- (NSInteger)hotpLength:(NSString *)OCRASuit
{
    NSString *cryptoFunction = [[OCRASuit componentsSeparatedByString:@":"] objectAtIndex:1];
    NSString *hotpLength = [[cryptoFunction componentsSeparatedByString:@"-"] objectAtIndex:2];
    return [hotpLength integerValue];
}

- (BOOL)start:(NSError **)errPtr
{
    if (!secret || !validationKey || !authCounter || !deviceId)
    {
        NSString *errMsg = @"Missing OCRA DataInput.";
        NSDictionary *info = @{NSLocalizedDescriptionKey : errMsg};
        
        NSError *err = [NSError errorWithDomain:XMPPStreamErrorDomain code:XMPPStreamInvalidState userInfo:info];
        
        if (errPtr) *errPtr = err;
        return NO;
    }
    XMPPLogTrace();
    
    NSString *base64 = [self clientInitialResponse];
    
    NSXMLElement *auth = [NSXMLElement elementWithName:@"auth" xmlns:@"urn:ietf:params:xml:ns:xmpp-sasl"];
    [auth addAttributeWithName:@"mechanism" stringValue:@"DEVICES-OCRA"];
    [auth setStringValue:base64];
    
    ocra_state = STATE_OCRA_CHALLENGE;
    
    [xmppStream sendAuthElement:auth];
    
    return YES;
}

- (XMPPHandleAuthResponse)handleAuthChallenge:(NSXMLElement *)authResponse
{
    XMPPLogTrace();
    
    if (![[authResponse name] isEqualToString:@"challenge"])
    {
        return XMPPHandleAuthResponseFailed;
    }
    
    NSData *base64Data = [[authResponse stringValue] dataUsingEncoding:NSASCIIStringEncoding];
    NSData *decodedData = [base64Data xmpp_base64Decoded];
    
    NSArray<NSString *> *serverChallenge = [[[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding] componentsSeparatedByString:@"\0"];
    if ([serverChallenge count] != 3)
    {
        return XMPPHandleAuthResponseFailed;
    }
    NSString *srvResponse = [serverChallenge objectAtIndex:0];
    NSString *srvOCRASuit = [serverChallenge objectAtIndex:1];
    NSString *srvChallengeQuestion = [serverChallenge objectAtIndex:2];
    
    NSString *srvResponseDecoded = [[NSString alloc] initWithData:[[srvResponse dataUsingEncoding:NSASCIIStringEncoding] xmpp_base64Decoded] encoding:NSUTF8StringEncoding];
    
    NSLog(@"challenge srvResponse: %@", srvResponse);
    NSLog(@"challenge srvResponseDecoded: %@", srvResponseDecoded);
    NSLog(@"challenge srvOCRASuit: %@", srvOCRASuit);
    NSLog(@"challenge srvChallengeQuestion: %@", srvChallengeQuestion );
    
    CCHmacAlgorithm clAlg = [self cryptoFunction:clientOCRASuit];
    NSUInteger clHashLength = [self hashLength:clientOCRASuit];

    NSMutableData *clHash = [NSMutableData dataWithLength:clHashLength];
    NSData *secret_ = [[NSData alloc] initWithBase64EncodedString: secret options:
                       NSDataBase64DecodingIgnoreUnknownCharacters];
    NSMutableData *clientChallengeQuestionData = [NSMutableData alloc];
    [clientChallengeQuestionData appendData:[[NSData alloc] initWithData:[clientChallengeQuestion dataUsingEncoding:kCFStringEncodingUTF8]]];
    NSUInteger clientChallengeQuestionDataPad = 128 - [clientChallengeQuestionData length];
    if (clientChallengeQuestionDataPad > 0)
    {
        [clientChallengeQuestionData appendData:[NSMutableData dataWithLength:clientChallengeQuestionDataPad]];
    }
    NSMutableData *clDataInput = [NSMutableData alloc];
    [clDataInput appendData:[[NSData alloc] initWithData:[clientOCRASuit dataUsingEncoding:kCFStringEncodingUTF8]]];
    [clDataInput appendData:[[NSData alloc] initWithData:[@"\0" dataUsingEncoding:kCFStringEncodingUTF8]]];
    [clDataInput appendData:clientChallengeQuestionData];
    
    CCHmac(clAlg, secret_.bytes, secret_.length, clDataInput.bytes, clDataInput.length, clHash.mutableBytes);

    NSInteger clHotpLength = [self hotpLength:clientOCRASuit];
    BOOL result = false;
    if (clHotpLength == 0) {
        NSString *hashString = [clHash xmpp_base64Encoded];
        result = [hashString isEqual:srvResponse];
    } else {
        const char *ptr = clHash.bytes;
        unsigned char offset = ptr[clHashLength-1] & 0x0f;
        
        const void *truncatedHashPtr = &ptr[offset];
        unsigned int truncatedHash = *(unsigned int *)truncatedHashPtr;
        truncatedHash = NSSwapBigIntToHost(truncatedHash);
        truncatedHash &= 0x7fffffff;
        unsigned long pinValue = truncatedHash % ((unsigned int)pow(10, clHotpLength));
        NSString *payload;
        if (clHotpLength == 4)
        {
            payload = [NSString stringWithFormat:@"%04lu", pinValue];
        }
        else if (clHotpLength == 6)
        {
            payload = [NSString stringWithFormat:@"%06lu", pinValue];
        }
        else if (clHotpLength == 8)
        {
            payload = [NSString stringWithFormat:@"%08lu", pinValue];
        } else
        {
            payload = [NSString stringWithFormat:@"%u", pinValue];
        }
        result = [payload isEqual:srvResponseDecoded];
    }
    if (result)
    {
        CCHmacAlgorithm alg = [self cryptoFunction:srvOCRASuit];
        NSUInteger hashLength = [self hashLength:srvOCRASuit];

        NSMutableData *hash = [NSMutableData dataWithLength:hashLength];
        NSData *secret_ = [[NSData alloc] initWithBase64EncodedString: secret options:
                           NSDataBase64DecodingIgnoreUnknownCharacters];

        NSMutableData *srvChallengeQuestionData = [NSMutableData alloc];
        [srvChallengeQuestionData appendData:[[NSData alloc] initWithData:[srvChallengeQuestion dataUsingEncoding:kCFStringEncodingUTF8]]];
        NSUInteger srvChallengeQuestionDataPad = 128 - [srvChallengeQuestionData length];
        if (srvChallengeQuestionDataPad > 0)
        {
            [srvChallengeQuestionData appendData:[NSMutableData dataWithLength:srvChallengeQuestionDataPad]];
        }
        NSMutableData *dataInput = [NSMutableData alloc];
        [dataInput appendData:[[NSData alloc] initWithData:[srvOCRASuit dataUsingEncoding:kCFStringEncodingUTF8]]];
        [dataInput appendData:[[NSData alloc] initWithData:[@"\0" dataUsingEncoding:kCFStringEncodingUTF8]]];
        uint64_t counter_mod = NSSwapHostLongLongToBig(authCounter);
        NSMutableData *buffer = [NSMutableData dataWithBytes:&counter_mod length:sizeof(counter_mod)];
        [dataInput appendData:buffer];
        [dataInput appendData:srvChallengeQuestionData];
        
        
        CCHmac(alg, secret_.bytes, secret_.length, dataInput.bytes, dataInput.length, hash.mutableBytes);

        NSInteger hotpLength = [self hotpLength:srvOCRASuit];
        NSXMLElement *response = [NSXMLElement elementWithName:@"response" xmlns:@"urn:ietf:params:xml:ns:xmpp-sasl"];
        if (hotpLength == 0) {
            NSString *base64 = [hash xmpp_base64Encoded];
            [response setStringValue:[[base64 dataUsingEncoding:NSUTF8StringEncoding] xmpp_base64Encoded]];
        } else {
            const char *ptr = hash.bytes;
            unsigned char offset = ptr[hashLength-1] & 0x0f;
            
            const void *truncatedHashPtr = &ptr[offset];
            unsigned int truncatedHash = *(unsigned int *)truncatedHashPtr;
            truncatedHash = NSSwapBigIntToHost(truncatedHash);
            truncatedHash &= 0x7fffffff;
            unsigned long pinValue = truncatedHash % ((unsigned int)pow(10, hashLength));
            NSString *payload;
            if (hashLength == 4)
            {
                payload = [NSString stringWithFormat:@"%04lu", pinValue];
            }
            else if (hashLength == 6)
            {
                payload = [NSString stringWithFormat:@"%06lu", pinValue];
            }
            else if (hashLength == 8)
            {
                payload = [NSString stringWithFormat:@"%08lu", pinValue];
            } else
            {
                payload = [NSString stringWithFormat:@"%u", pinValue];
            }
            NSString *base64 = [[payload dataUsingEncoding:NSUTF8StringEncoding] xmpp_base64Encoded];
            [response setStringValue:base64];
        }
        [xmppStream sendAuthElement:response];
        ocra_state = STATE_OCRA_END;
        return XMPPHandleAuthResponseContinue;
    }
    else
    {
        return XMPPHandleAuthResponseFailed;
    }
}

- (XMPPHandleAuthResponse)handleAuthEnd:(NSXMLElement *)authResponse
{
    XMPPLogTrace();
        
    if ([[authResponse name] isEqual:@"success"]) {
        return XMPPHandleAuthResponseSuccess;
    }
    else {
        return XMPPHandleAuthResponseFailed;
    }
}

- (XMPPHandleAuthResponse)handleAuth:(NSXMLElement *)authResponse
{
    XMPPLogTrace();
    if (ocra_state == STATE_OCRA_CHALLENGE)
    {
        return [self handleAuthChallenge:authResponse];
    }
    else if (ocra_state == STATE_OCRA_END)
    {
        return [self handleAuthEnd:authResponse];
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

@implementation XMPPStream(DevicesOCRA)

- (BOOL)supportsOCRAAuthentication
{
    return [self supportsAuthenticationMechanism:[DevicesOCRA mechanismName]];
}

- (BOOL)authenticateWithOCRASecret:(NSString *)secret validationKey:(NSString *)validationKey deviceId:(NSString *)deviceId counter:(uint64_t)counter error:(NSError *__autoreleasing  _Nullable *)errPtr
{
    XMPPLogTrace();
    
    __block BOOL result = YES;
    __block NSError *err = nil;
    
    dispatch_block_t block = ^{ @autoreleasepool {
        
        if ([self supportsOCRAAuthentication])
        {
            DevicesOCRA *OCRAAuth = [[DevicesOCRA alloc] initWithStream:self secret:secret validationKey:validationKey counter:counter deviceId:deviceId];
            result = [self authenticate:OCRAAuth error:&err];
        }
        else
        {
            NSString *errMsg = @"The server does not support OCRA authentication.";
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
