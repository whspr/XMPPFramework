//
//  XMPPSRVResolver.m
//
//  Originally created by Eric Chamberlain on 6/15/10.
//  Based on SRVResolver by Apple, Inc.
//

#import "XMPPSRVResolver.h"
#import "XMPPLogging.h"

//#warning Fix "dns.h" issue without resorting to this ugly hack.
// This is a hack to prevent OnionKit's clobbering of the actual system's <dns.h>
//#include "/usr/include/dns.h"

#include <dns_util.h>
#include <stdlib.h>
#import <dns_sd.h>

#if ! __has_feature(objc_arc)
#warning This file must be compiled with ARC. Use -fobjc-arc flag (or convert project to ARC).
#endif

NSString *const XMPPSRVResolverErrorDomain = @"XMPPSRVResolverErrorDomain";
NSString *const XMPPSRVResolverSourceKey = @"XMPPSRVResolverSource";
NSString *const XMPPSRVResolverErrorCategoryKey = @"XMPPSRVResolverErrorCategory";
NSString *const XMPPSRVResolverSourceSystemDNS = @"system-dns";
NSString *const XMPPSRVResolverSourceDoH = @"doh";
NSString *const XMPPSRVResolverSourceCache = @"cache";
NSString *const XMPPSRVResolverSourceFallback = @"fallback";

static const NSTimeInterval XMPPSRVResolverDohProviderTimeout = 2.0;
static const NSTimeInterval XMPPSRVResolverDefaultCacheTTL = 30.0;
static const NSTimeInterval XMPPSRVResolverMaxCacheTTL = 3600.0;
static NSString *const XMPPSRVResolverDohMediaType = @"application/dns-message";

static const uint16_t XMPPDNSClassIN = 1;
static const uint16_t XMPPDNSTypeSRV = 33;
static const uint16_t XMPPDNSFlagResponse = 0x8000;
static const uint16_t XMPPDNSFlagRecursionDesired = 0x0100;
static const uint16_t XMPPDNSFlagTruncated = 0x0200;
static const uint16_t XMPPDNSRCodeMask = 0x000F;
static const NSUInteger XMPPDNSHeaderLength = 12;

@class XMPPSRVResolverCacheEntry;

// Log levels: off, error, warn, info, verbose
#if DEBUG
  static const int xmppLogLevel = XMPP_LOG_LEVEL_WARN; // | XMPP_LOG_FLAG_TRACE;
#else
  static const int xmppLogLevel = XMPP_LOG_LEVEL_WARN;
#endif

static void XMPPDNSAppendUInt16(NSMutableData *data, uint16_t value)
{
	uint16_t networkValue = htons(value);
	[data appendBytes:&networkValue length:sizeof(networkValue)];
}

static BOOL XMPPDNSReadUInt16(const uint8_t *bytes, NSUInteger length, NSUInteger offset, uint16_t *value)
{
	if (offset > length || length - offset < sizeof(uint16_t))
	{
		return NO;
	}

	*value = ((uint16_t)bytes[offset] << 8) | bytes[offset + 1];
	return YES;
}

static BOOL XMPPDNSReadUInt32(const uint8_t *bytes, NSUInteger length, NSUInteger offset, uint32_t *value)
{
	if (offset > length || length - offset < sizeof(uint32_t))
	{
		return NO;
	}

	*value = ((uint32_t)bytes[offset] << 24) |
	         ((uint32_t)bytes[offset + 1] << 16) |
	         ((uint32_t)bytes[offset + 2] << 8) |
	          (uint32_t)bytes[offset + 3];
	return YES;
}

static BOOL XMPPDNSReadName(const uint8_t *bytes, NSUInteger length, NSUInteger *offsetPtr, NSString **namePtr)
{
	if (bytes == NULL || offsetPtr == NULL || namePtr == NULL || *offsetPtr >= length)
	{
		return NO;
	}

	NSMutableArray<NSString *> *labels = [NSMutableArray array];
	NSUInteger offset = *offsetPtr;
	NSUInteger nextOffset = NSNotFound;
	NSUInteger jumps = 0;
	NSUInteger wireLength = 1;
	BOOL jumped = NO;

	while (YES)
	{
		if (offset >= length)
		{
			return NO;
		}

		uint8_t labelLength = bytes[offset];

		if ((labelLength & 0xC0) == 0xC0)
		{
			if (length - offset < 2)
			{
				return NO;
			}

			NSUInteger pointer = ((NSUInteger)(labelLength & 0x3F) << 8) | bytes[offset + 1];
			if (pointer >= length)
			{
				return NO;
			}

			if (!jumped)
			{
				nextOffset = offset + 2;
			}

			if (++jumps > 128)
			{
				return NO;
			}

			offset = pointer;
			jumped = YES;
			continue;
		}
		else if ((labelLength & 0xC0) != 0)
		{
			return NO;
		}

		offset += 1;

		if (labelLength == 0)
		{
			if (!jumped)
			{
				nextOffset = offset;
			}

			break;
		}

		if (labelLength > 63 || offset > length || length - offset < labelLength)
		{
			return NO;
		}

		wireLength += (NSUInteger)labelLength + 1;
		if (wireLength > 255)
		{
			return NO;
		}

		NSString *label = [[NSString alloc] initWithBytes:&bytes[offset]
		                                           length:labelLength
		                                         encoding:NSASCIIStringEncoding];
		if (label == nil)
		{
			return NO;
		}

		[labels addObject:label];
		offset += labelLength;
	}

	if (nextOffset == NSNotFound)
	{
		return NO;
	}

	*offsetPtr = nextOffset;
	*namePtr = [labels componentsJoinedByString:@"."];
	return YES;
}

static BOOL XMPPDNSSkipResourceRecords(const uint8_t *bytes, NSUInteger length, NSUInteger *offsetPtr, uint16_t count)
{
	if (bytes == NULL || offsetPtr == NULL)
	{
		return NO;
	}

	for (uint16_t i = 0; i < count; i++)
	{
		NSString *recordName = nil;
		if (!XMPPDNSReadName(bytes, length, offsetPtr, &recordName) ||
		    *offsetPtr > length ||
		    length - *offsetPtr < 10)
		{
			return NO;
		}
		(void)recordName;

		uint16_t rdLength = 0;
		if (!XMPPDNSReadUInt16(bytes, length, *offsetPtr + 8, &rdLength))
		{
			return NO;
		}

		*offsetPtr += 10;
		if (*offsetPtr > length || length - *offsetPtr < rdLength)
		{
			return NO;
		}

		*offsetPtr += rdLength;
	}

	return YES;
}

static dispatch_queue_t XMPPSRVResolverCacheQueue(void)
{
	static dispatch_queue_t queue;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		queue = dispatch_queue_create("XMPPSRVResolver.cache", DISPATCH_QUEUE_SERIAL);
	});
	return queue;
}

static NSMutableDictionary<NSString *, XMPPSRVResolverCacheEntry *> *XMPPSRVResolverCacheStorage(void)
{
	static NSMutableDictionary<NSString *, XMPPSRVResolverCacheEntry *> *cache;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		cache = [NSMutableDictionary dictionary];
	});
	return cache;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

@interface XMPPSRVRecord ()

@property(nonatomic, assign) NSUInteger srvResultsIndex;
@property(nonatomic, assign) NSUInteger sum;

- (NSComparisonResult)compareByPriority:(XMPPSRVRecord *)aRecord;

@end

@interface XMPPSRVResolver (Testing)

+ (nullable NSData *)xmpp_dnsMessageForSRVName:(NSString *)srvName queryID:(UInt16)queryID;
+ (nullable NSArray<XMPPSRVRecord *> *)xmpp_SRVRecordsFromDNSMessage:(NSData *)data queryID:(UInt16)queryID;
+ (NSUInteger)xmpp_cacheEntryCountForTesting;

- (void)setDohProviderURLs:(NSArray<NSURL *> *)providerURLs;
- (void)setDohURLSessionProtocolClasses:(nullable NSArray *)protocolClasses;
- (BOOL)markSystemResolverStarted;
- (void)startSystemResolver;
- (void)xmpp_resolveRecordsForTesting:(NSArray<XMPPSRVRecord *> *)records source:(NSString *)source;
- (void)xmpp_failSystemResolverForTestingWithError:(NSError *)error;

@end

@interface XMPPSRVResolverCacheEntry : NSObject

@property (nonatomic, copy, nullable) NSArray<XMPPSRVRecord *> *records;
@property (nonatomic, strong, nullable) NSError *error;
@property (nonatomic, copy) NSString *source;
@property (nonatomic, strong) NSDate *expiresAt;

@end

@implementation XMPPSRVResolverCacheEntry
@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

@interface XMPPSRVResolver ()
{
#if __has_feature(objc_arc_weak)
    __weak id<XMPPSRVResolverDelegate> delegate;
#else
    __unsafe_unretained id<XMPPSRVResolverDelegate> delegate;
#endif

    dispatch_queue_t delegateQueue;

    dispatch_queue_t resolverQueue;
    void *resolverQueueTag;

	    __strong NSString *srvName;
	    NSTimeInterval timeout;
	    __strong NSString *resultSource;
	    __strong NSString *cacheKey;
	    __strong NSError *lastResolverError;

	    BOOL resolveInProgress;

    NSMutableArray *results;
    DNSServiceRef sdRef;

    int sdFd;
    dispatch_source_t sdReadSource;
    dispatch_source_t timeoutTimer;

    NSArray<NSURL *> *dohProviderURLs;
    NSArray *dohURLSessionProtocolClasses;
    NSUInteger dohProviderIndex;
    NSUInteger dohAttemptID;
    UInt16 dohQueryID;
    NSURLSession *dohSession;
    NSURLSessionDataTask *dohTask;
    dispatch_source_t dohProviderTimer;
    BOOL systemResolverStarted;
}

- (void)succeed;
- (void)succeedWithSource:(NSString *)source cacheable:(BOOL)cacheable;
- (void)failWithError:(NSError *)error;
- (void)failWithError:(NSError *)error source:(NSString *)source cacheable:(BOOL)cacheable;
- (void)failWithDNSError:(DNSServiceErrorType)sdErr;
- (void)continueAfterSystemResolverFailure:(NSError *)error;
- (void)cleanupSystemResolver;
- (void)startNextDohProvider;

@end

@implementation XMPPSRVResolver

- (instancetype)initWithDelegate:(id<XMPPSRVResolverDelegate>)aDelegate
                   delegateQueue:(dispatch_queue_t)dq
                   resolverQueue:(nullable dispatch_queue_t)rq {
	NSParameterAssert(aDelegate != nil);
	NSParameterAssert(dq != NULL);

	if ((self = [super init]))
	{
		XMPPLogTrace();

		delegate = aDelegate;
		delegateQueue = dq;

		#if !OS_OBJECT_USE_OBJC
		dispatch_retain(delegateQueue);
		#endif

		if (rq)
		{
			resolverQueue = rq;
			#if !OS_OBJECT_USE_OBJC
			dispatch_retain(resolverQueue);
			#endif
		}
		else
		{
			resolverQueue = dispatch_queue_create("XMPPSRVResolver", NULL);
		}

		resolverQueueTag = &resolverQueueTag;
		dispatch_queue_set_specific(resolverQueue, resolverQueueTag, resolverQueueTag, NULL);

		results = [[NSMutableArray alloc] initWithCapacity:2];

		// Public DoH providers can bypass or be blocked by device VPN DNS policy.
		// Keep DoH support opt-in; production SRV resolution uses system DNS by default.
		dohProviderURLs = @[];
	}
	return self;
}

- (void)dealloc
{
	XMPPLogTrace();

    [self stop];

	#if !OS_OBJECT_USE_OBJC
	if (resolverQueue)
		dispatch_release(resolverQueue);
	#endif
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Properties
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

@dynamic srvName;
@dynamic timeout;
@dynamic resultSource;

- (NSString *)srvName
{
	__block NSString *result = nil;

	dispatch_block_t block = ^{
		result = [self->srvName copy];
	};

	if (dispatch_get_specific(resolverQueueTag))
		block();
	else
		dispatch_sync(resolverQueue, block);

	return result;
}

- (NSTimeInterval)timeout
{
	__block NSTimeInterval result = 0.0;

	dispatch_block_t block = ^{
		result = self->timeout;
	};

	if (dispatch_get_specific(resolverQueueTag))
		block();
	else
		dispatch_sync(resolverQueue, block);

	return result;
}

- (NSString *)resultSource
{
	__block NSString *result = nil;

	dispatch_block_t block = ^{
		result = [self->resultSource copy];
	};

	if (dispatch_get_specific(resolverQueueTag))
		block();
	else
		dispatch_sync(resolverQueue, block);

	return result;
}

- (void)setDohProviderURLs:(NSArray<NSURL *> *)providerURLs
{
	dispatch_block_t block = ^{
		self->dohProviderURLs = [providerURLs copy];
	};

	if (dispatch_get_specific(resolverQueueTag))
		block();
	else
		dispatch_sync(resolverQueue, block);
}

- (void)setDohURLSessionProtocolClasses:(nullable NSArray *)protocolClasses
{
	dispatch_block_t block = ^{
		self->dohURLSessionProtocolClasses = [protocolClasses copy];
	};

	if (dispatch_get_specific(resolverQueueTag))
		block();
	else
		dispatch_sync(resolverQueue, block);
}

+ (NSString *)cacheKeyForSRVName:(NSString *)srvName dohProviderURLs:(NSArray<NSURL *> *)providerURLs
{
	NSMutableArray<NSString *> *providerStrings = [NSMutableArray arrayWithCapacity:[providerURLs count]];
	for (NSURL *url in providerURLs)
	{
		[providerStrings addObject:[url absoluteString] ?: @""];
	}
	return [NSString stringWithFormat:@"%@|%@", srvName ?: @"", [providerStrings componentsJoinedByString:@","]];
}

+ (NSTimeInterval)cacheTTLForRecords:(NSArray<XMPPSRVRecord *> *)records
{
	UInt32 minTTL = UINT32_MAX;
	for (XMPPSRVRecord *record in records)
	{
		if (record.ttl > 0)
		{
			minTTL = MIN(minTTL, record.ttl);
		}
	}

	NSTimeInterval ttl = minTTL == UINT32_MAX ? XMPPSRVResolverDefaultCacheTTL : (NSTimeInterval)minTTL;
	return MIN(MAX(ttl, 1.0), XMPPSRVResolverMaxCacheTTL);
}

+ (void)storeCacheRecords:(NSArray<XMPPSRVRecord *> *)records error:(NSError *)error source:(NSString *)source key:(NSString *)key
{
	if ([key length] == 0)
	{
		return;
	}

	NSTimeInterval ttl = [records count] > 0 ? [self cacheTTLForRecords:records] : XMPPSRVResolverDefaultCacheTTL;
	XMPPSRVResolverCacheEntry *entry = [XMPPSRVResolverCacheEntry new];
	entry.records = [records copy];
	entry.error = error;
	entry.source = source ?: XMPPSRVResolverSourceSystemDNS;
	entry.expiresAt = [NSDate dateWithTimeIntervalSinceNow:ttl];

	dispatch_sync(XMPPSRVResolverCacheQueue(), ^{
		XMPPSRVResolverCacheStorage()[key] = entry;
	});
}

+ (nullable XMPPSRVResolverCacheEntry *)cacheEntryForKey:(NSString *)key
{
	if ([key length] == 0)
	{
		return nil;
	}

	__block XMPPSRVResolverCacheEntry *entry = nil;
	dispatch_sync(XMPPSRVResolverCacheQueue(), ^{
		entry = XMPPSRVResolverCacheStorage()[key];
		if (entry && [entry.expiresAt timeIntervalSinceNow] <= 0)
		{
			[XMPPSRVResolverCacheStorage() removeObjectForKey:key];
			entry = nil;
		}
	});
	return entry;
}

+ (void)invalidateCache
{
	[self invalidateCacheWithReason:nil];
}

+ (void)invalidateCacheWithReason:(NSString *)reason
{
	(void)reason;
	dispatch_sync(XMPPSRVResolverCacheQueue(), ^{
		[XMPPSRVResolverCacheStorage() removeAllObjects];
	});
}

+ (NSUInteger)xmpp_cacheEntryCountForTesting
{
	__block NSUInteger count = 0;
	dispatch_sync(XMPPSRVResolverCacheQueue(), ^{
		NSDate *now = [NSDate date];
		NSArray<NSString *> *keys = [XMPPSRVResolverCacheStorage() allKeys];
		for (NSString *key in keys)
		{
			XMPPSRVResolverCacheEntry *entry = XMPPSRVResolverCacheStorage()[key];
			if ([entry.expiresAt compare:now] != NSOrderedDescending)
			{
				[XMPPSRVResolverCacheStorage() removeObjectForKey:key];
			}
		}
		count = [XMPPSRVResolverCacheStorage() count];
	});
	return count;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Private Methods
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

+ (NSData *)xmpp_dnsMessageForSRVName:(NSString *)srvName queryID:(UInt16)queryID
{
	if ([srvName length] == 0)
	{
		return nil;
	}

	NSString *normalizedName = [srvName hasSuffix:@"."] ? [srvName substringToIndex:([srvName length] - 1)] : srvName;
	if ([normalizedName length] == 0)
	{
		return nil;
	}

	NSMutableData *data = [NSMutableData dataWithCapacity:64];

	XMPPDNSAppendUInt16(data, queryID);
	XMPPDNSAppendUInt16(data, XMPPDNSFlagRecursionDesired);
	XMPPDNSAppendUInt16(data, 1);
	XMPPDNSAppendUInt16(data, 0);
	XMPPDNSAppendUInt16(data, 0);
	XMPPDNSAppendUInt16(data, 0);

	NSUInteger wireNameLength = 1;
	NSArray<NSString *> *labels = [normalizedName componentsSeparatedByString:@"."];
	for (NSString *label in labels)
	{
		NSData *labelData = [label dataUsingEncoding:NSASCIIStringEncoding];
		if ([labelData length] == 0 || [labelData length] > 63)
		{
			return nil;
		}

		wireNameLength += [labelData length] + 1;
		if (wireNameLength > 255)
		{
			return nil;
		}

		uint8_t labelLength = (uint8_t)[labelData length];
		[data appendBytes:&labelLength length:sizeof(labelLength)];
		[data appendData:labelData];
	}

	uint8_t rootLabel = 0;
	[data appendBytes:&rootLabel length:sizeof(rootLabel)];
	XMPPDNSAppendUInt16(data, XMPPDNSTypeSRV);
	XMPPDNSAppendUInt16(data, XMPPDNSClassIN);

	return data;
}

+ (NSArray<XMPPSRVRecord *> *)xmpp_SRVRecordsFromDNSMessage:(NSData *)data queryID:(UInt16)queryID
{
	if ([data length] < XMPPDNSHeaderLength)
	{
		return nil;
	}

	const uint8_t *bytes = [data bytes];
	NSUInteger length = [data length];

	uint16_t responseID = 0;
	uint16_t flags = 0;
	uint16_t qdCount = 0;
	uint16_t anCount = 0;
	uint16_t nsCount = 0;
	uint16_t arCount = 0;

	if (!XMPPDNSReadUInt16(bytes, length, 0, &responseID) ||
	    !XMPPDNSReadUInt16(bytes, length, 2, &flags) ||
	    !XMPPDNSReadUInt16(bytes, length, 4, &qdCount) ||
	    !XMPPDNSReadUInt16(bytes, length, 6, &anCount) ||
	    !XMPPDNSReadUInt16(bytes, length, 8, &nsCount) ||
	    !XMPPDNSReadUInt16(bytes, length, 10, &arCount))
	{
		return nil;
	}

	if (responseID != queryID ||
	    (flags & XMPPDNSFlagResponse) == 0 ||
	    (flags & XMPPDNSFlagTruncated) != 0 ||
	    (flags & XMPPDNSRCodeMask) != 0 ||
	    qdCount != 1 ||
	    nsCount > 4096 ||
	    arCount > 4096)
	{
		return nil;
	}

	NSUInteger offset = XMPPDNSHeaderLength;

	for (uint16_t i = 0; i < qdCount; i++)
	{
		NSString *questionName = nil;
		if (!XMPPDNSReadName(bytes, length, &offset, &questionName) ||
		    offset > length ||
		    length - offset < 4)
		{
			return nil;
		}
		(void)questionName;

		offset += 4;
	}

	NSMutableArray<XMPPSRVRecord *> *records = [NSMutableArray arrayWithCapacity:anCount];

	for (uint16_t i = 0; i < anCount; i++)
	{
		NSString *recordName = nil;
		if (!XMPPDNSReadName(bytes, length, &offset, &recordName) ||
		    offset > length ||
		    length - offset < 10)
		{
			return nil;
		}
		(void)recordName;

		uint16_t type = 0;
		uint16_t rrClass = 0;
		uint32_t ttl = 0;
		uint16_t rdLength = 0;

		if (!XMPPDNSReadUInt16(bytes, length, offset, &type) ||
		    !XMPPDNSReadUInt16(bytes, length, offset + 2, &rrClass) ||
		    !XMPPDNSReadUInt32(bytes, length, offset + 4, &ttl) ||
		    !XMPPDNSReadUInt16(bytes, length, offset + 8, &rdLength))
		{
			return nil;
		}
			offset += 10;

		if (offset > length || length - offset < rdLength)
		{
			return nil;
		}

		NSUInteger rdataOffset = offset;
		NSUInteger rdataEnd = offset + rdLength;

		if (type == XMPPDNSTypeSRV && rrClass == XMPPDNSClassIN)
		{
			if (rdLength < 7)
			{
				return nil;
			}

			uint16_t priority = 0;
			uint16_t weight = 0;
			uint16_t port = 0;

			if (!XMPPDNSReadUInt16(bytes, length, rdataOffset, &priority) ||
			    !XMPPDNSReadUInt16(bytes, length, rdataOffset + 2, &weight) ||
			    !XMPPDNSReadUInt16(bytes, length, rdataOffset + 4, &port))
			{
				return nil;
			}

			NSUInteger targetOffset = rdataOffset + 6;
			NSString *target = nil;
				if (!XMPPDNSReadName(bytes, length, &targetOffset, &target) ||
				    targetOffset != rdataEnd)
				{
					return nil;
				}
				if ([target length] == 0)
				{
					target = @".";
				}

				XMPPSRVRecord *record = [XMPPSRVRecord recordWithPriority:priority
				                                                   weight:weight
				                                                     port:port
				                                                   target:target
				                                                      ttl:ttl];
			[records addObject:record];
		}

		offset = rdataEnd;
	}

	if (!XMPPDNSSkipResourceRecords(bytes, length, &offset, nsCount) ||
	    !XMPPDNSSkipResourceRecords(bytes, length, &offset, arCount))
	{
		return nil;
	}

	return records;
}

- (BOOL)markSystemResolverStarted
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	if (systemResolverStarted)
	{
		return NO;
	}

	systemResolverStarted = YES;
	return YES;
}

- (void)cancelDohProviderTimer
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	if (dohProviderTimer)
	{
		dispatch_source_cancel(dohProviderTimer);
		#if !OS_OBJECT_USE_OBJC
		dispatch_release(dohProviderTimer);
		#endif
		dohProviderTimer = NULL;
	}
}

- (void)cleanupDohAttemptAndCancelTask:(BOOL)cancelTask
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	[self cancelDohProviderTimer];

	NSURLSessionDataTask *task = dohTask;
	NSURLSession *session = dohSession;

	dohTask = nil;
	dohSession = nil;
	dohAttemptID++;

	if (cancelTask)
	{
		[task cancel];
		[session invalidateAndCancel];
	}
	else
	{
		[session finishTasksAndInvalidate];
	}
}

- (void)cleanupSystemResolver
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	if (sdReadSource)
	{
		dispatch_source_cancel(sdReadSource);
		sdReadSource = NULL;
		sdFd = -1;
		sdRef = NULL;
	}
}

- (void)continueAfterDohFailure
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	dohProviderIndex++;
	[self startNextDohProvider];
}

- (void)handleDohResponseData:(NSData *)data
                     response:(NSURLResponse *)response
                        error:(NSError *)error
                    attemptID:(NSUInteger)attemptID
                      queryID:(UInt16)queryID
                  providerURL:(NSURL *)providerURL
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	if (!resolveInProgress || attemptID != dohAttemptID)
	{
		return;
	}

	[self cleanupDohAttemptAndCancelTask:NO];

	NSHTTPURLResponse *httpResponse = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
	if (error || [httpResponse statusCode] != 200 || [data length] == 0)
	{
		XMPPLogVerbose(@"%@: DoH SRV lookup failed via %@; trying next resolver", THIS_FILE, [providerURL host]);
		[self continueAfterDohFailure];
		return;
	}

	NSArray<XMPPSRVRecord *> *dohRecords = [[self class] xmpp_SRVRecordsFromDNSMessage:data queryID:queryID];
	if ([dohRecords count] == 0)
	{
		XMPPLogVerbose(@"%@: DoH SRV lookup returned no valid SRV answers via %@; trying next resolver", THIS_FILE, [providerURL host]);
		[self continueAfterDohFailure];
		return;
	}

	[results addObjectsFromArray:dohRecords];
	[self succeedWithSource:XMPPSRVResolverSourceDoH cacheable:YES];
}

- (void)startNextDohProvider
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	if (!resolveInProgress)
	{
		return;
	}

	if (dohProviderIndex >= [dohProviderURLs count])
	{
		if ([dohProviderURLs count] == 0)
		{
			XMPPLogVerbose(@"%@: No DoH SRV provider configured", THIS_FILE);
		}
		else
		{
			XMPPLogVerbose(@"%@: Exhausted DoH SRV providers after system resolver failure", THIS_FILE);
		}
		NSError *error = lastResolverError;
		if (error == nil)
		{
			error = [NSError errorWithDomain:XMPPSRVResolverErrorDomain
			                            code:XMPPSRVResolverErrorTimedOut
			                        userInfo:@{NSLocalizedDescriptionKey: @"No SRV resolver available",
			                                   XMPPSRVResolverErrorCategoryKey: @"dns"}];
		}
		[self failWithError:error source:([dohProviderURLs count] > 0 ? XMPPSRVResolverSourceDoH : XMPPSRVResolverSourceSystemDNS) cacheable:YES];
		return;
	}

	NSURL *providerURL = dohProviderURLs[dohProviderIndex];
	dohQueryID = (UInt16)arc4random();
	NSData *queryData = [[self class] xmpp_dnsMessageForSRVName:srvName queryID:dohQueryID];
	if ([queryData length] == 0)
	{
		XMPPLogVerbose(@"%@: Unable to build DoH SRV query", THIS_FILE);
		dohProviderIndex = [dohProviderURLs count];
		[self startNextDohProvider];
		return;
	}

	NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:providerURL
	                                                        cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
	                                                    timeoutInterval:XMPPSRVResolverDohProviderTimeout];
	[request setHTTPMethod:@"POST"];
	[request setHTTPBody:queryData];
	[request setValue:XMPPSRVResolverDohMediaType forHTTPHeaderField:@"Content-Type"];
	[request setValue:XMPPSRVResolverDohMediaType forHTTPHeaderField:@"Accept"];

	NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
	configuration.timeoutIntervalForRequest = XMPPSRVResolverDohProviderTimeout;
	configuration.timeoutIntervalForResource = XMPPSRVResolverDohProviderTimeout;
	configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
	configuration.URLCache = nil;
	configuration.HTTPShouldSetCookies = NO;
	if ([dohURLSessionProtocolClasses count] > 0)
	{
		configuration.protocolClasses = dohURLSessionProtocolClasses;
	}

	dohSession = [NSURLSession sessionWithConfiguration:configuration];
	NSUInteger attemptID = ++dohAttemptID;
	UInt16 queryID = dohQueryID;

	__weak XMPPSRVResolver *weakSelf = self;
	dohTask = [dohSession dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {

		XMPPSRVResolver *strongSelf = weakSelf;
		if (strongSelf == nil)
		{
			return;
		}

		dispatch_async(strongSelf->resolverQueue, ^{ @autoreleasepool {

			[strongSelf handleDohResponseData:data
			                         response:response
			                            error:error
			                        attemptID:attemptID
			                          queryID:queryID
			                      providerURL:providerURL];

		}});
	}];

	dohProviderTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, resolverQueue);
	dispatch_source_set_event_handler(dohProviderTimer, ^{ @autoreleasepool {

		if (!self->resolveInProgress || attemptID != self->dohAttemptID)
		{
			return;
		}

		XMPPLogVerbose(@"%@: DoH SRV lookup timed out via %@; trying next resolver", THIS_FILE, [providerURL host]);
		[self cleanupDohAttemptAndCancelTask:YES];
		[self continueAfterDohFailure];

	}});

	dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (XMPPSRVResolverDohProviderTimeout * NSEC_PER_SEC));
	dispatch_source_set_timer(dohProviderTimer, tt, DISPATCH_TIME_FOREVER, 0);
	dispatch_resume(dohProviderTimer);

	[dohTask resume];
}

- (void)sortResults
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	XMPPLogTrace();

	// Sort results
	NSMutableArray *sortedResults = [NSMutableArray arrayWithCapacity:[results count]];

	// Sort the list by priority (lowest number first)
	[results sortUsingSelector:@selector(compareByPriority:)];

	/* From RFC 2782
	 *
	 * For each distinct priority level
	 * While there are still elements left at this priority level
	 *
	 * Select an element as specified above, in the
	 * description of Weight in "The format of the SRV
	 * RR" Section, and move it to the tail of the new
	 * list.
	 *
	 * The following algorithm SHOULD be used to order
	 * the SRV RRs of the same priority:
	 */

	NSUInteger srvResultsCount;

	while ([results count] > 0)
	{
		srvResultsCount = [results count];

		if (srvResultsCount == 1)
		{
			XMPPSRVRecord *srvRecord = results[0];

			[sortedResults addObject:srvRecord];
			[results removeObjectAtIndex:0];
		}
		else // (srvResultsCount > 1)
		{
			// more than two records so we need to sort

			/* To select a target to be contacted next, arrange all SRV RRs
			 * (that have not been ordered yet) in any order, except that all
			 * those with weight 0 are placed at the beginning of the list.
			 *
			 * Compute the sum of the weights of those RRs, and with each RR
			 * associate the running sum in the selected order.
			 */

			NSUInteger runningSum = 0;
			NSMutableArray *samePriorityRecords = [NSMutableArray arrayWithCapacity:srvResultsCount];

			XMPPSRVRecord *srvRecord = results[0];

			NSUInteger initialPriority = srvRecord.priority;
			NSUInteger index = 0;

			do
			{
				if (srvRecord.weight == 0)
				{
					// add to front of array
					[samePriorityRecords insertObject:srvRecord atIndex:0];

					srvRecord.srvResultsIndex = index;
					srvRecord.sum = 0;
				}
				else
				{
					// add to end of array and update the running sum
					[samePriorityRecords addObject:srvRecord];

					runningSum += srvRecord.weight;

					srvRecord.srvResultsIndex = index;
					srvRecord.sum = runningSum;
				}

				if (++index < srvResultsCount)
				{
					srvRecord = results[index];
				}
				else
				{
					srvRecord = nil;
				}

			} while(srvRecord && (srvRecord.priority == initialPriority));

			/* Then choose a uniform random number between 0 and the sum computed
			 * (inclusive), and select the RR whose running sum value is the
			 * first in the selected order which is greater than or equal to
			 * the random number selected.
			 */

			NSUInteger randomIndex = arc4random() % (runningSum + 1);

			for (srvRecord in samePriorityRecords)
			{
				if (srvRecord.sum >= randomIndex)
				{
					/* The target host specified in the
					 * selected SRV RR is the next one to be contacted by the client.
					 * Remove this SRV RR from the set of the unordered SRV RRs and
					 * apply the described algorithm to the unordered SRV RRs to select
					 * the next target host.  Continue the ordering process until there
					 * are no unordered SRV RRs.  This process is repeated for each
					 * Priority.
					 */

					[sortedResults addObject:srvRecord];
					[results removeObjectAtIndex:srvRecord.srvResultsIndex];

					break;
				}
			}
		}
	}

	results = sortedResults;

	XMPPLogVerbose(@"%@: Sorted results:\n%@", THIS_FILE, results);
}

- (void)succeed
{
	[self succeedWithSource:XMPPSRVResolverSourceSystemDNS cacheable:YES];
}

- (void)succeedWithSource:(NSString *)source cacheable:(BOOL)cacheable
{
    NSParameterAssert(delegate != nil);
    NSParameterAssert(delegateQueue != nil);
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	XMPPLogTrace();

    if (!delegate || !delegateQueue) {
        XMPPLogError(@"%@: No delegate or queue set for SRV resolver.", THIS_FILE);
        return;
    }

	[self sortResults];

	self->resultSource = [source copy];
	id theDelegate = delegate;
	NSArray *records = [results copy];
	if (cacheable)
	{
		[[self class] storeCacheRecords:records error:nil source:source key:cacheKey];
	}

	dispatch_async(delegateQueue, ^{ @autoreleasepool {

		SEL selector = @selector(xmppSRVResolver:didResolveRecords:);

		if ([theDelegate respondsToSelector:selector])
		{
			[theDelegate xmppSRVResolver:self didResolveRecords:records];
		}
		else
		{
			XMPPLogWarn(@"%@: delegate doesn't implement %@", THIS_FILE, NSStringFromSelector(selector));
		}

	}});

	[self stop];
}

- (void)failWithError:(NSError *)error
{
	[self failWithError:error source:XMPPSRVResolverSourceSystemDNS cacheable:YES];
}

- (void)failWithError:(NSError *)error source:(NSString *)source cacheable:(BOOL)cacheable
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	XMPPLogTrace2(@"%@: %@ %@", THIS_FILE, THIS_METHOD, error);

	self->resultSource = [source copy];
	NSMutableDictionary *userInfo = [[error userInfo] mutableCopy] ?: [NSMutableDictionary dictionary];
	if (source)
	{
		userInfo[XMPPSRVResolverSourceKey] = source;
	}
	if (userInfo[XMPPSRVResolverErrorCategoryKey] == nil)
	{
		userInfo[XMPPSRVResolverErrorCategoryKey] = @"dns";
	}
	NSError *decoratedError = [NSError errorWithDomain:[error domain] code:[error code] userInfo:userInfo];
	if (cacheable)
	{
		[[self class] storeCacheRecords:nil error:decoratedError source:source key:cacheKey];
	}
	id theDelegate = delegate;

    if (delegateQueue != NULL)
	{
		dispatch_async(delegateQueue, ^{ @autoreleasepool {

			SEL selector = @selector(xmppSRVResolver:didNotResolveDueToError:);

				if ([theDelegate respondsToSelector:selector])
				{
					[theDelegate xmppSRVResolver:self didNotResolveDueToError:decoratedError];
			}
			else
			{
				XMPPLogWarn(@"%@: delegate doesn't implement %@", THIS_FILE, NSStringFromSelector(selector));
			}

		}});
	}

	[self stop];
}

- (void)failWithDNSError:(DNSServiceErrorType)sdErr
{
	XMPPLogTrace2(@"%@: %@ %i", THIS_FILE, THIS_METHOD, (int)sdErr);

	NSError *error = [NSError errorWithDomain:XMPPSRVResolverErrorDomain
	                                     code:sdErr
	                                 userInfo:@{XMPPSRVResolverErrorCategoryKey: @"dns"}];
	[self continueAfterSystemResolverFailure:error];
}

- (void)continueAfterSystemResolverFailure:(NSError *)error
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	lastResolverError = error;
	[self cleanupSystemResolver];

	if ([dohProviderURLs count] > 0)
	{
		dohProviderIndex = 0;
		[self startNextDohProvider];
		return;
	}

	[self failWithError:error source:XMPPSRVResolverSourceSystemDNS cacheable:YES];
}

- (XMPPSRVRecord *)processRecord:(const void *)rdata length:(uint16_t)rdlen ttl:(uint32_t)ttl
{
	XMPPLogTrace();

	// Note: This method is almost entirely from Apple's sample code.
	//
	// Otherwise there would be a lot more comments and explanation...

	if (rdata == NULL)
	{
		XMPPLogWarn(@"%@: %@ - rdata == NULL", THIS_FILE, THIS_METHOD);
		return nil;
	}

	// Rather than write a whole bunch of icky parsing code, I just synthesise
	// a resource record and use <dns_util.h>.

	XMPPSRVRecord *result = nil;

	NSMutableData *         rrData;
	dns_resource_record_t * rr;
	uint8_t                 u8;   // 1 byte
	uint16_t                u16;  // 2 bytes
	uint32_t                u32;  // 4 bytes

	rrData = [NSMutableData dataWithCapacity:(1 + 2 + 2 + 4 + 2 + rdlen)];

	u8 = 0;
	[rrData appendBytes:&u8 length:sizeof(u8)];
	u16 = htons(kDNSServiceType_SRV);
	[rrData appendBytes:&u16 length:sizeof(u16)];
	u16 = htons(kDNSServiceClass_IN);
	[rrData appendBytes:&u16 length:sizeof(u16)];
	u32 = htonl(666);
	[rrData appendBytes:&u32 length:sizeof(u32)];
	u16 = htons(rdlen);
	[rrData appendBytes:&u16 length:sizeof(u16)];
	[rrData appendBytes:rdata length:rdlen];

	// Parse the record.

	rr = dns_parse_resource_record([rrData bytes], (uint32_t) [rrData length]);
    if (rr != NULL)
	{
        NSString *target;

	        target = [NSString stringWithCString:rr->data.SRV->target encoding:NSASCIIStringEncoding];
	        if (target != nil)
			{
				if ([target length] == 0)
				{
					target = @".";
				}
				UInt16 priority = rr->data.SRV->priority;
				UInt16 weight   = rr->data.SRV->weight;
				UInt16 port     = rr->data.SRV->port;

				result = [XMPPSRVRecord recordWithPriority:priority weight:weight port:port target:target ttl:ttl];
	        }

        dns_free_resource_record(rr);
    }

	return result;
}

static void QueryRecordCallback(DNSServiceRef       sdRef,
                                DNSServiceFlags     flags,
                                uint32_t            interfaceIndex,
                                DNSServiceErrorType errorCode,
                                const char *        fullname,
                                uint16_t            rrtype,
                                uint16_t            rrclass,
                                uint16_t            rdlen,
                                const void *        rdata,
                                uint32_t            ttl,
                                void *              context)
{
	// Called when we get a response to our query.
	// It does some preliminary work, but the bulk of the interesting stuff
	// is done in the processRecord:length: method.

	XMPPSRVResolver *resolver = (__bridge XMPPSRVResolver *)context;

	NSCAssert(dispatch_get_specific(resolver->resolverQueueTag), @"Invoked on incorrect queue");

	XMPPLogCTrace();

	if (!(flags & kDNSServiceFlagsAdd))
	{
		// If the kDNSServiceFlagsAdd flag is not set, the domain information is not valid.
		return;
    }

    if (errorCode == kDNSServiceErr_NoError &&
        rrtype == kDNSServiceType_SRV)
    {
	        XMPPSRVRecord *record = [resolver processRecord:rdata length:rdlen ttl:ttl];
        if (record)
        {
            [resolver->results addObject:record];
        }

        if ( ! (flags & kDNSServiceFlagsMoreComing) )
        {
            [resolver succeed];
        }
    }
    else
    {
        [resolver failWithDNSError:errorCode];
    }
}

- (void)startSystemResolver
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	if (![self markSystemResolverStarted])
	{
		return;
	}

	XMPPLogTrace();

	const char *srvNameCStr = [self->srvName cStringUsingEncoding:NSASCIIStringEncoding];
	if (srvNameCStr == NULL)
	{
		[self failWithDNSError:kDNSServiceErr_BadParam];
		return;
	}

	DNSServiceErrorType sdErr;
	sdErr = DNSServiceQueryRecord(&self->sdRef,                              // Pointer to unitialized DNSServiceRef
	                              kDNSServiceFlagsReturnIntermediates, // Flags
	                              kDNSServiceInterfaceIndexAny,        // Interface index
	                              srvNameCStr,                         // Full domain name
	                              kDNSServiceType_SRV,                 // rrtype
	                              kDNSServiceClass_IN,                 // rrclass
	                              QueryRecordCallback,                 // Callback method
	                              (__bridge void *)self);              // Context pointer

	if (sdErr != kDNSServiceErr_NoError)
	{
		[self failWithDNSError:sdErr];
		return;
	}

	self->sdFd = DNSServiceRefSockFD(self->sdRef);
	if (self->sdFd < 0)
	{
		// Todo...
	}

	self->sdReadSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, self->sdFd, 0, self->resolverQueue);

	dispatch_source_set_event_handler(self->sdReadSource, ^{ @autoreleasepool {

		XMPPLogVerbose(@"%@: sdReadSource_eventHandler", THIS_FILE);

		DNSServiceErrorType dnsErr = DNSServiceProcessResult(self->sdRef);
		if (dnsErr != kDNSServiceErr_NoError)
		{
			[self failWithDNSError:dnsErr];
		}

	}});

	#if !OS_OBJECT_USE_OBJC
	dispatch_source_t theSdReadSource = sdReadSource;
	#endif
	DNSServiceRef theSdRef = self->sdRef;

	dispatch_source_set_cancel_handler(self->sdReadSource, ^{ @autoreleasepool {

		XMPPLogVerbose(@"%@: sdReadSource_cancelHandler", THIS_FILE);

		#if !OS_OBJECT_USE_OBJC
		dispatch_release(theSdReadSource);
		#endif
		DNSServiceRefDeallocate(theSdRef);

	}});

	dispatch_resume(self->sdReadSource);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Public Methods
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)startWithSRVName:(NSString *)aSRVName timeout:(NSTimeInterval)aTimeout
{
	dispatch_block_t block = ^{ @autoreleasepool {

		if (self->resolveInProgress)
		{
			return;
		}

		XMPPLogTrace2(@"%@: startWithSRVName:%@ timeout:%f", THIS_FILE, aSRVName, aTimeout);

		// Save parameters

			self->srvName = [aSRVName copy];

			self->timeout = aTimeout;
			self->resultSource = nil;
			self->lastResolverError = nil;
			self->cacheKey = [[self class] cacheKeyForSRVName:self->srvName dohProviderURLs:self->dohProviderURLs];

			self->dohProviderIndex = 0;
			self->systemResolverStarted = NO;
			self->resolveInProgress = YES;

			XMPPSRVResolverCacheEntry *entry = [[self class] cacheEntryForKey:self->cacheKey];
			if (entry)
			{
				self->resultSource = XMPPSRVResolverSourceCache;
				if ([entry.records count] > 0)
				{
					[self->results addObjectsFromArray:entry.records];
					[self succeedWithSource:XMPPSRVResolverSourceCache cacheable:NO];
				}
				else
				{
					NSError *error = entry.error ?: [NSError errorWithDomain:XMPPSRVResolverErrorDomain
					                                                     code:XMPPSRVResolverErrorTimedOut
					                                                 userInfo:@{NSLocalizedDescriptionKey: @"Cached negative SRV response",
					                                                            XMPPSRVResolverErrorCategoryKey: @"dns"}];
					[self failWithError:error source:XMPPSRVResolverSourceCache cacheable:NO];
				}
				return;
			}

			// Create timer (if requested timeout > 0)

		if (self->timeout > 0.0)
		{
			self->timeoutTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self->resolverQueue);

			dispatch_source_set_event_handler(self->timeoutTimer, ^{ @autoreleasepool {

					NSString *errMsg = @"Operation timed out";
					NSDictionary *userInfo = @{NSLocalizedDescriptionKey : errMsg,
					                           XMPPSRVResolverErrorCategoryKey : @"timeout"};

					NSError *err = [NSError errorWithDomain:XMPPSRVResolverErrorDomain code:XMPPSRVResolverErrorTimedOut userInfo:userInfo];

					[self failWithError:err source:XMPPSRVResolverSourceSystemDNS cacheable:YES];

			}});

			dispatch_time_t tt = dispatch_time(DISPATCH_TIME_NOW, (self->timeout * NSEC_PER_SEC));

			dispatch_source_set_timer(self->timeoutTimer, tt, DISPATCH_TIME_FOREVER, 0);
			dispatch_resume(self->timeoutTimer);
		}

			[self startSystemResolver];
		}};

	if (dispatch_get_specific(resolverQueueTag))
		block();
	else
		dispatch_async(resolverQueue, block);
}

- (void)stop
{
	dispatch_block_t block = ^{ @autoreleasepool {

		XMPPLogTrace();

		self->delegate = nil;
		if (self->delegateQueue)
		{
			#if !OS_OBJECT_USE_OBJC
			dispatch_release(delegateQueue);
			#endif
			self->delegateQueue = NULL;
		}

			[self->results removeAllObjects];
			[self cleanupDohAttemptAndCancelTask:YES];
			[self cleanupSystemResolver];

			if (self->timeoutTimer)
		{
			dispatch_source_cancel(self->timeoutTimer);
			#if !OS_OBJECT_USE_OBJC
			dispatch_release(timeoutTimer);
			#endif
			self->timeoutTimer = NULL;
		}

			self->dohProviderIndex = 0;
			self->systemResolverStarted = NO;
			self->resolveInProgress = NO;
			self->lastResolverError = nil;
		}};

	if (dispatch_get_specific(resolverQueueTag))
		block();
	else
		dispatch_sync(resolverQueue, block);
}

- (void)xmpp_resolveRecordsForTesting:(NSArray<XMPPSRVRecord *> *)records source:(NSString *)source
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	[results addObjectsFromArray:records];
	[self succeedWithSource:source ?: XMPPSRVResolverSourceSystemDNS cacheable:YES];
}

- (void)xmpp_failSystemResolverForTestingWithError:(NSError *)error
{
	NSAssert(dispatch_get_specific(resolverQueueTag), @"Invoked on incorrect queue");

	[self continueAfterSystemResolverFailure:error];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark Utility Methods
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

+ (NSString *)srvNameFromXMPPDomain:(NSString *)xmppDomain
{
    NSParameterAssert(xmppDomain != nil);
	if (xmppDomain == nil)
		return nil;
	else
		return [NSString stringWithFormat:@"_xmpp-client._tcp.%@", xmppDomain];
}

@end

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark -
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

@implementation XMPPSRVRecord

@synthesize priority;
@synthesize weight;
@synthesize port;
@synthesize ttl;
@synthesize target;

@synthesize sum;
@synthesize srvResultsIndex;


+ (XMPPSRVRecord *)recordWithPriority:(UInt16)p1 weight:(UInt16)w port:(UInt16)p2 target:(NSString *)t
{
	return [[XMPPSRVRecord alloc] initWithPriority:p1 weight:w port:p2 target:t];
}

+ (XMPPSRVRecord *)recordWithPriority:(UInt16)p1 weight:(UInt16)w port:(UInt16)p2 target:(NSString *)t ttl:(UInt32)ttl
{
	return [[XMPPSRVRecord alloc] initWithPriority:p1 weight:w port:p2 target:t ttl:ttl];
}

- (id)initWithPriority:(UInt16)p1 weight:(UInt16)w port:(UInt16)p2 target:(NSString *)t
{
	return [self initWithPriority:p1 weight:w port:p2 target:t ttl:0];
}

- (id)initWithPriority:(UInt16)p1 weight:(UInt16)w port:(UInt16)p2 target:(NSString *)t ttl:(UInt32)recordTTL
{
	if ((self = [super init]))
	{
		priority = p1;
		weight   = w;
		port     = p2;
		ttl      = recordTTL;
		target   = [t copy];

		sum = 0;
		srvResultsIndex = 0;
	}
	return self;
}


- (NSString *)description
{
	return [NSString stringWithFormat:@"<%@:%p target(%@) port(%hu) priority(%hu) weight(%hu) ttl(%u)>",
			NSStringFromClass([self class]), self, target, port, priority, weight, ttl];
}

- (NSComparisonResult)compareByPriority:(XMPPSRVRecord *)aRecord
{
	UInt16 mPriority = self.priority;
	UInt16 aPriority = aRecord.priority;

	if (mPriority < aPriority)
		return NSOrderedAscending;

	if (mPriority > aPriority)
		return NSOrderedDescending;

	return NSOrderedSame;
}

@end
