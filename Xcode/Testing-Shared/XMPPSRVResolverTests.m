//
//  XMPPSRVResolverTests.m
//  XMPPFrameworkTests
//

#import <XCTest/XCTest.h>
@import XMPPFramework;
#include <arpa/inet.h>

static NSString *const XMPPSRVResolverTestSRVName = @"_xmpp-client._tcp.example.com";

@interface XMPPSRVResolver (DoHTesting)

+ (NSData *)xmpp_dnsMessageForSRVName:(NSString *)srvName queryID:(UInt16)queryID;
+ (NSArray<XMPPSRVRecord *> *)xmpp_SRVRecordsFromDNSMessage:(NSData *)data queryID:(UInt16)queryID;

- (void)setDohProviderURLs:(NSArray<NSURL *> *)providerURLs;
- (void)setDohURLSessionProtocolClasses:(NSArray *)protocolClasses;
- (BOOL)markSystemResolverStarted;
- (void)startSystemResolver;

@end

@interface XMPPSRVResolverDelegateRecorder : NSObject <XMPPSRVResolverDelegate>

@property (nonatomic, strong) XCTestExpectation *expectation;
@property (nonatomic, copy) NSArray<XMPPSRVRecord *> *records;
@property (nonatomic, strong) NSError *error;

@end

@implementation XMPPSRVResolverDelegateRecorder

- (void)xmppSRVResolver:(XMPPSRVResolver *)sender didResolveRecords:(NSArray<XMPPSRVRecord *> *)records
{
	self.records = records;
	[self.expectation fulfill];
}

- (void)xmppSRVResolver:(XMPPSRVResolver *)sender didNotResolveDueToError:(NSError *)error
{
	self.error = error;
	[self.expectation fulfill];
}

@end

@interface XMPPSRVResolverFallbackSpy : XMPPSRVResolver

@property (nonatomic, assign) NSUInteger startSystemResolverCount;
@property (nonatomic, strong) XCTestExpectation *fallbackExpectation;

@end

@implementation XMPPSRVResolverFallbackSpy

- (void)startSystemResolver
{
	if ([self markSystemResolverStarted])
	{
		self.startSystemResolverCount++;
		[self.fallbackExpectation fulfill];
	}
}

@end

typedef void (^XMPPSRVResolverMockHandler)(NSURLRequest *request, id<NSURLProtocolClient> client, NSURLProtocol *protocol);

@interface XMPPSRVResolverMockURLProtocol : NSURLProtocol

@property (class, nonatomic, copy) XMPPSRVResolverMockHandler requestHandler;

@end

static XMPPSRVResolverMockHandler XMPPSRVResolverMockURLProtocolRequestHandler;

@implementation XMPPSRVResolverMockURLProtocol

+ (XMPPSRVResolverMockHandler)requestHandler
{
	return XMPPSRVResolverMockURLProtocolRequestHandler;
}

+ (void)setRequestHandler:(XMPPSRVResolverMockHandler)requestHandler
{
	XMPPSRVResolverMockURLProtocolRequestHandler = [requestHandler copy];
}

+ (BOOL)canInitWithRequest:(NSURLRequest *)request
{
	return YES;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
	return request;
}

- (void)startLoading
{
	XMPPSRVResolverMockHandler handler = [XMPPSRVResolverMockURLProtocol requestHandler];
	if (handler)
	{
		handler(self.request, self.client, self);
	}
}

- (void)stopLoading
{
}

@end

static void XMPPSRVResolverTestAppendUInt16(NSMutableData *data, UInt16 value)
{
	UInt16 networkValue = htons(value);
	[data appendBytes:&networkValue length:sizeof(networkValue)];
}

static void XMPPSRVResolverTestAppendUInt32(NSMutableData *data, UInt32 value)
{
	UInt32 networkValue = htonl(value);
	[data appendBytes:&networkValue length:sizeof(networkValue)];
}

static void XMPPSRVResolverTestAppendName(NSMutableData *data, NSString *name)
{
	for (NSString *label in [name componentsSeparatedByString:@"."])
	{
		NSData *labelData = [label dataUsingEncoding:NSASCIIStringEncoding];
		UInt8 labelLength = (UInt8)[labelData length];
		[data appendBytes:&labelLength length:sizeof(labelLength)];
		[data appendData:labelData];
	}

	UInt8 rootLabel = 0;
	[data appendBytes:&rootLabel length:sizeof(rootLabel)];
}

static UInt16 XMPPSRVResolverTestOffsetOfLabel(NSString *name, NSString *label)
{
	UInt16 offset = 12;
	for (NSString *currentLabel in [name componentsSeparatedByString:@"."])
	{
		if ([currentLabel isEqualToString:label])
		{
			return offset;
		}

		offset += (UInt16)(1 + [currentLabel length]);
	}

	return 0;
}

static void XMPPSRVResolverTestAppendCompressedExampleTarget(NSMutableData *data, NSString *target)
{
	NSArray<NSString *> *labels = [target componentsSeparatedByString:@"."];
	NSCAssert([labels count] == 3, @"Expected host.example.com target");
	NSData *hostData = [labels[0] dataUsingEncoding:NSASCIIStringEncoding];
	UInt8 hostLength = (UInt8)[hostData length];
	[data appendBytes:&hostLength length:sizeof(hostLength)];
	[data appendData:hostData];

	UInt16 pointer = 0xC000 | XMPPSRVResolverTestOffsetOfLabel(XMPPSRVResolverTestSRVName, @"example");
	XMPPSRVResolverTestAppendUInt16(data, pointer);
}

static NSData *XMPPSRVResolverTestResponse(UInt16 queryID, UInt16 flags, NSArray<NSDictionary *> *srvRecords)
{
	NSMutableData *data = [NSMutableData data];

	XMPPSRVResolverTestAppendUInt16(data, queryID);
	XMPPSRVResolverTestAppendUInt16(data, flags);
	XMPPSRVResolverTestAppendUInt16(data, 1);
	XMPPSRVResolverTestAppendUInt16(data, (UInt16)[srvRecords count]);
	XMPPSRVResolverTestAppendUInt16(data, 0);
	XMPPSRVResolverTestAppendUInt16(data, 0);

	XMPPSRVResolverTestAppendName(data, XMPPSRVResolverTestSRVName);
	XMPPSRVResolverTestAppendUInt16(data, 33);
	XMPPSRVResolverTestAppendUInt16(data, 1);

	for (NSDictionary *record in srvRecords)
	{
		XMPPSRVResolverTestAppendUInt16(data, 0xC00C);
		XMPPSRVResolverTestAppendUInt16(data, 33);
		XMPPSRVResolverTestAppendUInt16(data, 1);
		XMPPSRVResolverTestAppendUInt32(data, 60);

		NSMutableData *rdata = [NSMutableData data];
		XMPPSRVResolverTestAppendUInt16(rdata, [record[@"priority"] unsignedShortValue]);
		XMPPSRVResolverTestAppendUInt16(rdata, [record[@"weight"] unsignedShortValue]);
		XMPPSRVResolverTestAppendUInt16(rdata, [record[@"port"] unsignedShortValue]);
		XMPPSRVResolverTestAppendCompressedExampleTarget(rdata, record[@"target"]);

		XMPPSRVResolverTestAppendUInt16(data, (UInt16)[rdata length]);
		[data appendData:rdata];
	}

	return data;
}

static UInt16 XMPPSRVResolverTestQueryIDFromRequest(NSURLRequest *request)
{
	NSData *body = request.HTTPBody;
	const UInt8 *bytes = [body bytes];
	return ((UInt16)bytes[0] << 8) | bytes[1];
}

static void XMPPSRVResolverTestRespondWithDNSMessage(NSURLRequest *request,
                                                     id<NSURLProtocolClient> client,
                                                     NSURLProtocol *protocol,
                                                     NSData *data)
{
	NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:request.URL
	                                                          statusCode:200
	                                                         HTTPVersion:@"HTTP/1.1"
	                                                        headerFields:@{@"Content-Type": @"application/dns-message"}];
	[client URLProtocol:protocol didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
	[client URLProtocol:protocol didLoadData:data];
	[client URLProtocolDidFinishLoading:protocol];
}

@interface XMPPSRVResolverTests : XCTestCase

@end

@implementation XMPPSRVResolverTests

- (void)tearDown
{
	[XMPPSRVResolverMockURLProtocol setRequestHandler:nil];
	[super tearDown];
}

- (void)testParsesValidDoHSRVResponseWithMultipleRecords
{
	UInt16 queryID = 0x1234;
	NSData *response = XMPPSRVResolverTestResponse(queryID, 0x8000, @[
		@{@"priority": @20, @"weight": @5, @"port": @5223, @"target": @"xmpp2.example.com"},
		@{@"priority": @10, @"weight": @7, @"port": @5222, @"target": @"xmpp1.example.com"}
	]);

	NSArray<XMPPSRVRecord *> *records = [XMPPSRVResolver xmpp_SRVRecordsFromDNSMessage:response queryID:queryID];

	XCTAssertEqual([records count], 2U);
	XCTAssertEqual(records[0].priority, 20);
	XCTAssertEqual(records[0].weight, 5);
	XCTAssertEqual(records[0].port, 5223);
	XCTAssertEqualObjects(records[0].target, @"xmpp2.example.com");
	XCTAssertEqual(records[1].priority, 10);
	XCTAssertEqual(records[1].weight, 7);
	XCTAssertEqual(records[1].port, 5222);
	XCTAssertEqualObjects(records[1].target, @"xmpp1.example.com");
}

- (void)testRejectsMalformedDoHResponse
{
	NSData *malformedResponse = [@"abc" dataUsingEncoding:NSASCIIStringEncoding];

	NSArray<XMPPSRVRecord *> *records = [XMPPSRVResolver xmpp_SRVRecordsFromDNSMessage:malformedResponse queryID:0x1234];

	XCTAssertNil(records);
}

- (void)testRejectsDoHResponseWithUnsupportedRCode
{
	NSData *response = XMPPSRVResolverTestResponse(0x1234, 0x8003, @[]);

	NSArray<XMPPSRVRecord *> *records = [XMPPSRVResolver xmpp_SRVRecordsFromDNSMessage:response queryID:0x1234];

	XCTAssertNil(records);
}

- (void)testMockedDoHSuccessResolvesRecordsWithoutSystemFallback
{
	XCTestExpectation *expectation = [self expectationWithDescription:@"DoH success resolves records"];
	XMPPSRVResolverDelegateRecorder *delegate = [XMPPSRVResolverDelegateRecorder new];
	delegate.expectation = expectation;

	dispatch_queue_t resolverQueue = dispatch_queue_create("XMPPSRVResolverTests.success", DISPATCH_QUEUE_SERIAL);
	XMPPSRVResolverFallbackSpy *resolver = [[XMPPSRVResolverFallbackSpy alloc] initWithDelegate:delegate
	                                                                              delegateQueue:dispatch_get_main_queue()
	                                                                              resolverQueue:resolverQueue];
	[resolver setDohProviderURLs:@[[NSURL URLWithString:@"https://resolver.test/dns-query"]]];
	[resolver setDohURLSessionProtocolClasses:@[[XMPPSRVResolverMockURLProtocol class]]];

	[XMPPSRVResolverMockURLProtocol setRequestHandler:^(NSURLRequest *request, id<NSURLProtocolClient> client, NSURLProtocol *protocol) {

		XCTAssertEqualObjects([request valueForHTTPHeaderField:@"Content-Type"], @"application/dns-message");
		XCTAssertEqualObjects([request valueForHTTPHeaderField:@"Accept"], @"application/dns-message");

		UInt16 queryID = XMPPSRVResolverTestQueryIDFromRequest(request);
		NSData *response = XMPPSRVResolverTestResponse(queryID, 0x8000, @[
			@{@"priority": @20, @"weight": @0, @"port": @5223, @"target": @"xmpp2.example.com"},
			@{@"priority": @10, @"weight": @0, @"port": @5222, @"target": @"xmpp1.example.com"}
		]);

		XMPPSRVResolverTestRespondWithDNSMessage(request, client, protocol, response);
	}];

	[resolver startWithSRVName:XMPPSRVResolverTestSRVName timeout:5.0];

	[self waitForExpectationsWithTimeout:2.0 handler:nil];

	XCTAssertNil(delegate.error);
	XCTAssertEqual([delegate.records count], 2U);
	XCTAssertEqual(delegate.records[0].priority, 10);
	XCTAssertEqualObjects(delegate.records[0].target, @"xmpp1.example.com");
	XCTAssertEqual(delegate.records[1].priority, 20);
	XCTAssertEqualObjects(delegate.records[1].target, @"xmpp2.example.com");
	XCTAssertEqual(resolver.startSystemResolverCount, 0U);
}

- (void)testAllDoHProvidersFailingStartsSystemFallbackExactlyOnce
{
	XCTestExpectation *expectation = [self expectationWithDescription:@"System fallback starts"];
	XMPPSRVResolverDelegateRecorder *delegate = [XMPPSRVResolverDelegateRecorder new];
	dispatch_queue_t resolverQueue = dispatch_queue_create("XMPPSRVResolverTests.fallback", DISPATCH_QUEUE_SERIAL);
	XMPPSRVResolverFallbackSpy *resolver = [[XMPPSRVResolverFallbackSpy alloc] initWithDelegate:delegate
	                                                                              delegateQueue:dispatch_get_main_queue()
	                                                                              resolverQueue:resolverQueue];
	resolver.fallbackExpectation = expectation;
	[resolver setDohProviderURLs:@[
		[NSURL URLWithString:@"https://resolver-one.test/dns-query"],
		[NSURL URLWithString:@"https://resolver-two.test/dns-query"],
		[NSURL URLWithString:@"https://resolver-three.test/dns-query"]
	]];
	[resolver setDohURLSessionProtocolClasses:@[[XMPPSRVResolverMockURLProtocol class]]];

	__block NSUInteger requestCount = 0;
	[XMPPSRVResolverMockURLProtocol setRequestHandler:^(NSURLRequest *request, id<NSURLProtocolClient> client, NSURLProtocol *protocol) {

		(void)request;
		requestCount++;
		NSError *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:nil];
		[client URLProtocol:protocol didFailWithError:error];
	}];

	[resolver startWithSRVName:XMPPSRVResolverTestSRVName timeout:5.0];

	[self waitForExpectationsWithTimeout:2.0 handler:nil];
	dispatch_sync(resolverQueue, ^{
		[resolver startSystemResolver];
	});

	XCTAssertEqual(requestCount, 3U);
	XCTAssertEqual(resolver.startSystemResolverCount, 1U);
	[resolver stop];
}

@end
