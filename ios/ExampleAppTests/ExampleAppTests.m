//
//  ExampleAppTests.m
//  ExampleAppTests
//
//  Created by Jakob Jensen on 08/06/14.
//
//

#import <XCTest/XCTest.h>
#import "CRPayload.h"

@interface ExampleAppTests : XCTestCase

@end

@implementation ExampleAppTests

- (void)testExample
{
    NSString *resourcePath;

    resourcePath = [[NSBundle mainBundle] pathForResource:@"private_p12" ofType:@"p12"];
    NSData *p12Data = [NSData dataWithContentsOfFile:resourcePath];

    resourcePath = [[NSBundle mainBundle] pathForResource:@"public_certificate" ofType:@"der"];
    NSData *certData = [NSData dataWithContentsOfFile:resourcePath];

    SecKeyRef public_key = [CRPayload getPublicKeyRefWithCertificateData:certData];
    SecKeyRef private_key = [CRPayload getPrivateKeyRefWithP12Data:p12Data andPassword:@""];

    NSString *data = @"stuff to encode";

    NSData *sealed = [CRPayload seal:data publicKey:public_key];

    NSString *unsealed = [CRPayload open:sealed privateKey:private_key];

    XCTAssertEqualObjects(data, unsealed, @"Whhooooot!");
}

@end
