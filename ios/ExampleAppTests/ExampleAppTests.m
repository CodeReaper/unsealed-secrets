//
//  ExampleAppTests.m
//  ExampleAppTests
//
//  Created by Jakob Jensen on 08/06/14.
//
//

#import <XCTest/XCTest.h>
#import "NSData+Seal.h"

@interface ExampleAppTests : XCTestCase

@end

@implementation ExampleAppTests

- (void)testSealingAndUnsealing
{
    NSString *resourcePath;

    resourcePath = [[NSBundle mainBundle] pathForResource:@"private_p12" ofType:@"p12"];
    NSData *p12Data = [NSData dataWithContentsOfFile:resourcePath];
    SecKeyRef private_key = [p12Data privateKeyRefWithPassword:@""];

    resourcePath = [[NSBundle mainBundle] pathForResource:@"public_certificate" ofType:@"der"];
    NSData *certData = [NSData dataWithContentsOfFile:resourcePath];
    SecKeyRef public_key = [certData publicKeyRef];

    NSString *string = @"makes life worth living";

    NSData *stringData = [string dataUsingEncoding:NSUTF8StringEncoding];

    NSData *sealed = [stringData sealWithPublicKey:public_key];

    NSData *unsealed = [sealed openWithPrivateKey:private_key];

    NSString *recreated = [[NSString alloc] initWithData:unsealed encoding:NSUTF8StringEncoding];

    XCTAssertEqualObjects(string, recreated, @"Recreated string should match the original.");
}

- (void)testUnsealing
{
    NSDictionary *jsonDictionary = @{@"payload":@"C8Qz+5ogNcP/yFGIZRjZvk44qHxu1U0duQSrSdqPdnfhIjs=",
                                     @"token":@"GpbIl2xnpntTbPsvdJWyJBhwWAvbkifCkz++UIAys8URlE2UAUXJH0AP6IrfI0Xh1OB6F9TTQPaNp0K2ewZL7fbe1FqZ8KA94FNgwwc5eQtVFBRwkdlkKVUr0UnaEkG5DaeFmpeR/vVX2RYQyLpd970HnMLCDpCAE/gUD9YUmhJ737dyWOdnAlAzIcDMiYXbFXUq8hIQbYPorxlvBUDcIboC2d1sypR/VOcCLeia7PfhM/vWYXlzKzKjQcixHIn/tK7pWFBkbGMxZd2fH6P5u3ZSrPy3b1T3b11a+K26ED8wUihmmxnjAUfdioWT57zoGm+PZbRDzslQacv73uSnrQ=="};

    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:jsonDictionary options:0 error:nil];

    NSString *resourcePath = [[NSBundle mainBundle] pathForResource:@"private_p12" ofType:@"p12"];
    NSData *p12Data = [NSData dataWithContentsOfFile:resourcePath];
    SecKeyRef private_key = [p12Data privateKeyRefWithPassword:@""];

    NSData *unsealed = [jsonData openWithPrivateKey:private_key];

    NSError *error = nil;
    NSDictionary *recreated = [NSJSONSerialization JSONObjectWithData:unsealed options:0 error:&error];

    XCTAssertEqualObjects(recreated[@"data"], @"makes life worth living", @"Payload should be decodeable.");
}

@end
