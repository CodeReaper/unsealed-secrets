//
//  CRPayload.h
//  ExampleApp
//
//  Created by Jakob Jensen on 08/06/14.
//
//

#import <Foundation/Foundation.h>

@interface CRPayload : NSObject

+ (NSData *)seal:(NSString *)string publicKey:(SecKeyRef)publicKey;
+ (NSString *)open:(NSData *)sealed privateKey:(SecKeyRef)privateKey;

+ (SecKeyRef)getPublicKeyRefWithCertificateData:(NSData *)certData;
+ (SecKeyRef)getPrivateKeyRefWithP12Data:(NSData *)p12Data andPassword:(NSString *)password;

@end
