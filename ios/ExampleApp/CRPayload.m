//
//  CRPayload.m
//  ExampleApp
//
//  Created by Jakob Jensen on 08/06/14.
//
//

#import "CRPayload.h"
#import "NSData+Base64.h"

@implementation CRPayload

+ (NSString *)encryptRSA:(NSString *)plainTextString key:(SecKeyRef)publicKey
{
	size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
	uint8_t *cipherBuffer = malloc(cipherBufferSize);
	uint8_t *nonce = (uint8_t *)[plainTextString UTF8String];
	SecKeyEncrypt(publicKey,
                  kSecPaddingOAEP,
                  nonce,
                  strlen( (char*)nonce ),
                  &cipherBuffer[0],
                  &cipherBufferSize);
	NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
	return [encryptedData base64EncodedString];
}

+ (NSString *)decryptRSA:(NSString *)cipherString key:(SecKeyRef)privateKey
{
	size_t plainBufferSize = SecKeyGetBlockSize(privateKey);
	uint8_t *plainBuffer = malloc(plainBufferSize); NSData *incomingData = [NSData dataFromBase64String:cipherString];
	uint8_t *cipherBuffer = (uint8_t*)[incomingData bytes];
	size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
	SecKeyDecrypt(privateKey,
                  kSecPaddingOAEP,
                  cipherBuffer,
                  cipherBufferSize,
                  plainBuffer,
                  &plainBufferSize);
	NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
	NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    return decryptedString;
}

@end
