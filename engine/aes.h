#ifndef _AES_H
#define _AES_H

#define uint8  unsigned char
#define uint32 unsigned long int

typedef struct aes_context
{
    int nr;             /* number of rounds      */
    uint32 erk[64];     /* encryption round keys */
    uint32 drk[64];     /* decryption round keys */
} aes_context;

int  aes_set_key( struct aes_context *ctx, uint8 *key, int nbits );
void aes_encrypt( struct aes_context *ctx, uint8 data[16] );
void aes_decrypt( struct aes_context *ctx, uint8 data[16] );

#endif /* aes.h */

