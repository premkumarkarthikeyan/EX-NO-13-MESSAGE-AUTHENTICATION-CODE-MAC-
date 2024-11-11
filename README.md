# EX-NO-13-MESSAGE-AUTHENTICATION-CODE-MAC

## AIM:
To implement MESSAGE AUTHENTICATION CODE(MAC)

## ALGORITHM:

1. Message Authentication Code (MAC) is a cryptographic technique used to verify the integrity and authenticity of a message by using a secret key.

2. Initialization:
   - Choose a cryptographic hash function \( H \) (e.g., SHA-256) and a secret key \( K \).
   - The message \( M \) to be authenticated is input along with the secret key \( K \).

3. MAC Generation:
   - Compute the MAC by applying the hash function to the combination of the message \( M \) and the secret key \( K \): 
     \[
     \text{MAC}(M, K) = H(K || M)
     \]
     where \( || \) denotes concatenation of \( K \) and \( M \).

4. Verification:
   - The recipient, who knows the secret key \( K \), computes the MAC using the received message \( M \) and the same hash function.
   - The recipient compares the computed MAC with the received MAC. If they match, the message is authentic and unchanged.

5. Security: The security of the MAC relies on the secret key \( K \) and the strength of the hash function \( H \), ensuring that an attacker cannot forge a valid MAC without knowledge of the key.

## Program:

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define BLOCK_SIZE 64
#define OUTPUT_SIZE 32

// SHA-256 constants and initial hash values
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTRIGHT(word,bits) (((word) >> (bits)) | ((word) << (32-(bits))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

void sha256_transform(uint32_t state[], const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i, j;

    for (i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; i++)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256(const uint8_t data[], size_t len, uint8_t hash[]) {
    uint32_t state[8] = { 
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 
    };
    uint8_t block[64] = {0};
    int i;

    while (len >= 64) {
        memcpy(block, data, 64);
        sha256_transform(state, block);
        data += 64;
        len -= 64;
    }

    memset(block, 0, sizeof(block));
    memcpy(block, data, len);
    block[len] = 0x80;
    if (len >= 56) {
        sha256_transform(state, block);
        memset(block, 0, sizeof(block));
    }

    uint64_t bits = len * 8;
    for (i = 63; i >= 56; i--, bits >>= 8)
        block[i] = bits & 0xFF;
    sha256_transform(state, block);

    for (i = 0; i < 8; i++) {
        hash[i * 4] = (state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = state[i] & 0xFF;
    }
}

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac) {
    uint8_t key_block[BLOCK_SIZE] = {0};
    uint8_t o_key_pad[BLOCK_SIZE], i_key_pad[BLOCK_SIZE];
    uint8_t temp_hash[OUTPUT_SIZE];
    int i;

    if (key_len > BLOCK_SIZE) {
        sha256(key, key_len, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    for (i = 0; i < BLOCK_SIZE; i++) {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    uint8_t inner_data[BLOCK_SIZE + data_len];
    memcpy(inner_data, i_key_pad, BLOCK_SIZE);
    memcpy(inner_data + BLOCK_SIZE, data, data_len);
    sha256(inner_data, BLOCK_SIZE + data_len, temp_hash);

    uint8_t outer_data[BLOCK_SIZE + OUTPUT_SIZE];
    memcpy(outer_data, o_key_pad, BLOCK_SIZE);
    memcpy(outer_data + BLOCK_SIZE, temp_hash, OUTPUT_SIZE);
    sha256(outer_data, BLOCK_SIZE + OUTPUT_SIZE, mac);
}

int main() {
    const char *key = "my_secret_key";
    const char *message = "This is a test message";
    uint8_t mac[OUTPUT_SIZE];

    hmac_sha256((uint8_t*)key, strlen(key), (uint8_t*)message, strlen(message), mac);

    printf("HMAC (SHA-256): ");
    for (int i = 0; i < OUTPUT_SIZE; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");

    return 0;
}
```

## Output:
![Screenshot 2024-11-04 114407](https://github.com/user-attachments/assets/ae28ce3e-bc1c-4589-b94a-ce899c76ea72)


## Result:
The program is executed successfully.
