# RSA Public-Key Encryption and Signature Lab

**Authors (Group 5):**
- Diogo Rodrigues up201806429
- Pedro Azevedo up201603816
- Rui Pinto up201806441

This week's suggested lab was RSA (Rivest-Shamir-Adleman) Public-Key Encryption and Signature Lab, from SEED labs, with the intent of providing us with a better understanding of how this algorithm works and how it is implemented.

# Introduction

In this lab, we seek to gain hands-on experience with the RSA algorithm. Besides that, this lab covers the following topics:

- Public-key cryptography.
- The RSA algorithm and key generation.
- Big number calculation.
- Encryption and Decryption using RSA.
- Digital signature.
- X.509 certificate.

## Background

Typically, the RSA algorithm involves computations on large numbers. And these computations involve more than 32-bit or 64-bit numbers. Most of the time, these numbers are more than 512 bits long. To perform arithmetic operations in these numbers we'll use the Big Number library provided by *OpenSSL* that has an API that enables us to do those computations. We were presented a simple script where three `BIGNUM` variables, a, b, and n are initialized, and we compute `a * b` and `a^b mod n`. The script is as follows:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
    
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *res = BN_new();

    // Initialize a, b, n
    BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
    BN_dec2bn(&b, "273489463796838501848592769467194369268");
    BN_rand(n, NBITS, 0, 0);
    
    // res = a*b
    BN_mul(res, a, b, ctx);
    printBN("a * b = ", res);
    
    // res = aˆb mod n
    BN_mod_exp(res, a, b, n, ctx);
    printBN("a^c mod n = ", res);
    
    return 0;
}
```

When compiling and running the script, we get the following result:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc bn_sample.c -o bn_sample -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./bn_sample     
a * b =  A5A38F6F914CFDDEDF9998C401C6AC24230A6D011DA777D53832FE24CDBCAF8C1B9DB466B3D69BC82E6B88B88F30C2BC
a^c mod n =  3BEEB779B28C81F2B160DB875CB980896C07E18C7E8BF51E05D26D0D2107AFA7
```

Indeed, the results of the computations are much larger than 32-bit or 64-bit numbers!

# Tasks

# Task 1

In the first task we are asked to derive the private key of RSA given the `p`, `q`, and `e` prime numbers, such that `n = p * q` and `(e, n)` is the public key. `n` is the so-called modulus, `e` is the public key exponent, and the private key (exponent) is `d`. The RSA key generation process works as follows:
- Choose two large random prime numbers, `p` and `q`.
- Compute `n = p * q`. This number is the modulus for the public key and private key. To be secure, `n` needs to be large. In our task, we already have `p` and `q`, so we can calculate `n`.
- Select an integer `e`, such that `1 < e < ¢(n)`, and `e` is relatively prime to `¢(n)`, meaning the greatest common divisor (gcd) of `e` and `¢(n)` is one. This number is called the public key exponent, and it is made public. This number does not need to be large; in practice, many public keys choose `e = 65537`, which is a prime number. In practice, we find `e` first, and then generate `p` and `q`. If `¢(p * q)` and `e` are not relatively prime, we will pick another `p` and/or `q`, until the condition is met. Also, it's important to note that this `¢(n)` is Euler's totient function and counts the positive integers up to a given integer `n` that are relatively prime to `n`.
- Lastly, we find `d`, such that `e * d mod ¢(n) = 1`. We can use the extended Euclidean algorithm to get `d`. This number is called the private key exponent, and it is kept a secret.

Knowing the three prime numbers we were given, we can find the value of `d`. Even given `e` and `n` it is possible to get `p` and `q`, but factoring a large number is a difficult problem, and there's no efficient way to do that yet. Factoring a 2048-bit number is considered infeasible using today's computer power. It is based on this that the RSA algorithm security stands.

Note the way `¢(n)` is calculated is as follows:

`¢(n) = ¢(p) * ¢(q) = (p - 1) * (q - 1)`

Also, for the equation `e * d mod ¢(n) = 1` used in RSA, it comes from the calculation of the greatest common divisor:

`a * x + b * y = gcd(a, b)`

Substituting the right arguments:

`e * d + ¢(n) * y = gcd(e, ¢(n)) = 1`

Dividing everything by `mod ¢(n)`, we get:

`e * d mod ¢(n) = 1`

To solve this task we used the following C script that does the described operations:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *p_minus_one = BN_new();
    BIGNUM *q_minus_one = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *res = BN_new();

    // Initialize p, q, e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // Compute p - 1 and q - 1
    BN_sub(p_minus_one, p, BN_value_one()); 
    BN_sub(q_minus_one, q, BN_value_one()); 
    
    // n = p * q
    BN_mul(n, p, q, ctx);

    // Compute ¢(n)
    BN_mul(phi, p_minus_one, q_minus_one, ctx);

    // Check if e and ¢(n) are relatively prime (i.e. gcd(e, ¢(n)) = 1)
    BN_gcd(res, phi, e, ctx);
    if (!BN_is_one(res)) {
        exit(0);
    } 

    // Compute the private key exponent d solving this equation: e * d mod ¢(n) = 1
    BN_mod_inverse(d, e, phi, ctx);

    printBN("d = ", d);

    return 0;
}
```

Compiling and running it, we get `d` as the private key:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task1.c -o task1 -lcrypto
                                                                                                                    
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task1                      
d =  3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB
```

## Task 2

For this task, given the public key `(e, n)`, the decryption key `d` for verification purposes, and a message "A top secret!" we need to encrypt this message using the RSA algorithm.

First, we convert our message to hexadecimal format:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print("A top secret!".encode("utf-8").hex())'
4120746f702073656372657421
```

The output is `4120746f702073656372657421`, as can be seen.

With this in mind, we developed a script that takes the aforementioned values and encrypts our message using the equation `c = m^e mod n` and also decrypts it for verification purposes using the equation `m = c^d mod n`. The script is as follows:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *new_m = BN_new();

    // Initialize n, m, e, d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&m, "4120746f702073656372657421");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // Encryption: Calculate m^e mod n
    BN_mod_exp(c, m, e, n, ctx);
    printBN("Encryption: ", c);

    // Decryption: Calculate c^d mod n (Verification)
    BN_mod_exp(new_m, c, d, n, ctx);
    printBN("Decryption: ", new_m);

    return 0;
}
```

Compiling and running it:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task2.c -o task2 -lcrypto
                                                                                                                    
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task2
Encryption:  6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC
Decryption:  4120746F702073656372657421
```

We can indeed see the encrypted message being `6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC` in hexadecimal format and the decrypted message being `4120746F702073656372657421` which is exactly what we obtained using that short python line at the beginning of this task.

## Task 3

In this task, contrary to what we were asked in the previous task we have to decrypt a message. Using the parameters `n`, `e` and `d` given, and knowing the ciphertext `c` is `8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F`, we just need to use the formula `c^d mod n` and we get the decrypted text according to the RSA algorithm. For this, we developed a C script that takes the given arguments and calculates the decrypted text in hexadecimal format. The script is as follows:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();

    // Initialize n, c, e, d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Decryption: Calculate c^d mod n
    BN_mod_exp(m, c, d, n, ctx);
    printBN("Decryption: ", m);

    return 0;
}
```

Compiling and running:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task3.c -o task3 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task3                      
Decryption:  50617373776F72642069732064656573
```

As it can be seen the decrypted text in hexadecimal format is `50617373776F72642069732064656573`. Converting this to ASCII format can be done using the following python code:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print(bytearray.fromhex("50617373776F72642069732064656573").decode())'
Password is dees
```

The deciphered text is "Password is dees".

## Task 4

In this task, we are asked to sign a message. Note that this signature should be directly applied to the message and not to its hash value, as it's commonly done due to the long dimension that some messages might have. For a message `m` that needs to be signed, we need to follow the equation `s = m^d mod n` using our private key `d`, and `s` will serve as our signature on the message.

For the message "I owe you $2000." we first need to convert it to hexadecimal format:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print("I owe you $2000.".encode("utf-8").hex())'
49206f776520796f752024323030302e
```

Then, we developed the following C script to achieve sign the message. Note that the parameters in use are the same as in task 2.

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();

    // Initialize n, d, e, m
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&m, "49206f776520796f752024323030302e");

    // Signature: Calculate m^d mod n
    BN_mod_exp(s, m, d, n, ctx);
    printBN("Signature: ", s);

    return 0;
}
```

Compiling and running it:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task4.c -o task4 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task4                                                    
Signature:  55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB
```
The signature obtained is `55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB`.

If we instead change the message `m` to "I owe you $3000." the result would be as follows. First, we convert the message to hexadecimal format:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print("I owe you $3000.".encode("utf-8").hex())'
49206f776520796f752024333030302e
```

Changing the previous script in the line of the initialization of the `m` variable to:

```c
BN_hex2bn(&m, "49206f776520796f752024333030302e");
```

And compiling and running the script again:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task4.c -o task4 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task4
Signature:  BCC20FB7568E5D48E434C387C06A6025E90D29D848AF9C3EBAC0135D99305822
```

We get this new signature: `BCC20FB7568E5D48E434C387C06A6025E90D29D848AF9C3EBAC0135D99305822` which is completely different from the previous one, as expected. A slight change in the message produces a different signature.

## Task 5

In this task, we are asked to verify a signature given an original message "Launch a missile.". Knowing the parameters `e` and `n`, part of the RSA public key and the signature value obtained using an unknown private key we can verify that the signature `643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F` comes from the message "Launch a missile." using the public key. 

First, we calculate the hexadecimal format of the given message:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print("Launch a missile.".encode("utf-8").hex())'
4c61756e63682061206d697373696c652e
```

After that, we developed a C script that calculates `s^e mod n`. The result is the content of the original message before being signed. If this result matches the output of the "Launch a missile." in hexadecimal format, then we can firmly state that the signature matches! To prove that, we developed another C script:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *new_m = BN_new();

    // Initialize n, d, e, m
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");

    // Verify Signature: Calculate s^e mod n
    BN_mod_exp(new_m, s, e, n, ctx);
    printBN("Signature Verification : ", new_m);

    if(BN_cmp(m, new_m) == 0)
        printf("Signature matches!");
    else 
        printf("Signature doesn't match!");

    return 0;
}
```

Compiling and running it:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task5.c -o task5 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task5                      
Signature Verification :  4C61756E63682061206D697373696C652E
Signature matches!
```

We can see that the signature matches!

If we modified the signature one small bit such that the last byte was `3F` instead of `2F` then our obtained message wouldn't match the original message, as the signature would become invalid. To verify this we only change the initialization of the variable `s` in the previous script to:

```c
BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
```

And then we compile and run the program again:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task5.c -o task5 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task5                      
Signature Verification :  91471927C80DF1E42C154FB4638CE8BC726D3D66C83A4EB6B7BE0203B41AC294
Signature doesn't match!
```

The obtained message `91471927C80DF1E42C154FB4638CE8BC726D3D66C83A4EB6B7BE0203B41AC294` is very different from the original one `643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F`, thus we can state that after aplying the RSA public key on the signature, we get a block of data that is significantly different from the original one.