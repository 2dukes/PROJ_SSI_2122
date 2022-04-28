# RSA Public-Key Encryption and Signature Lab

**Authors (Group 5):**
- Diogo Rodrigues up201806429
- Pedro Azevedo up201603816
- Rui Pinto up201806441

This week's suggested lab was RSA (Rivest-Shamir-Adleman) Public-Key Encryption and Signature Lab, from SEED labs, with the intent of providing us with a better understanding of how this algorithm works and how it is implemented.

# Introduction

In this lab we seek to gain hands-on experience on the RSA algorithm. Besides that, this lab covers the follwoing topics:

- Public-key cryptography.
- The RSA algorithm and key generation.
- Big number calculation.
- Encryption and Decryption using RSA.
- Digital signature.
- X.509 certificate.

## Background

Typically, the RSA algorithm involves computations on large numbers. And these computations involve more than 32-bit or 64-bit numbers. Most of the time, these numbers are more than 512 bits long. To perform arithmetic operations in these numbers we'll use the Big Number library provided by *openssl* that has an API that enables us to do those computations. We are presented a simple script where three `BIGNUM` variables, a, b, and n are initialized, and the we compute `a * b` and `a^b mod n`. The script is as follows:

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

In the first task we are asked to derive the private key of RSA given the `p`, `q`, and `e` prime numbers, such that `n = p * q` and `(e, n)` is the public key. `n` is the so-called modulus, `e` is the publick key exponent, and the private key (exponent) is `d`. The RSA key generation process works as follows:
- Choose two large random prime numbers, `p` and `q`.
- Compute `n = p * q`. This number is the modulus for the public key and private key. To be secure, `n` needs to be large. In our task, we already have `p` and `q`, so we can calculate `n`.
- Select an integer `e`, such that `1 < e < ¢(n)`, and `e` is relatively prime to `¢(n)`, meaning the greates common divisor (gcd) of `e` and `¢(n)` is one. This number is called public key exponent, and it is made public. This number does not need to be large; in practice, many publick keys choose `e = 65537`, which is a prime number. In practice, we find `e` first, and then generate `p` and `q`. If `¢(p * q)` and `e` are not relatively prime, we will pick another `p` and/or `q`, until the condition is met.
- Lastly, we find `d`, such that `e * d mod ¢(n) = 1`. We can use the extended Euclidean algorithm to get `d`. This number is called private key exponent, and it is kept as a secret.

Knowing the three prime number we were given, we can find the value of `d`. Even given `e` and `n` it is possible to get `p` and `q`, but factoring a large number is a difficult problem, and there's no efficient way to do that yet. Factoring a 2048-bit number is considered infeasible using today's computer power. It is based on this that the RSA algorithm security stands.

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