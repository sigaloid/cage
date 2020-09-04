# cage
age, but c#


Beginner's guide: run the program. Self tests will run, ensuring the code is working. Press 1 to generate a key, 2 to encrypt with someone's public key, 3 to decrypt with a private key, and 4 to run extended self tests. (If you generate a key, it will be saved in memory until the program is closed. save your private key somewhere important!)

Crypto info: ChaCha20-Poly1305 cipher (https://blog.cloudflare.com/it-takes-two-to-chacha-poly/), X25519 for shared keys (https://en.wikipedia.org/wiki/Curve25519)


Public cage v1 keys start with cagepub1, private cage keys start with cageprv1. The key format is RAW, so there is no error checking nor X25519 key checking. NSec/PKix keys are larger than raw, and key size is an important factor. 

Vanity keys will take a while to generate and are not case-sensitive. Anywhere up to 4 characters is reasonable. 

To do: 

add function to get public key from private key

switch to X448 (more strength)

allow for encrypting files 

Want to write me a message? My public key is cagepub1SgLd8hoQuKxSHgkBXlqdsFRVzJL/zcS2JKhlnehYEno=
