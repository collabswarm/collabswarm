# Flow

## Decrypt Change Message

```plantuml
@startuml
title Decrypt Change Message 
start
:open stream to peer
 (document);
:change source recv'd
 (document);
:decrypt
 (auth prov);
if (can decrypt?) then(yes)
  if (for any key in
      ACL_write,
      can verify?) then (yes)
    :deserialize
      (document);
    :apply remote change
      (CRDT provider);
    stop
  else (no)
    :warning;
  stop
  endif
else(no)
  :warning;
stop
endif
@enduml
```
[[plantuml](
  http://www.plantuml.com/plantuml/uml/NP6nJiGm44HxVyLqv2I-u2Wub2kXGVJ8SZONYsHjhJSvcQ_7IHo1SBFIpFFCMhuajQBpD1hrEXAkv2H7HJjOlX7UA2LRfjamSmwH64c5x0GDY4HYq7J1pHEndfxCsUqNKvZ54OJSyj3zGxgzewXsrW5Hmb9atwDnbb7TvnDq86uofPC1LhSF0iiPNvJXsM0xB-thvrsyqcCLreo5nFUvHk3804frAfOT_JTL_CzcEs9Z73E4fg24_JK7shvVFxPrVKTI-QGX6e36H6Wur9wx5VPyMv43uCxtPiKgzSjinEvVoYYVyGC0
  )]


## Change Document

```plantuml
@startuml
title Change Document 
start

if (write access?) then (yes)
:create change object;
:serialize change object;
:sign change object 
(auth prov);
:encrypt
(document key);
else(no)
endif
stop
@enduml
```

[[plantuml](
http://www.plantuml.com/plantuml/uml/RSz1hi8m30JGlK_XPNA5_iMl11S9wRGrf4aLkw1oUY8g5aWixMTBCxrQgBOjYKmiWKzpo1FuNEAs81lJsubaPFUeOk0G8rJ_FTkCp6w7UkfYHMWMZ-zokIBQ7tMAAY79yuV8bB-NJ6wjSWy6lc7txGOvrdqrSiCdpG582fUB9-H1HY9IAolrRMezNW00
  )]


References:
  https://jameshfisher.com/2017/11/02/web-cryptography-api-symmetric-encryption/
  https://www.tutorialsteacher.com/typescript/typescript-generic-class
  https://www.typescriptlang.org/docs/handbook/2/generics.html
  https://developer.mozilla.org/en-US/docs/Web/JavaScript/Typed_arrays 


#Subtle Crypo Algos

# Key type

https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey

## encrypt

https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt

### Algos for symmetric

  All symmetric algos require shared data used to encrypt and decrypt. All use underlying cipher AES (Advanced Encryption Standard):
  * CTR
  * CBC
  * GCM

> GCM does provide built-in authentication, and for this reason it's often recommended over the other two ... GCM is an "authenticated" mode, which means that it includes checks that the ciphertext has not been modified by an attacker

AesGcmParams
  * name: "AES-GCM"
  * iv: BufferSource
    * unique for every encryption operation carried out with a given key
    * 96 bits long ... from a random number generator
    * does not have to be secret, just unique: so it is OK, for example, to transmit it in the clear alongside the encrypted message
  * tagLength is optional and defaults to 128; bits of the authentication tag 

## sign

### Algos for public-key

Three of these algorithms — RSASSA-PKCS1-v1_5, RSA-PSS, and ECDSA — are public-key