/*:
# Generating a key from a password

> **WARNING: Do not do this lightly. Let RNCryptor convert keys to passwords for you. That's why
> it's here. Correct use of salts is critical. If you do not have time to read this and learn how
> to correctly choose a salt, then you shouldn't be trying to generate keys on your own. Do not
> just copy random pieces of code from this playground.**

Keys are random byte sequences of a specific length. Passwords are not keys. They're not random at all, 
and they can be a wide variety of lengths.

Converting a password to a key is done by a Key Derivation Function (KDF). The output of a 
correctly-used KDF is indistinguishable from random bytes. The RNCryptor v3 KDF combines a "salt"
(explained below) and a password to generate a key. This is an expensive operation (tens of
milliseconds). That's on purpose. Passwords are easily guessed. The goal of a KDF is to make guessing 
them very expensive.

Since the KDF is expensive, if you have many messages to encrypt or decrypt, it may not be
practical to re-generate the keys for every message. Instead, you can generate the keys one time
and use them for many messages. Doing that correctly is the point of this playground.

The KDF works by combining the salt and the password, and then hashing the result many times in a
special way that is hard to do in parallel. Each salt+password combination will result in a unique key.
Without a salt, an attacker could simply apply the KDF to many common passwords, and then quickly
test those keys against messsages. To avoid this, either the password must be highly random or the
salt must be highly random.

This gives us three major scenarios:

* Human generated passwords
* Random keys
* Random passwords
*/
import Foundation
import RNCryptor

/*: 
## Human generated passwords

Human generated passwords are terrible, but they're probably why you're reading this playground.
The only way to save them from themselves is to add a unique random salt. You keep store these
salts along with the message so you can reconstruct the key later. RNCryptor does this automatically
when you use passwords, but if you bypass that, you must store the salts yourself somewhere else.
Usually you would put an envelope around the RNCryptor output that included the salts.
*/

_ = {
    let password = "password" // Humans are terrible at picking passwords
    let message = Data("Attack at dawn".utf8)

    // Encrypting
    let ciphertext: Data = {
        func randomSaltAndKeyForPassword(password: String) -> (salt: Data, key: Data) {
            let salt = RNCryptor.randomData(ofLength: RNCryptor.FormatV3.saltSize)
            let key = RNCryptor.FormatV3.makeKey(forPassword: password, withSalt: salt)
            return (salt, key)
        }

        let (encryptionSalt, encryptionKey) = randomSaltAndKeyForPassword(password: password)
        let (hmacSalt, hmacKey) = randomSaltAndKeyForPassword(password: password)
        let encryptor = RNCryptor.EncryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)

        var ciphertext = Data(encryptionSalt)
        ciphertext.append(hmacSalt)
        ciphertext.append(encryptor.encrypt(data: message))
        return ciphertext
    }()

    // Decrypting
    let plaintext: Data = {
        let encryptionSaltRange = 0..<RNCryptor.FormatV3.saltSize
        let hmacSaltRange = encryptionSaltRange.upperBound..<(encryptionSaltRange.upperBound + RNCryptor.FormatV3.saltSize)
        let bodyRange = hmacSaltRange.upperBound..<ciphertext.count

        let encryptionSalt = ciphertext[encryptionSaltRange]
        let hmacSalt = ciphertext[hmacSaltRange]
        let body = ciphertext[bodyRange]

        let encryptionKey = RNCryptor.FormatV3.makeKey(forPassword: password, withSalt: encryptionSalt)
        let hmacKey = RNCryptor.FormatV3.makeKey(forPassword: password, withSalt: hmacSalt)

        return try! RNCryptor.DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)
            .decrypt(data: body)
    }()

    // Did it work? Should be true
    plaintext == message
}()

/*:
## Random keys

Random keys are the best keys. Besides being the most secure, they're also very fast because you
don't need a KDF.

Random keys are not strings. They're two `NSData` objects, 32-bytes long each. If you need to store
them in a string for some reason, then you need to encode them somehow (hex or Base64 are popular).
**A 32-character string is not a proper key! If you can type it, it has a tiny fraction of the 
entropy of random bytes of the same length.**
*/

_ = {
    // Obviously you need to store the results of these somewhere
    let encryptionKey = RNCryptor.randomData(ofLength: RNCryptor.FormatV3.keySize)
    let hmacKey = RNCryptor.randomData(ofLength: RNCryptor.FormatV3.keySize)

    let message = Data("Attack at dawn".utf8)

    // Encrypting
    let ciphertext = RNCryptor.EncryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)
        .encrypt(data: message)

    // Decrypting
    let plaintext = try! RNCryptor.DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)
        .decrypt(data: ciphertext)

    // Did it work? Should be true
    plaintext == message
}()

/*:
## Random passwords

Random passwords are random character strings rather than random bytes. They're usually a little silly.
If you're already creating a random password, why not just create a random key? It's much
more secure without requiring a KDF. But occassionally it can be useful to have something a little
shorter than a full key if you will ever have to type it (two keys are 128 hex-encoded digits).

The good news of a random password is that the salt can be static. The point of the salt is to inject
randomness. If the password is already random, that's not required. I prefer to choose different
encryption and HMAC salts. There's no attack known against reusing the same key for both, but typically
it's best not to reuse keys.
*/

_ = {
    let passwordLength = 12 // Any length is fine, but I recommend no shorter than 8. 
                            // This will be dramatically more secure than a human-chosen
                            // password of equivalent length.

    let randomPassword = RNCryptor.randomData(ofLength: passwordLength)
        .base64EncodedString()

    // At this point, you could just use this random password with RNCryptor's password-based API.
    // But if you're trying to only run the KDF one time, here's how to generate the keys with static
    // salts.

    let encryptionSalt = Data("com.example.mygreatapp.encrypt".utf8)
    let hmacSalt = Data("com.example.mygreatapp.hmac".utf8)

    /* let encryptionKey */ _ = RNCryptor.FormatV3.makeKey(forPassword: randomPassword, withSalt: encryptionSalt)
    /* let hmacKey */ _ = RNCryptor.FormatV3.makeKey(forPassword: randomPassword, withSalt: hmacSalt)

    // Encryption and decryption as with random keys
}()
