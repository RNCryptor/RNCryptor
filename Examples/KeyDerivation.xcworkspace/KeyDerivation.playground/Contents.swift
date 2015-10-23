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
    let message = "Attack at dawn".dataUsingEncoding(NSUTF8StringEncoding)!

    // Encrypting
    let ciphertext: NSData = {
        func randomSaltAndKeyForPassword(password: String) -> (salt: NSData, key: NSData) {
            let salt = RNCryptor.randomDataOfLength(RNCryptor.FormatV3.saltSize)
            let key = RNCryptor.FormatV3.keyForPassword(password, salt: salt)
            return (salt, key)
        }

        let (encryptionSalt, encryptionKey) = randomSaltAndKeyForPassword(password)
        let (hmacSalt, hmacKey) = randomSaltAndKeyForPassword(password)
        let encryptor = RNCryptor.EncryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)

        let ciphertext = NSMutableData(data: encryptionSalt)
        ciphertext.appendData(hmacSalt)
        ciphertext.appendData(encryptor.encryptData(message))
        return ciphertext
    }()

    // Decrypting
    let plaintext: NSData = {
        let encryptionSaltRange = NSRange(location: 0, length: RNCryptor.FormatV3.saltSize)
        let hmacSaltRange = NSRange(location: NSMaxRange(encryptionSaltRange), length: RNCryptor.FormatV3.saltSize)
        let bodyRange = NSRange(NSMaxRange(hmacSaltRange)..<ciphertext.length)

        let encryptionSalt = ciphertext.subdataWithRange(encryptionSaltRange)
        let hmacSalt = ciphertext.subdataWithRange(hmacSaltRange)
        let body = ciphertext.subdataWithRange(bodyRange)

        let encryptionKey = RNCryptor.FormatV3.keyForPassword(password, salt: encryptionSalt)
        let hmacKey = RNCryptor.FormatV3.keyForPassword(password, salt: hmacSalt)

        return try! RNCryptor.DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)
            .decryptData(body)
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
    let encryptionKey = RNCryptor.randomDataOfLength(RNCryptor.FormatV3.keySize)
    let hmacKey = RNCryptor.randomDataOfLength(RNCryptor.FormatV3.keySize)

    let message = "Attack at dawn".dataUsingEncoding(NSUTF8StringEncoding)!

    // Encrypting
    let ciphertext = RNCryptor.EncryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)
        .encryptData(message)

    // Decrypting
    let plaintext = try! RNCryptor.DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey)
        .decryptData(ciphertext)

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

    let randomPassword = RNCryptor.randomDataOfLength(passwordLength)
        .base64EncodedStringWithOptions([])

    // At this point, you could just use this random password with RNCryptor's password-based API.
    // But if you're trying to only run the KDF one time, here's how to generate the keys with static
    // salts.

    let encryptionSalt = "com.example.mygreatapp.encrypt".dataUsingEncoding(NSUTF8StringEncoding)!
    let hmacSalt = "com.example.mygreatapp.hmac".dataUsingEncoding(NSUTF8StringEncoding)!

    let encryptionKey = RNCryptor.FormatV3.keyForPassword(randomPassword, salt: encryptionSalt)
    let hmacKey = RNCryptor.FormatV3.keyForPassword(randomPassword, salt: hmacSalt)

    // Encryption and decryption as with random keys
}()
