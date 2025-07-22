# Cryptographic Attacks

Here you'll find an overview on the most common cryptographic attacks, and how you can prevent them.

## Brute Force Attacks

The brute-force attack describes an attack where the attacker tries to guess the key by trying every possible key-combination.
Assuming a key can only consist out of 4 letters, the attacker will start trying to decrypt the data using the keys 'A', 'B', 'C', 'D'... up to "ZZZZ", until it finds the desired key.
While this attack is suitable for short key lengths, it becomes nearly impossible to guess a key which consists of many different letters.
For strong keys, the attacker needs to attempt A^n key combinations until he is guaranteed to find the desired key, where A describes the size of the used Alphabet (f.E., for upper & lowercase lettes: A-Z (26) + a-z(26) => 52) and n describes the length of the key.
In order to protect against brute-force attacks, you should choose keys which are as long as possible.

## Dictionary Attacks

For dictionary attacks, the attacker tries to guess the key by iterating through a pre-existing dictionary of possible keys.
There are many pre-existing dictionaries availabe for download, containing many frequently used keys.
Dictionary attacks are suitable for shorter keys, as those are more likely to be present in leaked password databases.
In order to avoid your keys being guessed via dictionaries, you are encouraged to use long keys, consisting of different letters, numbers and symbols. Besides that, you should not re-use any of your passwords.

## Rainbow Tables

Rainbow table attacks involve the use of precomputed tables that map input values (not exclusively passwords) to hash values. Instead of repeatedly hashing potential inputs during an attack, the attacker can quickly look up the hash in a precomputed table to find the corresponding original input.
Rainbow tables offer a tradeoff between performance and storage:

- Compared to brute-force attacks, they require much less computational power.
- Compared to dictionary attacks containing a combination of nearly every single possible key, they demand much less storage.
- To prevent rainbow table attacks, you should use techniques such as salting. Salting involves adding random data to the password before hashing it. The salt should be changed regulary, ideally after each password.
  That way, rainbow tables become useless, as the hash of the password cannot directly lead to the original password.

## Side-Channel Attacks

Side-channel attacks focus on exploiting information leaked during the execution of cryptographic algorithms. This could include timing information, power consumption, or electromagnetic radiation.
By analyzing these side-channel leaks, an attacker may gain insights into the cryptographic keys being used.
To defend against side-channel attacks, cryptographic implementations should be designed with countermeasures.
This might involve constant-time algorithms that do not reveal information through timing variations.
