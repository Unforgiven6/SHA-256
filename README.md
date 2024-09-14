# SHA-256
**Secure Hash Algorithm 256-bit**: A cryptographic method of converting input data of any kind and size, into a string of fixed number of characters (256 bits). Allowed input data range: 2<sup>64</sup> bits.

The data process of SHA-256 is shown below:

<p align="center">
  <img src="https://github.com/user-attachments/assets/3f5fe919-3d61-4bf1-a9c8-c53eeae42bc2" />
</p>

The goal of the project is to create a hash algorithm that converts any input data up to **2<sup>64</sup> bits** into a fixed bit hashed output.

The input can be a word, a sentence, password, images, mp3 files, etc.

**Main properties for properly secured hashing:**

- *Compression*

Regardless the size of input bits, output should be fixed # of characters.

- *Avalanche Effect*

Minimal changes causes drastical change in output.
Prevention of hackers from predicting the output hash value by trial and error method.

- *Determinism*

Same input will produce same output despite using different systems, for all systems that understand hashing algorithm.

- *Pre-Image Resistant (One Way Function)*

Retrieval of input data using output ought to be impossible. No algorithm to reverse the hashing process.

- *Efficient (Quick Computation)*

The program should be a fast process without the needs of heavy machine power usage.

- *Collision Resistance*

Since input can have a large range of combinations and output is a fixed amount of characters, hashing into the same output values from different input can rarely occur (like the birthday problem).

To avoid hackers taking advantage of this collision error, extend the output length to be large enough so the "birthday problem" will be computationally infeasible.

**Applications:**

- Verifying File Integrity
- Storing and Validating Password

