
***

### 6. `/docs/crypto-rsa-attack/index.md`

```markdown
---
title: RSA Weak Key Exploitation
tags: [Crypto, CTF, Mathematics]
description: A breakdown of low-exponent RSA key recovery using modular arithmetic.
date: 2025-10-31
---

## Introduction to RSA
RSA (Rivest–Shamir–Adleman) is a widely used public-key cryptosystem. It relies on the computational difficulty of factoring large integers, which are the product of two large prime numbers.

**Key Components:**
*   **Public Key:** $(n, e)$ where $n = p \times q$ (modulus) and $e$ (public exponent).
*   **Private Key:** $(d)$ where $d \times e \equiv 1 \pmod{\phi(n)}$ and $\phi(n) = (p-1)(q-1)$.

Encryption: $C = M^e \pmod n$
Decryption: $M = C^d \pmod n$

### Attack Scenario: Small Public Exponent (e)
A common weak configuration in RSA is using a very small public exponent, such as $e=3$. While not inherently insecure on its own, it can become problematic when combined with other weaknesses, especially small messages ($M$).

If $M^e < n$, then $M^e \pmod n = M^e$. In such cases, if $e$ is small, we can simply calculate the $e$-th root of $C$ to recover $M$. This is known as the **Broadcast Attack** or **Hastad's Broadcast Attack** when multiple recipients share the same $e$.

Consider a message $M$ encrypted with $e=3$:
$C = M^3 \pmod n$

If $M^3 < n$, then $C = M^3$. We can find $M$ by simply calculating the cubic root of $C$:
$M = \sqrt[3]{C}$

This is trivial to break.

![RSA Chart](rsa-chart.png)
*A flowchart demonstrating the RSA encryption and decryption process, highlighting key generation steps.*

### Coppersmith's Attack (Small Private Exponent)
Another type of weak key exploitation involves a small private exponent $d$. If $d$ is small enough (approximately $N^{0.292}$), it can be recovered using Coppersmith's method, which leverages lattice reduction algorithms to find small roots of polynomial equations modulo $N$.

The extended Euclidean algorithm gives us:
$e \times d - k \times \phi(n) = 1$
Substituting $\phi(n) = n - p - q + 1$, we get:
$e \times d - k(n - p - q + 1) = 1$

If $d$ is small, then $k$ is also likely small. Coppersmith's method forms a polynomial $f(x, y) = e \cdot d - k \cdot (n - x - y + 1) - 1 = 0$ modulo $n$, and finds small roots.

### Practical Implications in CTFs
In Capture The Flag (CTF) challenges, attackers often encounter RSA problems where one of these weaknesses is intentionally introduced. For instance:

*   **Given multiple ciphertexts for the same message with different public keys but the same small $e$**: Hastad's Broadcast Attack.
*   **Given $n, e, c$ and knowing $e$ is small, check if $c < n$**: Straight cube root attack.
*   **Given $n, e, c$ and knowing $d$ is small**: Coppersmith's attack (often requires a specialized tool like `RsaCtfTool` or implementing lattice reduction).

### Conclusion
RSA's security heavily relies on the large prime factors of $n$ and appropriate key generation parameters. Using small exponents without careful consideration of other parameters can lead to critical vulnerabilities that allow for the efficient recovery of the plaintext or private key. Always use sufficiently large and randomly generated $p$ and $q$, and ensure exponents meet security recommendations.