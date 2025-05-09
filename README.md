
<p align="center">
    <img src="https://capsule-render.vercel.app/api?type=waving&height=200&color=gradient&text=MD5%20Length%20Extension%20Attack%20Demo&fontAlignY=40&fontSize=40&fontColor=ffffff" alt="Title Banner"/>
</p>  

<p align="center">
    <img src="https://img.shields.io/badge/Made%20With-Python-blue?style=for-the-badge&logo=python&logoColor=white"/>

</p>

# **1.1. Message Authentication Codes (MACs)**

- ###  **1.1.1. Definition**
- A Message Authentication Code (MAC), also referred to as a tag, is a small block of data generated through a cryptographic process involving both the message content and a secret key.
- The MAC algorithm takes two distinct inputs: the variable-length message to be authenticated and a fixed-length secret key shared exclusively between the communicating parties.
---
- ### **1.1.2. Purpose and Significance**
    The primary functions of a MAC are to provide assurances of:
    - **Data Integrity:**
        - MACs ensure that the message has not been accidentally or maliciously altered during transit from the sender to the receiver.
        - Any modification to the message, however minor, will result in the computation of a different MAC value by the receiver, leading to a mismatch with the transmitted MAC and thus detection of the alteration.
    - **Message Authentication (Origin Authentication):**
        - MACs verify the authenticity of the message's source, confirming that it originates from the party claiming to have sent it.
        - This assurance is derived from the shared secret key; only entities possessing this key can generate a valid MAC for a given message. Successful verification implies the sender's knowledge of the key.
---
- **1.1.3. General Operational Workflow**
```mermaid
sequenceDiagram
    autonumber
    actor Sender
    actor Receiver

    Sender->>Sender: Compose message (M)
    Sender->>Sender: Compute MAC_S = Algorithm(K, M)
    Sender->>Receiver: Transmit (Message M, MAC_S)

    activate Receiver
    Receiver->>Receiver: Obtain (Message M', MAC_R)
    Receiver->>Receiver: Re-compute MAC_R' = Algorithm(K, M')
    Receiver->>Receiver: Compare received MAC_R with local MAC_R'
    alt MACs Match
        Receiver->>Receiver: Verification: OK (Integrity & Authenticity confirmed)
    else MACs Mismatch
        Receiver->>Receiver: Verification: FAILED (Message compromised. Discard/Flag)
    end
    deactivate Receiver
````

The process of using a MAC typically involves the following steps:
    - **Sender-Side Operations:**
        1. The sender composes the message.
        2. Using the pre-shared secret key and the message, the sender computes the MAC value via the agreed-upon MAC algorithm.
        3. The sender transmits the original message along with the computed MAC to the receiver.
    - **Receiver-Side Operations:**
        1. The receiver obtains the message and the accompanying MAC.
        2. Using the same shared secret key and the received message, the receiver independently re-computes the MAC value.
        3. The receiver compares its locally computed MAC with the received MAC.
    - **Verification Outcomes:**
        - **Match:** If the two MAC values are identical, the receiver can conclude with high confidence that the message's integrity is intact and its origin is authentic.
        - **Mismatch:** If the MAC values differ, the message is considered compromised (either tampered with or not from the legitimate sender) and should typically be discarded or flagged.

---

**1.2. Length Extension Attacks (LEAs)**

- **1.2.1. Introduction to Length Extension Attacks**
    - A Length Extension Attack is a type of cryptographic attack that targets certain constructions of MACs or checksums where a hash function is used in a specific (often naive) way.
    - These attacks are particularly effective against hash functions based on the Merkle–Damgård construction, such as MD5, SHA-1, and members of the SHA-2 family (e.g., SHA-256, SHA-512).
----
- **1.2.2. Mechanism of Merkle–Damgård Based Hash Functions**
    - **Iterative Processing:** These hash functions process input messages by dividing them into fixed-size blocks and iterating a compression function over these blocks.
    - **Internal State (Chaining Value):** An internal state (often initialized with a standard IV - Initialization Vector) is updated after processing each block. The output of the compression function for one block becomes the chaining value (input internal state) for the next.
    - **Final Hash Value:** The final hash output is typically the value of the internal state after all message blocks (including padding) have been processed.
----
- **1.2.3. Exploitation by Length Extension Attacks**
    - **Attacker's Knowledge and Objective:** An attacker who knows an `original_message` and its corresponding `original_MAC = H(secret_key || original_message)`, but _not_ the `secret_key` itself, can still perform this attack. The objective is to compute `H(secret_key || original_message || padding || appended_data)` for some chosen `appended_data`.
    - **Crucial Requirement: Length of the Secret Key:** The attacker must know, or be able to successfully guess, the length of the `secret_key`. This is essential for correctly calculating the `padding` that the hash function would apply to the `secret_key || original_message` segment.
----
- **1.2.4. Attack Steps Detailed**

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant "System's Hashing Process" as SystemHash

    Attacker->>Attacker: Starts with: original_message, original_MAC
    Note over Attacker,SystemHash: Attacker does NOT know the secret_key.

    Attacker->>Attacker: 1. Prepare for Attack:<br/>Treat original_MAC as an intermediate hash state.<br/>(This state is H(secret_key || original_message))

    Attacker->>Attacker: 2. Calculate Necessary Padding:<br/>Determine the padding the system would add to<br/>(secret_key || original_message) to meet block size.<br/>(Requires knowing/guessing secret_key length)

    Attacker->>Attacker: 3. Craft Malicious Extension:<br/>Choose additional data (data_to_append) to add.

    Attacker->>SystemHash: 4. Forge New MAC:<br/>Instruct hash function to process 'data_to_append',<br/>starting from the state derived from 'original_MAC'.
    activate SystemHash
    Note over Attacker,SystemHash: SystemHash effectively computes H(secret_key || original_message || padding || data_to_append)
    SystemHash-->>Attacker: Returns forged_MAC
    deactivate SystemHash

    Attacker->>Attacker: 5. Attack Complete:<br/>The forged_MAC is valid for the extended message:<br/>(original_message || padding || data_to_append).
```
    
1. **Initialize State:** The attacker uses the `original_MAC` (which is the internal state of `H(secret_key || original_message)`) as the initial state for continuing the hash computation.
2. **Determine Padding:** The attacker calculates the `padding` that the specific hash algorithm would have appended to `secret_key || original_message`. This padding ensures the data conforms to the block size requirements and usually includes the original length of the data being padded.
3. **Append Data:** The attacker appends their chosen `data_to_append` after this implicit `padding`.
4. **Compute Forged MAC:** The hash function is then run on the `data_to_append` (and any further padding necessary for this new segment), starting from the state initialized by `original_MAC`. The result is a `forged_MAC`.
5. The `forged_MAC` is a valid MAC for the extended message: `secret_key || original_message || padding || data_to_append`. The `original_message` itself is also effectively extended to `original_message || padding || data_to_append`.

---
- **1.2.5. Prerequisites for a Successful Attack**
    - The targeted MAC construction must use a Merkle–Damgård type hash function.
    - The attacker must possess a valid `(message, MAC)` pair.
    - The attacker must know the length of the original message.
    - Crucially, the attacker must know or successfully deduce the length of the `secret_key`.
---
**1.3. Insecurity of the `MAC = H(secret_key || message)` Construction**
- **1.3.1. Direct Vulnerability to Length Extension Attacks**
    - The construction `MAC = H(secret_key || message)`, often termed a "secret-prefix MAC," is inherently vulnerable to LEAs due to its direct mapping to the scenario exploited by such attacks.
---
- **1.3.2. Exposure of Hash Function's Internal State**
    - In this construction, the computed `MAC` is precisely the final internal state of the hash function after processing the concatenated `secret_key || message`.
    - This "leakage" of the internal state allows an attacker to effectively resume the hash computation from that point, appending new data and calculating a corresponding valid MAC.
----
- **1.3.3. Hash Functions vs. Secure MAC Algorithms**
    - **Design Goals:** Standard cryptographic hash functions are primarily designed for properties like preimage resistance, second-preimage resistance, and collision resistance. They are not intrinsically designed to function as secure MACs.
    - **MAC Security Requirements:** Secure MAC algorithms have additional requirements, notably resistance to existential forgery, meaning an attacker should not be able to generate a valid MAC for any new message (not previously seen with a MAC) without possessing the secret key. The `H(secret_key || message)` construction fails this under LEA conditions.
----
- **1.3.4. The Critical Flaw: Placement of the Secret Key**
    - Prepending the secret key (`secret_key || message`) is the fundamental weakness. Once the `secret_key` has been processed as part of the initial blocks, its cryptographic contribution is encapsulated in the internal state. If this state (the MAC) is known, the secret's initial protection is effectively bypassed for extension purposes.
---
- **1.3.5. Conclusion on Insecurity**
    - In summary, the `MAC = H(secret_key || message)` construction is cryptographically insecure because it reveals the final internal state of the hash function. This allows an attacker who knows this state (the MAC) and the length of the secret to append arbitrary data to the original message and compute a valid MAC for the new, extended message, thereby compromising both data integrity and authenticity without ever needing to know the actual secret key.
---

## 📬 Connect with Me  

<p align="center">
    <a href="mailto:aghazal085@gmail.com">
        <img src="https://img.shields.io/badge/Email-Contact%20Me-red?style=for-the-badge&logo=gmail&logoColor=white"/>
    </a>
    <a href="https://www.linkedin.com/in/ahmedghaza1" target="_blank">
        <img src="https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin&logoColor=white"/>
    </a>
</p>  

---

<p align="center">
    <img src="https://capsule-render.vercel.app/api?type=waving&height=150&color=gradient&section=footer" alt="Footer">
</p>  




