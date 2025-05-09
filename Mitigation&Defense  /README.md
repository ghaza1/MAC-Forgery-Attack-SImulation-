<p align="center">
    <img src="https://capsule-render.vercel.app/api?type=waving&height=200&color=gradient&text=MD5%20Length%20Extension%20Attack%20Demo&fontAlignY=40&fontSize=40&fontColor=ffffff" alt="Title Banner"/>
</p>  
<p align="center">
    <img src="https://img.shields.io/badge/Made%20With-Python-blue?style=for-the-badge&logo=python&logoColor=white"/>

</p>

# 🔓 MD5 Length Extension Attack Demo

This project demonstrates a **length extension attack** on a custom MAC implementation using the insecure `H(secret || message)` pattern with **MD5**.

## ⚠️ Disclaimer
This is for **educational purposes only**. Do not use this insecure MAC pattern in any real applications.
### **Task 1: Background Study**
## 🔐 Secure Length Extension Attack Demo

### Overview

This project demonstrates why using **insecure constructions like `MD5(secret || message)`** for MACs is dangerous, and how switching to **HMAC (e.g., `HMAC-MD5`)** defeats length extension attacks.

---

## 💡 Objective

* Simulate a server generating secure MACs using `HMAC-MD5`.
* Attempt a length extension attack with `client.py` to forge a valid MAC.
* Confirm that the attack **fails** with HMAC but would **succeed** with insecure `MD5(key || message)`.

---

## 🛡️ HMAC Background

* `HMAC(K, M) = H((K' ⊕ opad) || H((K' ⊕ ipad) || M))`
* Immune to length extension attacks because the key is hashed *inside* the function.

---

## 📁 Files

| File        | Purpose                                     |
| ----------- | ------------------------------------------- |
| `server.py` | Simulates the secure server using HMAC-MD5  |
| `client.py` | Tries to forge a MAC using length extension |

---

## ▶️ How to Run

### Step 1: Start the Server

Run:

```bash
python3 server.py
```

Follow prompts:

1. **Input the secret key**, e.g., `YELLOW SUBMARINE` (only known to server).
2. **Input a message**, e.g.:

```bash
amount=100&to=alice
```

Server will print:

* Original message
* HMAC-MD5 MAC (valid)
* Secret key length hint (to simulate attacker info)

✅ The server then waits for an **attacker’s forged message and MAC**.

---

### Step 2: Simulate the Attack

To simulate the attacker trying to forge a new valid MAC:

> ⚠️ The client attack works **only** if the server was using `MD5(secret || message)` — which it no longer does.

Run:

```bash
python3 client.py
```

Edit `client.py` with:

* `original_message_bytes = b"amount=100&to=alice"`
* `original_mac = "<server's MAC>"`
* `secret_len = <guessed key length>` (e.g., 16)
* `data_to_append = b"&amount=1000000&to=bob"`

Client will print:

* Forged message in hex
* Forged MAC (attempted)
* Full message (original + padding + appended data)

---

### Step 3: Test Attack on Server

Paste output from `client.py` into `server.py` when prompted:

* **Forged message (hex)**
* **Forged MAC**

---

## 🔍 Example Output

### From `server.py`:

```bash
Original message: amount=100&to=alice
Generated Original HMAC-MD5 MAC: 5d41402abc4b2a76b9719d911017c592
```

### From `client.py`:

```bash
Forged message (hex): 616d6f756e743d31303026746f3d616c69636580...
Forged MAC: 9e107d9d372bb6826bd81d3542a419d6
```

### Server Verdict:

```bash
>>> ATTACK MITIGATED: Server rejected the attacker's old forged message and MAC (as expected with HMAC).
```

✅ HMAC prevented the attack.

---

## ❌ What If Server Used Insecure `MD5(key || message)`?

If the server was using naive `MD5(secret + message)` instead of HMAC:

* The attack **succeeds**.
* The server would incorrectly accept the forged message.

---

## 📚 Lessons Learned

| Construction            | Vulnerable to Length Extension? | Secure?    |  
| ----------------------- | ------------------------------- | ---------- | 
| \`MD5(secretmessage)\`  | ✅ Yes                             | ❌ No |
| `HMAC-MD5(secret, msg)` | ❌ No                            | ✅ Yes      |      
Use **HMAC** with a secure hash (SHA-256 preferred) to avoid this class of attacks.

---

## 🛡️ Recommendations

* NEVER use `MD5(secret + message)` or `SHA1(secret + message)`
* ALWAYS use standardized HMAC functions (e.g., `hmac` module in Python)
* Prefer `SHA-256` or `SHA-3` over older hashes like `MD5`

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
