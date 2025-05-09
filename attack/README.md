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

## 🧠 Attack Summary

The server computes MACs as:

```

MD5(SECRET\_KEY || message)

```

The attacker, knowing only the original message and its MAC, can forge a **valid MAC** for a **longer message**:

```

MD5(SECRET\_KEY || original\_message || padding || attacker\_data)

````

This is possible because MD5 (and other Merkle–Damgård hashes) allow continuation from an intermediate state.

---

## 🔧 Setup

1. Ensure both `server.py` and `client.py` are in the same directory.
2. Python 3 is required.

---

## 🚀 Run Server

### Step 1: Start the server

```bash
python3 server.py
````

### Step 2: Input SECRET\_KEY

For example:

```
Enter the SECRET_KEY for the server: secret123
```

### Step 3: Input the original message

```
Enter the original message string (e.g., amount=100&to=alice): amount=100&to=alice
```

You will get output like:

```
Generated Original MAC: 382c...  <--- Attacker: Note this MAC and Secret Key Length for client.py
```

📌 Note down:

* The original message
* The original MAC
* The length of the SECRET\_KEY (`len("secret123") = 9`)

---

## 🧑‍💻 Run Client (Attacker)

### Step 4: Execute the client script

Edit `client.py` to add an `if __name__ == "__main__":` block like this at the bottom:

```python
if __name__ == "__main__":
    original_message = b"amount=100&to=alice"
    original_mac = "382c..."  # Use MAC from server
    secret_length = 9         # Length of the secret used on server
    data_to_append = b"&admin=true"

    forged_message, forged_mac = md5_length_extend(secret_length, original_message, original_mac, data_to_append)

    print(f"Forged Message (hex): {forged_message.hex()}")
    print(f"Forged MAC: {forged_mac}")
```

Then run it:

```bash
python3 client.py
```

You will get:

```
Forged Message (hex): 616d6f756e743d31303026746f3d616c69636580...
Forged MAC: 8b8f...
```

📌 Copy:

* The forged message (in hex)
* The forged MAC

---

## 🧪 Send Forged Data to Server

### Step 5: Paste forged data in `server.py` prompt

```
Enter the Forged Message for Server (as HEX string from client.py output): 616d6f756e743d31...
Enter the Forged MAC (hex string from client.py output): 8b8f...
```

### Step 6: Server Response

If successful, the server will show:

```
>>> ATTACK SUCCESSFUL: Server accepted the attacker's forged message and MAC!
```

🎉 The attacker has forged a valid MAC **without knowing the secret**.

---

## 📘 Explanation

### Why This Works

* MD5 processes data in blocks and maintains internal state (`A, B, C, D`).
* The attacker:

  1. Uses original MAC to recover internal state.
  2. Adds padding + extra data.
  3. Continues MD5 from internal state.
* The server recreates `MD5(secret || message || padding || attacker_data)` and accepts it.

---

## 🔐 Security Recommendation

Never use:

```python
MAC = H(secret || message)
```

Use **HMAC** instead:

```python
MAC = HMAC(secret, message)
```

Python:

```python
import hmac, hashlib
mac = hmac.new(secret_key, message, hashlib.md5).hexdigest()
```

---

## 🛡️ Lessons Learned

* `MD5(secret || message)` is vulnerable to length extension attacks.
* Always use cryptographic primitives correctly (e.g., `HMAC`, `bcrypt`, `argon2`).
* MD5 is deprecated. Use SHA-256 or better with HMAC.

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


