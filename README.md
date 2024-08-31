# rsa-encryption-decryption-signature
``` sh
python3 rsa.py [-h] operation -in_file IN_FILE
```

### Generate keys
``` sh
python3 rsa.py [-h] gen
```
``` sh
python3 rsa.py gen
```

### Encrypt File
``` sh
python3 rsa.py [-h] enc -in_file IN_FILE -key PUBLIC_KEY
```
``` sh
python3 rsa.py enc -in_file plaintext.txt -key public_key.pem
```

### Decrypt File
``` sh
python3 rsa.py [-h] dec -in_file IN_FILE -key PRIVATE_KEY
```
``` sh
python3 rsa.py dec -in_file plaintext.txt.encrypted -key private_key.pem
```

### Sign File
``` sh
python3 rsa.py [-h] sign -in_file IN_FILE -key PRIVATE_KEY
```
``` sh
python3 rsa.py sign -in_file plaintext.txt -key private_key.pem
```

### Verify Signature
``` sh
python3 rsa.py [-h] verify -in_file IN_FILE -sign_file SIGNATURE_FILE -key PUBLIC_KEY
```
``` sh
python3 rsa.py verify -in_file plaintext.txt.encrypted.decrypted -key public_key.pem -sign_file plaintext.txt.signature
```
