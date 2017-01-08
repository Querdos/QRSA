# RSA Implementation by Querdos
An implementation of the RSA algorithm according to PKCS#1

# Prerequisits
This implementation use the well known library Gnu Multiple Precision (GMP).

# Usage
Three possibilities: 
* Generate a key-pair
  
  `./rsa --generate-key-pair`
  
  If the .rsa directory doesn't exists, it will create it and generate 2 files in it: **rsa.priv** and **rsa.pub**
* Encrypt a file
  
  `./rsa --encrypt file`
  
  It requires that the `--generate-key-pair` has been used before. Otherwise, will raise an error.
* Decrypt a file
  
  `./rsa --decrypt file`
  
  It requires that the `--generate-key-pair` has been used before. Otherwise, will raise an error.
