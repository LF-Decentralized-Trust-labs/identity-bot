A throwaway RSA-2048 key made for these tests only, and a ciphertext OpenSSL made for it:
openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha1
of the 30 bytes "a data key made elsewhere.....". It protects nothing.
