openssl req \
        -newkey rsa:2048 -nodes \
        -keyout localhost.key.pem \
        -x509 -subj "/CN=localhost" -days 365 \
        -out localhost.crt.pem
