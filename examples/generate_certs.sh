openssl req \
        -newkey rsa:2048 -nodes \
        -keyout localhost-ca.key.pem \
        -x509 -subj "/CN=localhost CA" -days 365 \
        -out localhost-ca.crt.pem \
        -config localhost.cnf -extensions root_exts

openssl req -new \
        -newkey rsa:2048 -nodes \
        -keyout localhost.key.pem \
        -out localhost.csr.pem \
        -subj "/CN=localhost"

openssl x509 \
        -req -in localhost.csr.pem -out localhost.crt.pem \
        -CAkey localhost-ca.key.pem -CA localhost-ca.crt.pem \
        -CAcreateserial \
        -extfile localhost.cnf -extensions server_exts
