keytool -genkey -alias test \
    -keyalg RSA \
    -keystore keystore.jks \
    -dname "cn=localhost, ou=IT, o=IT, c=UA" \
    -storepass qwerty \
    -keypass qwerty

keytool -exportcert \
        -keystore keystore.jks \
        -alias test \
        -storepass qwerty \
        -file ca.cer

keytool -importcert -keystore truststore.jks -alias test \
    -storepass qwerty \
    -file ca.cer \
    -noprompt

keytool -import -alias test \
    -file google.pem -keystore truststore2.jks

#openssl s_client -showcerts -connect news.google.com.ua:443 </dev/null 2>/dev/null|openssl x509 -outform PEM >google.pem
