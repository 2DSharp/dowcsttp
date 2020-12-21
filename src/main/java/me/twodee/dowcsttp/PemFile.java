package me.twodee.dowcsttp;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

public class PemFile {

    private static void write(File file, Key key, String description) throws IOException {
        PemObject pemObject = new PemObject(description, key.getEncoded());
        PemWriter pemWriter = new PemWriter(new FileWriter(file));
        try {
            pemWriter.writeObject(pemObject);
        } finally {
            pemWriter.close();
        }
    }

    public static void writePrivateKey(File file, Key key) throws IOException {
        write(file, key, "PRIVATE KEY");
    }

    public static void writePublicKey(File file, Key key) throws IOException {
        write(file, key, "PUBLIC KEY");
    }

    public static PublicKey readPublicKey(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {
            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
            return converter.getPublicKey(publicKeyInfo);
        }
    }

    public static PrivateKey readPrivateKey(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {

            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());

            return converter.getPrivateKey(privateKeyInfo);
        }
    }

}
