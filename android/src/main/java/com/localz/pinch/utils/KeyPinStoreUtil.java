package com.localz.pinch.utils;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class KeyPinStoreUtil {

    private static HashMap<String[], KeyPinStoreUtil> instances = new HashMap<>();
    private SSLContext sslContext = SSLContext.getInstance("TLS");

    public static synchronized KeyPinStoreUtil getInstance(String[] filenames, String userP12Pwd) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        // if (filenames != null && instances.get(filenames) == null) {
        if (userP12Pwd != null) {
            instances.put(filenames, new KeyPinStoreUtil(filenames, userP12Pwd));
        }
        return instances.get(filenames);

    }

    private KeyPinStoreUtil(String[] filenames, String userP12Pwd) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Create a KeyStore for our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);

        // https 非自签名服务端证书，无需传入 cert certs，则无需设置自签名证书实体
        if (filenames != null) {
            for (String filename : filenames) {
                InputStream caInput = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/" + filename + ".cer"));
                Certificate ca;
                try {
                    ca = cf.generateCertificate(caInput);
                    System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
                } finally {
                    caInput.close();
                }
                keyStore.setCertificateEntry(filename, ca);
            }
        }

        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        // https 非自签名服务端证书，无需传入 cert certs，则无需设置自签名 keyStore
        if (filenames == null || filenames.length == 0) {
            tmf.init((KeyStore) null);
        } else {
            tmf.init(keyStore);
        }

        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream userP12S = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream("assets/user.p12"));
        ks.load(userP12S, userP12Pwd.toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
        try {
            kmf.init(ks, userP12Pwd.toCharArray());
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } finally {
            userP12S.close();
        }
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    }

    public SSLContext getContext() {
        return sslContext;
    }
}
