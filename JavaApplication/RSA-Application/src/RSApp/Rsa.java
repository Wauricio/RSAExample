/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RSApp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class Rsa {
    
  public static final String ALGORITHM = "RSA";
  public static final String PRIVATE_KEY_FILE = "privateC.key";
  public static final String PUBLIC_KEY_FILE = "publicC.key";
  public static final int bufSize=240;
  public static final int bufSizeDe=256;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    
    public Rsa(String publicKeyName,String privateKeyName) throws FileNotFoundException, IOException, ClassNotFoundException{
       ObjectInputStream inputStream = null;
        inputStream = new ObjectInputStream(new FileInputStream(publicKeyName));
       publicKey = (PublicKey) inputStream.readObject();
             inputStream = new ObjectInputStream(new FileInputStream(privateKeyName));
      privateKey = (PrivateKey) inputStream.readObject();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }
    
     public static void generateKey() {
    try {
      final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
      keyGen.initialize(2048,new SecureRandom());
       
      final KeyPair key = keyGen.generateKeyPair();
     

      File privateKeyFile = new File(PRIVATE_KEY_FILE);
      File publicKeyFile = new File(PUBLIC_KEY_FILE);

      // Create files to store public and private key
      if (privateKeyFile.getParentFile() != null) {
        privateKeyFile.getParentFile().mkdirs();
      }
      privateKeyFile.createNewFile();

      if (publicKeyFile.getParentFile() != null) {
        publicKeyFile.getParentFile().mkdirs();
      }
      publicKeyFile.createNewFile();

      // Saving the Public key in a file
      ObjectOutputStream publicKeyOS = new ObjectOutputStream(
          new FileOutputStream(publicKeyFile));
      publicKeyOS.writeObject(key.getPublic());
      publicKeyOS.close();

      // Saving the Private key in a file
      ObjectOutputStream privateKeyOS = new ObjectOutputStream(
          new FileOutputStream(privateKeyFile));
      privateKeyOS.writeObject(key.getPrivate());
      privateKeyOS.close();
    } catch (Exception e) {
      e.printStackTrace();
    }

  }

  /*  public static KeyPair getKeyPairFromKeyStore() throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks

        InputStream ins = Rsa.class.getResourceAsStream("/keystore.jks");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }*/

    public static byte[] sign(byte[] inData, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        
        privateSignature.update(inData);

       return privateSignature.sign();
    }

    public static boolean verify(byte[] indata, byte[] inSign, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(indata);
        return publicSignature.verify(inSign);
    }
    
    public static void writeFile(byte[] data,String name) throws IOException{
          FileOutputStream fileOuputStream = new FileOutputStream(name);
          fileOuputStream.write(data);
          fileOuputStream.close();
    }
    
    public static void writeObjct(String filename,Object ob) throws FileNotFoundException, IOException{
        FileOutputStream f = new FileOutputStream(new File(filename));
        ObjectOutputStream o = new ObjectOutputStream(f);
        o.writeObject(ob);
        o.close();
        f.close();
    }
    
    public static Object[] readObjects2(String filename) throws FileNotFoundException, IOException, ClassNotFoundException{
        FileInputStream fi = new FileInputStream(new File(filename));
        ObjectInputStream oi = new ObjectInputStream(fi);
	Object[] o=new Object[]{oi.readObject(),oi.readObject()};
        oi.close();
	fi.close();
        return o;
    }
    public static Object readObject(String filename) throws FileNotFoundException, IOException, ClassNotFoundException{
        FileInputStream fi = new FileInputStream(new File(filename));
        ObjectInputStream oi = new ObjectInputStream(fi);
	Object o= oi.readObject();
        oi.close();
	fi.close();
        return o;
    }
    
    
    
    public  static void cipherFile(String name ,String outname,PublicKey publicKey , PrivateKey privateKey) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception{
       Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        ByteArrayOutputStream ous = null;
        InputStream ios = null;
         byte[] buffer = new byte[bufSize];
        byte[] cipherData;
        ous = new ByteArrayOutputStream();
        ios = new FileInputStream(new File(name));
        while ((ios.read(buffer)) != -1) {
            cipherData=encryptCipher.doFinal(buffer);
            ous.write(cipherData, 0, cipherData.length);
        }
        Message m = new Message(ous.toByteArray(),sign(ous.toByteArray(),privateKey),".txt");
        writeObjct(outname,m);   
    }
    
    public  static boolean decipherFile(String name ,String outname,PrivateKey privateKey,PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, FileNotFoundException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, Exception{
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, privateKey); 
        Message m = (Message)readObject(name);
        ByteArrayOutputStream ous  = new ByteArrayOutputStream();
        InputStream ios= new ByteArrayInputStream(m.getMessage());;
        byte[] buffer = new byte[bufSizeDe];
        byte[] decipherData;
        while ((ios.read(buffer)) != -1) {
            decipherData=encryptCipher.doFinal(buffer);
            ous.write(decipherData, 0, decipherData.length);
        }
        writeFile(ous.toByteArray(),outname);
        return verify(m.getMessage(),m.getSign(),publicKey);
    }
    
    
    
    public static void main(String argv[]) throws Exception {
     
        
    //generateKey();
        
         //First generate a public/private key pair
        KeyPair pair = generateKeyPair();
        
        cipherFile ("test.bmp","outf.bmp",pair.getPublic(),pair.getPrivate()); 
        
        
        System.out.println(decipherFile("outf.bmp","outDs.bmp",pair.getPrivate(),pair.getPublic()));
        
        }
    }
    
    
    
  
    
