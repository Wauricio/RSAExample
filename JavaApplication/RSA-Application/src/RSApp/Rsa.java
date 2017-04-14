/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RSApp;

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
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.crypto.IllegalBlockSizeException;


public class Rsa {
    
  public static final String ALGORITHM = "RSA";
  public static final String PRIVATE_KEY_FILE = "privateC.key";
  public static final String PUBLIC_KEY_FILE = "publicC.key";
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

    public static void encrypt(String inFile,String outFile, PublicKey publicKey,PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, Exception  {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte data[]=readFile(inFile);
        byte[] cipherText = encryptCipher.doFinal(data);
        writeObjct(outFile,new Object[]{cipherText,sign(data,privateKey)});
       // System.out.println("Encrypted text:"+new String(cipherText));
        //writeFile(cipherText,outFile);
        //writeFile(cipherText,outFile);
        //return Base64.getEncoder().encodeToString(cipherText);
    }

    public static boolean decrypt(String inFile,String outFile, PrivateKey privateKey,PublicKey publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, Exception {
        
       Object[] o= readObjects(inFile);
       byte[] bytes=(byte[])o[0];
       byte[] sign = (byte[])o[1];
      //byte[] bytes=Base64.getDecoder().decode(readFile(inFile));
      //byte[] bytes=readFile(inFile);
       // byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
       bytes= decriptCipher.doFinal(bytes);
       // System.out.println("Decryped Text :"+ new String(bytes, UTF_8)); 
        //System.out.println("Signature correct: " + verify(bytes,sign,publicKey));
          writeFile(bytes,outFile);
       
        return verify(bytes,sign,publicKey);
    }

    public static byte[] sign(byte[] inData, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        
        privateSignature.update(inData);

       return privateSignature.sign();
        //writeFile(signature,outFile);

       // return Base64.getEncoder().encodeToString(signature);
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
    
    public static byte[] readFile(String name) throws IOException{
          Path path = Paths.get(name);
          return  Files.readAllBytes(path);
    }
    public static void writeObjct(String filename,Object[] objs) throws FileNotFoundException, IOException{
        FileOutputStream f = new FileOutputStream(new File(filename));
        ObjectOutputStream o = new ObjectOutputStream(f);
	for(Object ob : objs)
            o.writeObject(ob);
        o.close();
        f.close();
    }
    
    public static Object[] readObjects(String filename) throws FileNotFoundException, IOException, ClassNotFoundException{
        FileInputStream fi = new FileInputStream(new File(filename));
        ObjectInputStream oi = new ObjectInputStream(fi);
	Object[] o=new Object[]{oi.readObject(),oi.readObject()};
        oi.close();
	fi.close();
        return o;
    }
    
    
  
    public static void main(String... argv) throws Exception {
       generateKey();
        
        /* //First generate a public/private key pair
        KeyPair pair = generateKeyPair();
        //KeyPair pair = getKeyPairFromKeyStore();

        //Our secret message
        String message = "Hola Como Estas";

        //Encrypt the message
        encrypt("hola.txt","outObjet.txt", pair.getPublic(),pair.getPrivate());

        //Now decrypt it
         decrypt("outObjet.txt","finaltext.txt", pair.getPrivate(),pair.getPublic());

        //System.out.println(decipheredMessage);

        //Let's sign our message
        //System.out.println("message>len:"+message.length());
        //String signature = sign(message, pair.getPrivate());
        //sign("hola.txt","sign.txt", pair.getPrivate());
        //System.out.println("sig:"+signature);
        //Let's check the signature
        //boolean isCorrect = verify("finaltext.txt","sign.txt", pair.getPublic());
        //System.out.println("Signature correct: " + isCorrect);
        */
    }
}