import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoHW1{
  public static void main(String[] args){
    //use bouncycastle as the only provider
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    Scanner reader = new Scanner(System.in);
    System.out.println("-------------------- Eric Ghildyal Crypto HW 1 --------------------");
    System.out.println("Please enter a line of text (ignore if timing): ");
    String input = reader.nextLine();
    byte[] in = input.getBytes();
    runAES(in);
    System.out.println("\n\n");
    runBlowfish(in);
    System.out.println("\n\n");
    runRSA(in);
    System.out.println("\n\n");
    System.out.println("Generating 100 random strings of length 100 chars...");
    String[] randStrs = genRandStr(100, 100);
    
    System.out.println("-------------------- Running alogrithms --------------------");
    System.out.println("AES...");
    long aesTime = timeEncrypt(randStrs, "AES");
    System.out.println("Blowfish...");
    long blowfishTime = timeEncrypt(randStrs, "Blowfish");
    System.out.println("RSA...");
    long rsaTime = timeEncrypt(randStrs, "RSA");
    
    System.out.println("-------------------- Results --------------------");
    System.out.println("\nTimed AES: " + aesTime/1000000 + " ms");
    System.out.println("Timed Blowfish: " + blowfishTime/1000000 + " ms");
    System.out.println("Timed RSA: " + rsaTime/1000000 + " ms");

    System.out.println("\nAES vs RSA: " + ((double)(rsaTime-aesTime)/aesTime)*100 + "% better");
    System.out.println("Blowfish vs RSA: " + ((double)(rsaTime-blowfishTime)/blowfishTime)*100 + "% better");
    System.out.println("Blowfish vs AES: " + ((double)(aesTime-blowfishTime)/blowfishTime)*100 + "% better");
  }

  public static void runAES(byte[] input){
    System.out.println("-------------------- AES --------------------");
    //Get AES instance
    Cipher cipher = null;
    try{
      cipher = Cipher.getInstance("AES", "BC");
    }catch(Exception ex){
      System.out.println(ex);
    }

    //Generate 128bit keys
    KeyGenerator gen = null;
    try{
      gen = KeyGenerator.getInstance("AES");
    }catch(Exception ex){
      System.out.println(ex);
    }
    gen.init(128);
    SecretKey key = gen.generateKey();

    //Encrypt input
    byte[] ciphertext = crypt(key, cipher, input, true);
    //Print ciphertext
    // System.out.println("Here is your ciphertext: ");
    // System.out.println(Arrays.toString(ciphertext));

    //Decrypt ciphertext
    byte[] origInput = crypt(key, cipher, ciphertext, false);;
    
    System.out.println("Here is your decrypted output: ");
    System.out.println(new String(origInput));
  }

  public static void runBlowfish(byte[] input){
    System.out.println("-------------------- Blowfish --------------------");
    //Get blowfish instacne
    Cipher cipher = null;
    try{
      cipher = Cipher.getInstance("Blowfish", "BC");
    }catch(Exception ex){
      System.out.println(ex);
    }

    //Generate 128bit Blowfish key
    KeyGenerator gen = null;
    try{
      gen = KeyGenerator.getInstance("Blowfish");
    }catch(Exception ex){
      System.out.println(ex);
    }
    gen.init(128);
    SecretKey key = gen.generateKey();
    //Encrypt input
    byte[] ciphertext = crypt(key, cipher, input, true);
    //Print ciphertext
    // System.out.println("Here is your ciphertext: ");
    // System.out.println(Arrays.toString(ciphertext));

    //Decrypt ciphertext
    byte[] origInput = crypt(key, cipher, ciphertext, false);
    System.out.println("Here is your decrypted output: ");
    System.out.println(new String(origInput));
  }

  public static void runRSA(byte[] input){
    System.out.println("-------------------- RSA --------------------");
    //Get RSA instance
    Cipher cipher = null;
    try{
      cipher = Cipher.getInstance("RSA", "BC");
    }catch(Exception ex){
      System.out.println(ex);
    }

    //Generate RSA keypair
    KeyPairGenerator gen = null;
    try{
      gen = KeyPairGenerator.getInstance("RSA", "BC");
    }catch(Exception ex){
      System.out.println(ex);
    }
    KeyPair keyPair = gen.generateKeyPair();

    //Encrypt input
    byte[] ciphertext = crypt(keyPair, cipher, input, true);

    //Print ciphertext
    // System.out.println("Here is your ciphertext: ");
    // System.out.println(Arrays.toString(ciphertext));

    //Decrypt ciphertext
    byte[] origInput = crypt(keyPair, cipher, ciphertext, false);

    System.out.println("Here is your decrypted output: ");
    System.out.println(new String(origInput));

    //Generate RSA signature of input
    Signature sig = null;
    byte[] signedInput = null;
    try{
      //Hash then sign because it's best practice
      sig = Signature.getInstance("SHA1withRSA", "BC");
      sig.initSign(keyPair.getPrivate());
      sig.update(input);
      signedInput = sig.sign();
    }catch(Exception ex){
      System.out.println(ex);
    }
    //Verify resulting signature
    try{
      sig.initVerify(keyPair.getPublic());
      sig.update(input);
    }catch(Exception ex){
      System.out.println(ex);
    }

    //Output verfification results
    try{
      System.out.println("Signature verified: " + sig.verify(signedInput));
    }catch(Exception ex){
      System.out.println(ex);
    }

  }

   // boolean encrypts or decrypts
   public static byte[] crypt(SecretKey key, Cipher cipher, byte[] input, boolean encrypt){
    byte[] out = null;
    try{
      if(encrypt){
        cipher.init(Cipher.ENCRYPT_MODE, key);
      }else{
        cipher.init(Cipher.DECRYPT_MODE, key);
      }
      out = cipher.doFinal(input);
    }catch(Exception ex){
      System.out.println(ex);
    }
    return out;
  }

  //overloaded: uses keypair instead of secret key
  public static byte[] crypt(KeyPair key, Cipher cipher, byte[] input, boolean encrypt){
    byte[] out = null;
    try{
      if(encrypt){
        cipher.init(Cipher.ENCRYPT_MODE, key.getPublic());
      }else{
        cipher.init(Cipher.DECRYPT_MODE, key.getPrivate());
      }
      out = cipher.doFinal(input);
    }catch(Exception ex){
      System.out.println(ex);
    }
    return out;
  }

  

  //run all together but new methods for speed
  public static long timeEncrypt(String[] randStrs, String algo){
    switch(algo){
      case "AES":
        return timedAES(randStrs);
      case "Blowfish":
        return timedBlowfish(randStrs);
      case "RSA":
        return timedRSA(randStrs);
      default:
        return -1;
    }
  }

  public static long timedAES(String[] randStrs){
    Cipher cipher = null;
    try{
      cipher = Cipher.getInstance("AES", "BC");
    }catch(Exception ex){
      System.out.println(ex);
    }

    //Generate 128bit keys
    KeyGenerator gen = null;
    try{
      gen = KeyGenerator.getInstance("AES");
    }catch(Exception ex){
      System.out.println(ex);
    }
    gen.init(128);
    SecretKey key = gen.generateKey();

    //Encrypt input
    long start = System.nanoTime();
    for(int i = 0; i < randStrs.length; i++){
      crypt(key, cipher, randStrs[i].getBytes(), true);
    }
    long stop = System.nanoTime();
    return stop-start;
  }

  public static long timedBlowfish(String[] randStrs){
     //Get blowfish instacne
     Cipher cipher = null;
     try{
       cipher = Cipher.getInstance("Blowfish", "BC");
     }catch(Exception ex){
       System.out.println(ex);
     }
 
     //Generate 128bit Blowfish key
     KeyGenerator gen = null;
     try{
       gen = KeyGenerator.getInstance("Blowfish");
     }catch(Exception ex){
       System.out.println(ex);
     }
     gen.init(128);
     SecretKey key = gen.generateKey();

    long start = System.nanoTime();
    for(int i = 0; i < randStrs.length; i++){
      crypt(key, cipher, randStrs[i].getBytes(), true);
    }
    long stop = System.nanoTime();
    return stop-start;
  }

  public static long timedRSA(String[] randStrs){
    //Get RSA instance
    Cipher cipher = null;
    try{
      cipher = Cipher.getInstance("RSA", "BC");
    }catch(Exception ex){
      System.out.println(ex);
    }

    //Generate RSA keypair
    KeyPairGenerator gen = null;
    try{
      gen = KeyPairGenerator.getInstance("RSA", "BC");
    }catch(Exception ex){
      System.out.println(ex);
    }
    KeyPair keyPair = gen.generateKeyPair();

    long start = System.nanoTime();
    for(int i = 0; i < randStrs.length; i++){
      crypt(keyPair, cipher, randStrs[i].getBytes(), true);
    }
    long stop = System.nanoTime();
    return stop-start;
  }

  public static String[] genRandStr(int cnt, int len){
    String poss = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    String[] randStrs = new String[cnt];
    Random rand = new SecureRandom();

    for(int i = 0; i < cnt; i++){
      StringBuilder buff = new StringBuilder(len);
      for(int j = 0; j < len; j++){
        buff.append(poss.charAt(rand.nextInt(poss.length())));
      }
      randStrs[i] = buff.toString();
    }
    return randStrs;
  }

}
