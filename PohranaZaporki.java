import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.TreeMap;


public class PohranaZaporki {

    private static final String IME_DATOTEKE = "baza_zaporki.txt";
    private static final Path PUT_DATOTEKE = Path.of(IME_DATOTEKE);
    private static final boolean DATOTEKA_POSTOJI = Files.exists(PUT_DATOTEKE);

    public static void main(String[] args) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeySpecException, InvalidKeyException, ClassNotFoundException {

       if(args.length<2){
           System.out.println("Unesi barem 2 argumenta");
           return;
       }

        String naredba = args[0];
        String masterLozinka = args[1];

       if(naredba.equals("init")){
           if(DATOTEKA_POSTOJI) Files.delete(PUT_DATOTEKE);
           spremiLozinku(new TreeMap<>(), masterLozinka);
           System.out.println("Uspjesna inicijalizacija.");
       } else if (naredba.equals("put")){
           if(args.length<4){
               System.out.println("Unesi 4 argumenta za koristenje naredbe 'put'.");
               return;
           } else {
               String adresa = args[2];
               String zaporka = args[3];
               staviLozinku(masterLozinka, adresa, zaporka);
           }
       } else if (naredba.equals("get")){
           if(args.length<3){
               System.out.println("Unesi 3 argumenta za koristenje naredbe 'get'.");
               return;
           } else {
               String trazenaAdresa = args[2];
               dohvatiLozinku(masterLozinka, trazenaAdresa);
           }
       } else {
           System.out.println("Naredba nije prepoznata.");
       }

    }


    public static void staviLozinku(String masterLozinka, String adresa, String lozinka) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeySpecException, InvalidKeyException, ClassNotFoundException {
        TreeMap<String, String> lozinke = new TreeMap<>();
        if(DATOTEKA_POSTOJI){
            lozinke = ucitajLozinke(masterLozinka);
        }
        lozinke.put(adresa, lozinka);
        spremiLozinku(lozinke, masterLozinka);
        System.out.println("Lozinka uspjesno pohranjena.");
    }

    public static void dohvatiLozinku(String glavnaLozinka, String trazenaAdresa) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, ClassNotFoundException {
        TreeMap<String, String> lozinke = new TreeMap<>();
        if(DATOTEKA_POSTOJI){
            lozinke = ucitajLozinke(glavnaLozinka);
        }
        String trazenaLozinka = lozinke.get(trazenaAdresa);
        if (trazenaLozinka == null){
            System.out.println("Greska.");//ne dati napadacu ikakve korisne informacije
        } else {
            System.out.println("Lozinka za " + trazenaAdresa + " je: " + trazenaLozinka);
        }
    }

    @SuppressWarnings("unchecked")
    public static TreeMap<String, String> ucitajLozinke(String masterLozinka) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        byte[] sadrzaj = Files.readAllBytes(Path.of(IME_DATOTEKE));
        byte[] inicijalizacijskiVektor = Arrays.copyOfRange(sadrzaj, 0, 12);
        byte[] mac = Arrays.copyOfRange(sadrzaj, sadrzaj.length-32, sadrzaj.length);
        byte[] sifriraniTekst = Arrays.copyOfRange(sadrzaj, 12, sadrzaj.length-32);

        Mac hmac = Mac.getInstance("HmacSHA256");
        PBEKeySpec pbks = new PBEKeySpec(masterLozinka.toCharArray(), "kljucintegriteta".getBytes(), 150000,256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sk = skf.generateSecret(pbks);
        byte[] skbyte = sk.getEncoded();
        SecretKeySpec skc = new SecretKeySpec(skbyte, "AES");
        hmac.init(skc);
        hmac.update(inicijalizacijskiVektor);
        byte[] mac2 = hmac.doFinal(sifriraniTekst);

        if(Arrays.equals(mac, mac2)){
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            SecureRandom random = new SecureRandom();
            GCMParameterSpec gcmspecifikacija = new GCMParameterSpec(128, inicijalizacijskiVektor);
            PBEKeySpec pbks2 = new PBEKeySpec(masterLozinka.toCharArray(), "kljucenkripcije".getBytes(), 150000,256);
            SecretKeyFactory skf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey sk2 = skf2.generateSecret(pbks2);
            byte[] skbyte2 = sk2.getEncoded();
            SecretKeySpec skc2 = new SecretKeySpec(skbyte2, "AES");
            c.init(2, skc2, gcmspecifikacija, random);
            c.update(sifriraniTekst);
            byte[] desifriraniTekst = c.doFinal();

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(desifriraniTekst);
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            TreeMap<String, String> lozinke = (TreeMap<String, String>) objectInputStream.readUnshared();
            return lozinke;

        } else {
           throw new InvalidKeyException("Greska.");
        }


    }

    public static void spremiLozinku(TreeMap<String, String> adresaLozinka, String masterLozinka) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        ByteArrayOutputStream byteArrayOutputStreamStream = new ByteArrayOutputStream();
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStreamStream)) {
            objectOutputStream.writeUnshared(adresaLozinka);
        }
        byte[] lozinke = byteArrayOutputStreamStream.toByteArray();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] inicijalizacijskiVektor = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(inicijalizacijskiVektor);
        GCMParameterSpec gcmspecifikacija = new GCMParameterSpec(128, inicijalizacijskiVektor);
        PBEKeySpec pbks = new PBEKeySpec(masterLozinka.toCharArray(), "kljucenkripcije".getBytes(), 150000,256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sk = skf.generateSecret(pbks);
        byte[] skbyte = sk.getEncoded();
        SecretKeySpec skc = new SecretKeySpec(skbyte, "AES");
        cipher.init(1, skc, gcmspecifikacija, random);
        //cipher.update(lozinke);
        byte[] sifriraniTekst = cipher.doFinal(lozinke);


        Mac hmac = Mac.getInstance("HmacSHA256");
        PBEKeySpec pbks2 = new PBEKeySpec(masterLozinka.toCharArray(), "kljucintegriteta".getBytes(), 150000,256);
        SecretKeyFactory skf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sk2 = skf2.generateSecret(pbks2);
        byte[] skbyte2 = sk2.getEncoded();
        SecretKeySpec skc2 = new SecretKeySpec(skbyte2, "AES");
        hmac.init(skc2);
        hmac.update(inicijalizacijskiVektor);
        byte[] mac = hmac.doFinal(sifriraniTekst);

        try (BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(IME_DATOTEKE))) {
            bufferedOutputStream.write(inicijalizacijskiVektor);
            bufferedOutputStream.write(sifriraniTekst);
            bufferedOutputStream.write(mac);
        } catch (IOException e) {
            e.printStackTrace();
        }


    }


}
