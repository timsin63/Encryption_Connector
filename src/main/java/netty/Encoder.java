package netty;

import org.jasypt.util.text.StrongTextEncryptor;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import static sun.security.x509.CertificateAlgorithmId.ALGORITHM;


//класс-шифратор
public class Encoder {

    private int generatedNumber;
    private String macAddress;

    //конструктор объекта: при инициализации считает мак железки
    public Encoder() {
        macAddress = getMacAddress();
    }

    public int generateHash() throws NoSuchAlgorithmException {
        generatedNumber = (int) (Math.random() * 10000);  //генерируем случайное число от 0 до 10000

        // Вместо односторонних преобразований делаем хэш
        int generatedHash = new Integer(generatedNumber).hashCode();

        return generatedHash;
    }

    //функция получения мак-адреса железки
    public static String getMacAddress() {
        InetAddress ip;
        try {
            ip = InetAddress.getLocalHost();

            NetworkInterface network = NetworkInterface.getByInetAddress(ip);
            byte[] mac = network.getHardwareAddress();

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mac.length; i++) {
                sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
            }
            return sb.toString();
        } catch (Exception e) {
            System.out.println("Возникла ошибка при получении MAC адреса.");
            return "";
        }
    }


    //Функция получения публичного ключа из закодированной строки
    public static PublicKey decodeKeyFromResponse(String response) throws Exception {
        byte[] publicBytes = Base64.getDecoder().decode(response);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    //функция генерации сообщений
    public static String generateMessage(String messageToEncode, PublicKey publicKey, PrivateKey privateKey, PublicKey serverKey, int pingTime) throws UnsupportedEncodingException {
        byte[] signedHash = encryptKey(messageToEncode, privateKey);   //шифруем хэш
        String stringToSet = new String(signedHash, "ISO-8859-1"); //получаем строку из байт-массива

        byte[] signedMessage = encryptKey(stringToSet, serverKey); //шифруем сообщение

        String encodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());   //шифрация ключа

        String message = new String(signedMessage, "ISO-8859-1") + "&split&"
                + encodedKey; //подписанное сообщение + ключ

        int messageHash = (new String(signedMessage, "ISO-8859-1")
                + encodedKey).hashCode(); //хэш сообщения
        message += "&split&" + messageHash;  //добавляем в хвост сообщения хэш

        return message;
    }

    //шифрование текста
    public static byte[] encryptKey(String text, Key key) {
        byte[] cipherText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding"); //алгоритм шифрования
            cipher.init(Cipher.ENCRYPT_MODE, key);   //инициализация шифратора
            cipherText = cipher.doFinal(text.getBytes("ISO-8859-1"));  //шифрование
        } catch (Exception e) {
            e.printStackTrace();  //если видишь блок catch - это обработка ошибок. Почти во всех случаях это будет вывод текста ошибки в логи
        }
        return cipherText;
    }

    //Функция дешифрования по ключу (так же, как и шифрация)
    public static String decryptKey(byte[] text, Key key) throws UnsupportedEncodingException {
        byte[] dectyptedText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return new String(dectyptedText, "ISO-8859-1");
    }
}
