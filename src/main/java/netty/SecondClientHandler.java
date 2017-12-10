package netty;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.rsa.RSAKeyPairGenerator;

import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

//обработчик второго клиента
public class SecondClientHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private static final Logger LOG = Logger.getLogger(ServerHandler.class.getName());
    PublicKey publicKey;
    PrivateKey privateKey;
    PublicKey clientKey;

    String mac = "B5-73-B9-12-55-F4"; //его мак-адрес

    List<ClientIdentificator> identificators = new ArrayList<>();


    //конструктор объекта, передаем ему ключи
    public SecondClientHandler(PublicKey publicKey, PrivateKey privateKey) {

        Security.addProvider(new BouncyCastleProvider());

        this.publicKey = publicKey; //запоминаем переданные ключи второго клиента
        this.privateKey = privateKey;

        //заполняем список идентификаторов маками (пусть изначально у второго клиента они имеются)
        identificators.add(new ClientIdentificator("A4-02-B9-CA-25-6A"));
        identificators.add(new ClientIdentificator("B5-73-B9-12-55-F4"));
        identificators.add(new ClientIdentificator("95-D1-04-F0-89-BB"));
        identificators.add(new ClientIdentificator("48-21-91-FA-56-9A"));
    }

    //обработка ошибки
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        LOG.log(Level.SEVERE, null, cause);
        ctx.close();
    }

    //пришло сообщение
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf byteBuf) throws Exception {
        String address = ctx.channel().remoteAddress().toString(); //получаем адрес
        LOG.info("Получено сообщение от " + address);

        //инициализация буфера записи
        ByteBuf buf = ctx.alloc().buffer(1000);

        //входящее сообщение
        String s = byteBuf.toString(Charset.defaultCharset());

        switch (s.charAt(0)) {
            case '0':

                //пришел запрос от клиента
                byte[] macBytes = Encoder.encryptKey(mac, privateKey); //шифруем публичный ключ
                String message = new String(macBytes, "ISO-8859-1");  //конвертируем в строку
                buf.writeCharSequence("3:" + message, Charset.defaultCharset());  //пишем в буфер

                ctx.writeAndFlush(buf);   //отправляем сообщения
                break;
            case '1':

                //пришел запрос авторизации от первого клиента
                String[] incoming = s.substring(2).split("&split&");  //получаем массив из строки с помощью разделителя
                String encryptedHash = incoming[0];  //записывам в строку шифрованный хэш

                if (encryptedHash.hashCode() == Integer.parseInt(incoming[1])) {   //проверка хэшей

                    LOG.info("Контрольная сумма подтверждена");

                    //дешифрование хэша
                    String decryptedHash = Encoder.decryptKey(encryptedHash.getBytes("ISO-8859-1"), privateKey);

                    //избавляемся от нулевых байт
                    String nonNullHash = new String();
                    for (byte b : decryptedHash.getBytes("ISO-8859-1")) {
                        if (b != 0) {
                            nonNullHash += (char) b;
                        }
                    }


                    //получаем хэш мака клиента
                    int localHash = mac.hashCode();

                    //сверяем хэш, пришедший от первого клиента и хэш мака
                    if (nonNullHash.equals(String.valueOf(localHash))) {
                        LOG.info("Первый клиент подтвержден. Сеанс авторизации окончен успешно");
                    }
                }
        }
    }
}
