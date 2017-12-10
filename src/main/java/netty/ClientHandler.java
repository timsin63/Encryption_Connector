package netty;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import sun.security.rsa.RSAKeyPairGenerator;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

 //Класс-обработчик для входящих сообщений
@ChannelHandler.Sharable
public class ClientHandler extends ChannelDuplexHandler {

    //инициализация переменных
    private static final Logger LOG = Logger.getLogger(ClientHandler.class.getName()); //Для вывода логов
    private int pingTime; //время пинга
    private long initTime; //время отправки сообщения
    Encoder encoder;   //Объект нашего класса-шифратора
    PublicKey publicKey; //Ключи: публичный, приватный и серверный
    PrivateKey privateKey;
    PublicKey serverKey;

    List<ClientIdentificator> identificators = new ArrayList<>();  //Список идентификаторов (объектов нашего класса)

    int hashOfHash;

    static ClientHandler instance;

    //Блок Singleton: Этот кусок кода дает нам то, что у клиента будет работать один обработчик входящих сообщений, а не создаваться новый.
    public static ClientHandler getInstance() {
        if (instance == null) {  //если обработчика еще нет, то создать новый, если есть - вернуть существующий
            instance = new ClientHandler();
        }
        return instance;
    }

    //блок-конструктор: Вызывается при создании нового обработчика
    public ClientHandler() {
        initTime = System.currentTimeMillis(); //получаем текущее время
        encoder = new Encoder();  //получаем шифратор

        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();  //генератор пары глючей
        KeyPair keyPair = keyGen.generateKeyPair();  //сгенерить пару ключей
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
    }

    //обязательная функция для отправки сообщений
    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        String text = (String) msg;
        ctx.write(Unpooled.wrappedBuffer(text.getBytes(StandardCharsets.UTF_8)), promise);
    }


    //Вызывается автоматически, когда пришло сообщение
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        String text = ((ByteBuf) msg).toString(StandardCharsets.UTF_8);  //Байтбуфер в строку
        switch (text.charAt(0)) {   //конструкция, которая будет проверять нулевой символ входящего сообщения
            case '0':   //как например тут: символ нолик, значит выполнять код ниже. Пришел ответ на пинг
                pingTime = (int) ((System.currentTimeMillis() - initTime) * 1.2);  //вычисляем пинг
                LOG.info("Получили ответ от " + ctx.channel().remoteAddress() + ": " + text
                        + "   пинг: " + pingTime);

                //к каждому сообщению я ставил цифру и двоеточие, чтобы отделять типы сообщений
                String response = new String(text.substring(2).getBytes());

                //получаем ключ сервера из ответа
                serverKey = Encoder.decodeKeyFromResponse(response);

                //генерируем хэш случайного числа нашим шифратором
                int generatedHash = encoder.generateHash();

                //непосредственно сообщение для отправки на сервер
                String message = "1:" + Encoder.generateMessage(String.valueOf(generatedHash), publicKey, privateKey, serverKey, pingTime);

                //хэш сгенерированного хэша для дальнейшего подтверждения сервера
                hashOfHash = String.valueOf(generatedHash).hashCode();

                //отправляем сообщение
                ctx.channel().writeAndFlush(message);
                initTime = System.currentTimeMillis();  // фиксируем время отправки
                break; //конец куска кода, обрабатывающего код с символом 0
            case '1':
                //Проверка, сколько прошло времени до прихода сообщения.
                if (System.currentTimeMillis() - initTime < pingTime) {

                    LOG.info("Получен ответ сервера на запрос авторизации");
                    String[] arr = text.substring(2).split("&split&"); //пусть &split& - это разделитель данных. тогда из входной
                                                                            //строки получаем массив данных, которые в строке делились этим разделителем

                    message = arr[0] + arr[1];
                    String receivedHash = arr[2];
                    if (message.hashCode() == Integer.parseInt(receivedHash)) {  //сравниваем хэш сообщения и пришедший хэш
                        LOG.info("Контрольная сумма подтверждена");

                        //во всех передачах используется кодировка ISO-8859-1
                        arr[0] = Encoder.decryptKey(arr[0].getBytes("ISO-8859-1"), privateKey); //расшифровка приватным ключом

                        //цепочка преобразований в байт-поток
                        String encryptedServerMessage = arr[0];
                        byte[] encryptedServerHashBytes = encryptedServerMessage.getBytes("ISO-8859-1");

                        encryptedServerMessage = Encoder.decryptKey(encryptedServerHashBytes, serverKey);


                        //кусок кода для избавления от нулевых байт в массиве
                        String nonNullHashString = new String();
                        for (byte b : encryptedServerMessage.getBytes("ISO-8859-1")) {
                            if (b != 0) {
                                nonNullHashString += (char) b;
                            }
                        }


                        if (Integer.parseInt(nonNullHashString) == hashOfHash) { //сверяем хэши
                            LOG.info("Сервер авторизован");

                            String msg2 = "2:" + Encoder.generateMessage(Encoder.getMacAddress(), //генерируем сообщение на основе мака
                                    publicKey, privateKey, serverKey, pingTime);


                            ctx.channel().writeAndFlush(msg2); //отправляем
                            initTime = System.currentTimeMillis(); //получаем время
                        }
                    } else {
                        LOG.info("Превышено время ожидания"); //если не уложились во времени
                        ctx.channel().close();
                    }

                        break;
                    }
                    case '2':
                        if (System.currentTimeMillis() - initTime < pingTime) {
                            LOG.info("Сервер прислал список авторизованных клиентов");

                            //разделяем на подстроки из идентификаторов
                            String[] idents = text.substring(2).split("&split_items&");

                            //добавляем в обработчик список идентификаторов аторизаванных клиентов
                            for (int i = 0; i < idents.length; i++) {
                                String[] identIfos = idents[i].split("&");  //разделяем одним символом
                                identificators.add(new ClientIdentificator(identIfos[0], identIfos[1], identIfos[2])); //добавление в список идентификаторов
                            }

                            LOG.info("Авторизация успешно завершена");

                            //Вызываем у клиента метод подключения ко второму клиенту
                            Client.startConnectionToSecondClient();

                            break;
                        } else {
                            LOG.info("Превышено время ожидания");
                            ctx.channel().close();
                        }


                    case '3':
                        LOG.info("Второй клиент прислал свой Mac");
                        String address = ctx.channel().remoteAddress().toString(); //берем адрес второго клиента

                        ClientIdentificator currentIdentificator = new ClientIdentificator(null);


                        //поиск идентификатора по ip подключенного клиента
                        for (ClientIdentificator identificator : identificators) {
                            if (identificator.getIp().equals(address)) {
                                currentIdentificator = identificator;
                            }
                        }

                        //получаем из строки в списке идентификаторов ключ второго клиента
                        PublicKey secondClientKey = Encoder.decodeKeyFromResponse(currentIdentificator.getPublicKey());

                        //Дешифруем сообщение второго клиента его публичным ключом, чтобы получить мак
                        String secondClientMac = Encoder.decryptKey(text.substring(2).getBytes("ISO-8859-1"), secondClientKey);

                        //избавляемся от нулевых байт
                        String nonNullMac = new String();
                        for (byte b : secondClientMac.getBytes("ISO-8859-1")) {
                            if (b != 0) {
                                nonNullMac += (char) b;
                            }
                        }

                        //сверяем мак клиента с маком в списке авторизованных
                        if (nonNullMac.equals(currentIdentificator.getMac())) {

                            LOG.info("Второй клиент подтвержден");

                            String macHash = String.valueOf(nonNullMac.hashCode()); //получаем хэш

                            byte[] encryptedHash = Encoder.encryptKey(macHash, secondClientKey);  //шифруем его
                            String encryptedHashString = new String(encryptedHash, "ISO-8859-1"); //переводим в строку

                            //отправляем сообщение: код сообщения, шифрованный хэш, разделитель и хэш хэша для проверки контрольной суммы
                            ctx.channel().writeAndFlush("1:" + encryptedHashString + "&split&" + encryptedHashString.hashCode());
                        }


                        break;
                }
        }


        //вызывается автоматически, если произошла ошибка в подключениях
        @Override
        public void exceptionCaught (ChannelHandlerContext ctx, Throwable cause) throws Exception {
            LOG.log(Level.SEVERE, null, cause);
            ctx.close();
        }
    }
