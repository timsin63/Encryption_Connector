package netty;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

//обработчик сервера
public class ServerHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private static final Logger LOG = Logger.getLogger(ServerHandler.class.getName());
    PublicKey publicKey;   //ключи
    PrivateKey privateKey;
    PublicKey clientKey;

    List<ClientIdentificator> identificators = new ArrayList<>(); //идентификаторы


    //конструктор обработчика сервера
    public ServerHandler(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;  //запоминаем ключи от объекта Server
        this.privateKey = privateKey;

        Security.addProvider(new BouncyCastleProvider());

        //идентификаторы хранятся в объекте ServerRepository. Если их там нет, то кладем список идентификаторов
        if (ServerRepository.getInstance().getIdentificators().isEmpty()) {
            identificators.add(new ClientIdentificator("A4-02-B9-CA-25-6A")); //Сюда запиши свой мак
            identificators.add(new ClientIdentificator("0.0.0.0/0.0.0.0:12345", "B5-73-B9-12-55-F4", "qqq"));//Пусть это будет условный мак второго клиента
            identificators.add(new ClientIdentificator("95-D1-04-F0-89-BB"));
            identificators.add(new ClientIdentificator("48-21-91-FA-56-9A"));
            ServerRepository.getInstance().setIdentificators((ArrayList<ClientIdentificator>) identificators);
        } else {  //если они есть, то получаем готовый список
            identificators = ServerRepository.getInstance().getIdentificators();
        }
    }

    //для ошибки, трогать не надо
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        LOG.log(Level.SEVERE, null, cause);
        ctx.close();
    }


    //сообщение пришло
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf byteBuf) throws Exception {
        String address = ctx.channel().remoteAddress().toString();  //получаем адрес
        LOG.info("Получено сообщение от " + address);

        ByteBuf buf = ctx.alloc().buffer(10000);  //инициализация байтбуфера

        String s = byteBuf.toString(Charset.defaultCharset());  //получаем сообщение как строку

        switch (s.charAt(0)) {   //проверяем первый символ, в зависимости от него будет выполняться соответствующий блок case
            case '0':
                //пришел пинг-запрос, высылаем ключ
                LOG.info("Получен пинг-запрос");
                String encodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded()); //шифруем ключ через Base64
                buf.writeCharSequence("0:" + encodedKey, Charset.defaultCharset()); //отправляем клиенту

                break;
            case '1': {
                LOG.info("Получено сообщение на проверку сервера");
                String[] arr = s.substring(2).split("&split&");  //получаем массив строк с помощью разделителя

                String message = arr[0] + arr[1]; //для вычисления хэша

                //массив выглядит так:
                //arr[0] -> шифрованный генерированный клиентом хэш
                //arr[1] -> ключ клиента
                //arr[2] -> хэш сообщения

                if (message.hashCode() == Integer.parseInt(arr[2])) {  //проверка хэшей
                    LOG.info("Контрольная сумма подтверждена");

                    arr[0] = Encoder.decryptKey(arr[0].getBytes("ISO-8859-1"), privateKey);  //расшифровка сообщения приватным ключом сервера

                    clientKey = Encoder.decodeKeyFromResponse(arr[1]);    //расшифровка ключа с помощью base64

                    //расшифровка клиентского хэша
                    String hashString = Encoder.decryptKey(arr[0].getBytes("ISO-8859-1"), clientKey);

                    //избавляемся от нулевых байт
                    String nonNullHashString = new String();
                    for (byte b : hashString.getBytes("ISO-8859-1")) {
                        if (b != 0) {
                            nonNullHashString += (char) b;
                        }
                    }

                    //генерим сообщение для клиента
                    String messageToSend = Encoder.generateMessage(String.valueOf(nonNullHashString.hashCode()),
                            publicKey,
                            privateKey,
                            clientKey,
                            1000);

                    //записываем сообщение в буфер
                    buf.writeCharSequence("1:" + messageToSend, Charset.defaultCharset());
                    break;
                }
            }
            case '2': {
                LOG.info("Клиент прислал MAC");

                //пока все идет по аналогии
                String[] arr = s.substring(2).split("&split&");

                String message = arr[0] + arr[1];
                if (message.hashCode() == Integer.parseInt(arr[2])) {
                    LOG.info("Контрольная сумма подтверждена");

                    arr[0] = Encoder.decryptKey(arr[0].getBytes("ISO-8859-1"), privateKey); //расшифровка приватным ключом

                    String mac = Encoder.decryptKey(arr[0].getBytes("ISO-8859-1"), clientKey); //расшифровка ключом клиента

                    //отброс нулевыз байт
                    String nonNullMac = new String();
                    for (byte b : mac.getBytes("ISO-8859-1")) {
                        if (b != 0) {
                            nonNullMac += (char) b;
                        }
                    }

                    //клиентский ключ в строку
                    String clientKeyString = Base64.getEncoder().encodeToString(clientKey.getEncoded());
                    String identificatorsString = new String();

                    //обходим все идентификаторы
                    for (int i = 0; i < identificators.size(); i++) {
                        if (identificators.get(i).getMac().equals(nonNullMac)) { //если пришедший мак совпал со списком
                            LOG.info("Клиент подтвержден на сервере");
                            identificators.get(i).setIp(address);                  //записываем в текущий идентификатор остальную информацию
                            identificators.get(i).setPublicKey(clientKeyString);   //обновляем ключ в хранилище

                            for (int j = 0; j < identificators.size(); j++) {    //делаем обход
                                ClientIdentificator identificator = identificators.get(j);
                                //если не совпадает с маком клиента, то записываем все остальные в строку для отправки идентификаторов
                                if (!identificator.getMac().equals(nonNullMac)) {
                                    identificatorsString += identificator.getIp() + "&" + identificator.getMac() + "&" + identificator.getPublicKey() + "&split_items&";
                                }
                            }

                            //пишем идентификаторы в буфер
                            buf.writeCharSequence("2:" + identificatorsString, Charset.defaultCharset());

                            break;
                        }
                    }
                }

                break;
            }
            case 'q': {
                //второй клиент прислал свой ключ, запишем его в список идентификаторов
                identificators.get(1).setPublicKey(s.substring(2));
            }

        }

        //отправляем то, что записали до этого в буфер
        ctx.channel().writeAndFlush(buf);
    }
}
