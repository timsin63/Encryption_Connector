package netty;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.rsa.RSAKeyPairGenerator;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;


//класс, отвечающий за второго клиента. Втрой клиент должен стартовать сразу после запуска сервера
public class SecondClient {

    private String mac = "B5-73-B9-12-55-F4";  //т.к. прога выполняется на одной железке - просто дал фейковый мак ему, чтобы не получать один и тот же

    //запускаемый модуль
    public static void main(String[] args) throws InterruptedException {

        //при старте генерируем ключи
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        KeyPair keyPair = keyGen.generateKeyPair();
        final PublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        final PrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        Security.addProvider(new BouncyCastleProvider()); //просто наклепка на защите, избавляет от некоторых ошибок

        String encodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());  //объект ключа в строку

        sendKey(encodedKey);  //вызываем функцию отправки ключа

        //инициализация обработчика второго клиента
        ServerBootstrap bootstrap = new ServerBootstrap()
                .channel(NioServerSocketChannel.class)
                .group(new NioEventLoopGroup())
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel socketChannel) throws Exception {
                        socketChannel.pipeline().addLast(new SecondClientHandler(publicKey, privateKey));
                    }
                });

        Channel channel = bootstrap.bind(new InetSocketAddress(12345)).channel(); //порт 12345

    }


    private static void sendKey(String key) throws InterruptedException {

        //отправляем на сервер свой ключ

        Bootstrap bootstrap = new Bootstrap()
                .channel(NioSocketChannel.class)
                .group(new NioEventLoopGroup())
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel socketChannel) throws Exception {
                        socketChannel.pipeline().addLast(ClientHandler.getInstance());
                    }
                });

        ChannelFuture future = bootstrap.connect(new InetSocketAddress(11111)); //порт сервера
        Channel channel = future.sync().channel();

        channel.writeAndFlush("q:" + key);
    }
}
