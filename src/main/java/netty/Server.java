package netty;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.rsa.RSAKeyPairGenerator;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Server {

    //исполняемый модуль
    public static void main(String[] args) {

        //генерируем ключи сервера
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        KeyPair keyPair = keyGen.generateKeyPair();
        final PublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        final PrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        Security.addProvider(new BouncyCastleProvider());


        //вешаем серверный обработчик
        ServerBootstrap bootstrap = new ServerBootstrap()
                .channel(NioServerSocketChannel.class)
                .group(new NioEventLoopGroup())
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel socketChannel) throws Exception {
                        socketChannel.pipeline().addLast(new ServerHandler(publicKey, privateKey));
                    }
                });

        //назначаем серверу порт 11111
        Channel channel = bootstrap.bind(new InetSocketAddress(11111)).channel();
    }
}
