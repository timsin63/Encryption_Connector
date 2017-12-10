package netty;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;

import java.net.InetSocketAddress;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

//Класс инициализации и запуска клиента
public class Client {

    //запускаемый модуль
    public static void main(String[] args) throws Exception {

        //с помощью фреймворка открываем канал и кладем на обработку данного канала наш обработчик ClientHandler
        Bootstrap bootstrap = new Bootstrap()
                .channel(NioSocketChannel.class)
                .group(new NioEventLoopGroup())
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel socketChannel) throws Exception {
                        socketChannel.pipeline().addLast(ClientHandler.getInstance());
                    }
                });

        ChannelFuture future = bootstrap.connect(new InetSocketAddress(11111));  //Подрубаемся к порту 11111
        Channel channel = future.sync().channel();  //Получаем объект канала

        sendPingEcho(channel);  //Функция, описанная ниже в этом же классе
    }

    //С помощью этой функции посылаем эхо-сообщение для получения времени пинга
    private static void sendPingEcho(Channel channel) {

        channel.writeAndFlush("0:Ping");
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    //Функция, которая подрубается ко второму клиенту, вызывается из обработчика
    static void startConnectionToSecondClient() throws InterruptedException {
        Bootstrap bootstrap = new Bootstrap()
                .channel(NioSocketChannel.class)
                .group(new NioEventLoopGroup())
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel socketChannel) throws Exception {
                        socketChannel.pipeline().addLast(ClientHandler.getInstance()); //кладем тот же обработчик
                    }
                });

        ChannelFuture future = bootstrap.connect(new InetSocketAddress(12345));  //на новом порту
        Channel channel = future.sync().channel();

        channel.writeAndFlush("0:Request");
    }

}
