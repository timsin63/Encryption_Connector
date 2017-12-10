package netty;

import io.netty.buffer.ByteBuf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

//хранилище идентификаторов
//в хранилище хранится список идентификаторов
public class ServerRepository {
    private ArrayList<ClientIdentificator> identificators = new ArrayList<>();

    private static ServerRepository instance;

    //блок singleton: хранилище только одно
    public static ServerRepository getInstance() {
        if (instance == null) {
            instance = new ServerRepository();
        }
        return instance;
    }

    public ServerRepository() {
    }

    //метод для получения идентификаторов из хранилища
    public ArrayList<ClientIdentificator> getIdentificators() {
        return identificators;
    }


    //метод записывания идентификаторов в хранилище
    public void setIdentificators(ArrayList<ClientIdentificator> identificators) {
        this.identificators = identificators;
    }
}
