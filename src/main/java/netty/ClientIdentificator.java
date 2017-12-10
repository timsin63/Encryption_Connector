package netty;

//Класс, описывающий идентификатор клиента. Идентификатор состоит из мака, ip и публичного ключа
//является просто классом-объектом для работы программы



public class ClientIdentificator {

    private String mac;
    private String ip;
    private String publicKey;

    public ClientIdentificator(String mac) {
        this.mac = mac;
    }

    public ClientIdentificator(String ip, String mac, String publicKey) {
        this.mac = mac;
        this.ip = ip;
        this.publicKey = publicKey;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
