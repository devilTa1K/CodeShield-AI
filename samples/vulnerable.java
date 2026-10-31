import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class AccountService {
    private static final String DB_PASSWORD = "Sup3rSecret!2024";

    public ResultSet findUser(Connection conn, String name) throws Exception {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public void ping(String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public Object restore(java.io.InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();
    }

    public byte[] hash(String value) throws Exception {
        return MessageDigest.getInstance("MD5").digest(value.getBytes());
    }
}
