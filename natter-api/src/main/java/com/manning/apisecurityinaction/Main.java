package com.manning.apisecurityinaction;

import com.nimbusds.jose.JOSEException;
import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class Main {

    public static void main(String[] args) throws URISyntaxException, IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, JOSEException {
        // first populate the schema with elevated permissions
        createTables(Database.forDataSource(JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter", "password")));

        var port = (args.length > 0) ? Integer.parseInt(args[0]) : null;
        // now create a new datasource with restricted user
        new WebApp(Database.forDataSource(JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter_api_user", "password")),
                port)
                .init();
    }

    private static void createTables(Database database) throws URISyntaxException, IOException {
        final Path schema = Path.of(Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(schema));
    }
}
                                                           