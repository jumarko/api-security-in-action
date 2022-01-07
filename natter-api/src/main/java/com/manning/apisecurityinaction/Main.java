package com.manning.apisecurityinaction;

import org.dalesbred.Database;
import org.dalesbred.result.ResultSetProcessor;
import org.h2.jdbcx.JdbcConnectionPool;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Main {

    public static void main(String[] args) throws URISyntaxException, IOException {
        final JdbcConnectionPool datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter", "password");
        final Database database = Database.forDataSource(datasource);
        createTables(database);

        new WebApp(database).init();
    }

    private static void createTables(Database database) throws URISyntaxException, IOException {
        final Path schema = Path.of(Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(schema));
    }
}
