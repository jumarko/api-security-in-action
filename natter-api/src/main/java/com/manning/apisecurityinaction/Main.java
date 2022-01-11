package com.manning.apisecurityinaction;

import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Main {

    public static void main(String[] args) throws URISyntaxException, IOException {
        // first populate the schema with elevated permissions
        createTables(Database.forDataSource(JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter", "password")));

        // now create a new datasource with restricted user
        new WebApp(Database.forDataSource(JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter_api_user", "password"))).init();
    }

    private static void createTables(Database database) throws URISyntaxException, IOException {
        final Path schema = Path.of(Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(schema));
    }
}
