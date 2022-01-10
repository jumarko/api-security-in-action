package com.manning.apisecurityinaction.controllers;

import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.sql.SQLException;

public class SpaceController {

    private final Database database;

    public SpaceController(Database database) {
        this.database = database;
    }

    public JSONObject createSpace(Request request, Response response) throws SQLException {
        var json = new JSONObject(request.body());
        var spaceName = json.getString("name");
        var owner = json.getString("owner");

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq;");
            // WARNING: SQL injection vulnerability - will be fixed later
            database.updateUnique("INSERT INTO spaces(space_id, name, owner) VALUES (?, ?, ?)",
                    spaceId, spaceName, owner);
            response.status(201);
            var spaceUri = "/spaces/" + spaceId;
            response.header("Location", spaceUri);
            return new JSONObject().put("name", spaceName).put("uri", spaceUri);
        });

    }
}
