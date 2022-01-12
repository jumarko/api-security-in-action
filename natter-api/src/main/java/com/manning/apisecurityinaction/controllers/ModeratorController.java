package com.manning.apisecurityinaction.controllers;

import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

public class ModeratorController {
    private final Database database;

    public ModeratorController(Database database) {
        this.database = database;
    }

    // not covered in the book - available here: https://github.com/NeilMadden/apisecurityinaction/tree/chapter03/natter-api/src/main/java/com/manning/apisecurityinaction/controller
    public JSONObject deletePost(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var msgId = Long.parseLong(request.params(":msgId"));

        database.updateUnique("DELETE FROM messages " +
                "WHERE space_id = ? AND msg_id = ?", spaceId, msgId);
        response.status(200);
        return new JSONObject();
    }
}
