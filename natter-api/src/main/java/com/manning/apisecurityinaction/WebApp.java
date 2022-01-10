package com.manning.apisecurityinaction;

import org.json.JSONObject;
import spark.Spark;

import com.manning.apisecurityinaction.controllers.SpaceController;
import org.dalesbred.Database;

/**
 * The main entry point that sets up the routes
 * Notice that in the book this is all in the Main class.
 */
public class WebApp {
    private final Database database;

    public WebApp(Database database) {
        this.database = database;
    }

    public void init() {
        var spaceController = new SpaceController(database);

        Spark.post("/spaces", spaceController::createSpace);

        // In the book they first use after() but it should be afterAfter()
        // otherwise you'll get text/html content type for error responses
        // -> see page 37 about Content-Type
        // This commit fixes it anyway: https://github.com/NeilMadden/apisecurityinaction/commit/067b05a72fe8ed92b09d545912e8a33f8a909ab5#diff-eae019c32d4ba4dda402c532030540ae66b80cc7f7687fe353766126427d5814
        Spark.afterAfter(((request, response) -> response.type("application/json")));

        Spark.internalServerError(new JSONObject()
                .put("error", "internal server error").toString());
        Spark.notFound(new JSONObject("error", "not found").toString());
    }
}
