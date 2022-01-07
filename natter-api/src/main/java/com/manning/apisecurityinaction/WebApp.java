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

        // TODO: in the book they use just after() but I think it should be afterAfter()
        // -> see page 37 about Content-Type
        Spark.afterAfter(((request, response) -> response.type("application/json")));

        Spark.internalServerError(new JSONObject()
                .put("error", "internal server error").toString());
        Spark.notFound(new JSONObject("error", "not found").toString());
    }
}
