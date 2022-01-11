package com.manning.apisecurityinaction.controllers;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;
import spark.Request;
import spark.Response;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Handles audit log operations.
 * Audit logging is implemented as two filters:
 * - before: unique audit_id is generated and request is logged
 * - after: correlated audit_id is logged and processing is done
 *
 * This controller also exposes `readAuditLog` method which serves the requests to /logs endpoint
 * and returns the latest 20 logs.
 */
public class AuditController {
    private final Database database;

    public AuditController(Database database) {
        this.database = database;
    }

    public void auditRequestStart(Request request, Response response) {
        database.withVoidTransaction(tx -> {
            var auditId = database.findUniqueLong("SELECT NEXT VALUE FOR audit_id_seq");
            request.attribute("audit_id", auditId);
            database.updateUnique("INSERT INTO audit_log(audit_id, method, path, user_id, audit_time)" +
                    " VALUES(?, ?, ?, ?, current_timestamp);",
                    auditId, request.requestMethod(), request.pathInfo(), request.attribute("subject"));
        });
    }

    public void auditRequestEnd(Request request, Response response) {
        database.withVoidTransaction(tx -> {
            // read audit_id set by `auditRequestStart`
            var auditId = request.attribute("audit_id");
            // Design note: I would probably implement it as UPDATE, not INSERT
            // would add have end_timestamp column and set status
            database.updateUnique("INSERT INTO audit_log(audit_id, method, path, status, user_id, audit_time)" +
                    " VALUES(?, ?, ?, ?, ?, current_timestamp);",
                    auditId, request.requestMethod(), request.pathInfo(), response.status(), request.attribute("subject"));
        });
    }

    public JSONArray readAuditLog(Request request, Response response) {
        var since = Instant.now().minus(1, ChronoUnit.HOURS);
        var logs = database.findAll(AuditController::recordTojson,
                "SELECT * FROM audit_log WHERE audit_time >= ? LIMIT 20",
                since);
        return new JSONArray(logs);
    }

    private static JSONObject recordTojson(ResultSet row) throws SQLException {
        return new JSONObject()
                .put("id", row.getLong("audit_id"))
                .put("method", row.getString("method"))
                .put("path", row.getString("path"))
                .put("status", row.getString("status"))
                .put("user", row.getString("user_id"))
                .put("id", row.getLong("audit_id"));
    }


}
