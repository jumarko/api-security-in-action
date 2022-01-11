package com.manning.apisecurityinaction.controllers;

import org.dalesbred.Database;
import spark.Request;
import spark.Response;

/**
 * Handles audit log operations.
 * Audit logging is implemented as two filters:
 * - before: unique audit_id is generated and request is logged
 * - after: correlated audit_id is logged and processing is done
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
                    " VALUES(?, ?, ?, ?, current_timestamp),",
                    auditId, request.requestMethod(), request.pathInfo(), request.attribute("subject"));
        });
    }

    public void auditRequestEnd(Request request, Response response) {
        database.withVoidTransaction(tx -> {
            var auditId = database.findUniqueLong("SELECT NEXT VALUE FOR audit_id_seq");
            request.attribute("audit_id", auditId);
            database.updateUnique("INSERT INTO audit_log(audit_id, method, path, status, user_id, audit_time)" +
                    " VALUES(?, ?, ?, ?, ?, current_timestamp),",
                    auditId, request.requestMethod(), request.pathInfo(), response.status(), request.attribute("subject"));
        });
    }
}
