package com.manning.apisecurityinaction.controllers;

import spark.Request;
import spark.Response;
import spark.Spark;

import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Attribute-based Access Control (ABAC) implemented in section 8.3 (p. 283+).
 */
public abstract class ABACAccessController {
    public void enforcePolicy(Request request, Response response) {
        var subjectAttrs = new HashMap<String, Object>();
        subjectAttrs.put("user", request.attribute("subject"));
        subjectAttrs.put("groups", request.attribute("groups"));

        var resourceAttrs = new HashMap<String, Object>();
        resourceAttrs.put("path", request.pathInfo());
        // notice that space is a "realm" in natter-api
        resourceAttrs.put("space", request.params(":spaceId"));

        var actionAttrs = new HashMap<String, Object>();
        actionAttrs.put("method", request.requestMethod());

        var envAttrs = new HashMap<String, Object>();
        envAttrs.put("timeOfDay", LocalTime.now());
        // note: this is dummy and doesn't count with proxies like CloudFront (x-forwarded-for)
        envAttrs.put("ip", request.ip());

        final Decision decision = checkPermitted(subjectAttrs, resourceAttrs, actionAttrs, envAttrs);

        if (!decision.isPermitted()) {
            Spark.halt(403);
        }
    }


    abstract Decision checkPermitted(
        Map<String, Object> subjectAttrs,
        Map<String, Object> resourceAttrs,
        Map<String, Object> actionAttrs,
        Map<String, Object> envAttrs
    );

    /**
     * This class is used to combine multiple ABAC policy rules
     * into the final verdict allow/deny.
     * The `permit` flag is true by default which means we allow any action
     * unless there's an explicit 'deny' rule.
     */
    public static class Decision {
        // This wil
        private boolean permit = true;

        public void deny() {
            this.permit = false;
        }

        public void permit() {
            // no action since allow is the default
            // and if somebody else already denied the action we don't want to allow it again
        }

        boolean isPermitted() {
            return this.permit;
        }
    }
}
