package com.manning.apisecurityinaction.controllers;

import spark.Request;
import spark.Response;

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

        var decision = checkPermitted(subjectAttrs, resourceAttrs, actionAttrs, envAttrs);
    }


    abstract Decision checkPermitted(
        Map<String, Object> subjectAttrs,
        Map<String, Object> resourceAttrs,
        Map<String, Object> actionAttrs,
        Map<String, Object> envAttrs
    );

    public static class Decision {

    }
}
