package com.manning.apisecurityinaction.controllers;

import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;

import java.util.HashMap;
import java.util.Map;

/**
 * ABACAccessController implemented via Drools rule engine.
 */
public class DroolsAccessController extends ABACAccessController {

    private final KieContainer kieContainer;

    public DroolsAccessController() {
        this.kieContainer = KieServices.get().getKieClasspathContainer();
    }

    @Override
    Decision checkPermitted(Map<String, Object> subject, Map<String, Object> resource, Map<String, Object> action, Map<String, Object> env) {
        // NOTE: the first time this is called it will be very slow - at least several seconds
        var session = kieContainer.newKieSession();
        var decision = new Decision();
        try {
            session.setGlobal("decision", decision);
            session.insert(subject);
            session.insert(resource);
            session.insert(action);
            session.insert(env);

            session.fireAllRules();
            // TODO: this is in the book but that's just boolean not matching Decision type
            // return decision.isPermitted();
            return decision;
        } finally {
            session.dispose();
        }
    }

    // NOTE: these nested wrappers are really cumbersome - only because Drools likes types
    public static class Subject extends HashMap<String, Object> {
        Subject(Map<String, Object> m) { super(m); };
    }
    public static class Resource extends HashMap<String, Object> {
        Resource(Map<String, Object> m) { super(m); };
    }
    public static class Action extends HashMap<String, Object> {
        Action(Map<String, Object> m) { super(m); };
    }
    public static class Environment extends HashMap<String, Object> {
        Environment(Map<String, Object> m) { super(m); };
    }
}
