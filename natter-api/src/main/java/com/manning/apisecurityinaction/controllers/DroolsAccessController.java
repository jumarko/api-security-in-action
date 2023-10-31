package com.manning.apisecurityinaction.controllers;

import org.kie.api.runtime.KieContainer;

import java.util.Map;

/**
 * ABACAccessController implemented via Drools rule engine.
 */
public class DroolsAccessController extends ABACAccessController {

    private final KieContainer kieContainer;

    public DroolsAccessController(KieContainer kieContainer) {
        this.kieContainer = kieContainer;
    }

    @Override
    Decision checkPermitted(Map<String, Object> subject, Map<String, Object> resource, Map<String, Object> action, Map<String, Object> env) {
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
}
