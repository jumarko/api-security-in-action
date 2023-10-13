package com.manning.apisecurityinaction.controllers;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;

/**
 * Experimental class that isn't really used.
 * It's just to demonstrate LDAP groups lookup - see p. 272.
 */
public class LDAP {

    private final String ldapUrl;
    private final String connUser;
    private final String connPassword;

    public LDAP(String ldapUrl, String connUser, String connPassword) {
        this.ldapUrl = ldapUrl;
        this.connUser = connUser;
        this.connPassword = connPassword;
    }

    private List<String> lookupGroups(String username) throws NamingException {
        var props = new Properties();
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, ldapUrl);
        props.put(Context.SECURITY_AUTHENTICATION, "simple");
        props.put(Context.SECURITY_PRINCIPAL, connUser);
        props.put(Context.SECURITY_CREDENTIALS, connPassword);
        var directory = new InitialDirContext(props);

        var searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(new String[] {"cn"});

        var groups = new ArrayList<String>();
        // this assumes using https://hub.docker.com/r/bitnami/openldap/
        var results = directory.search("dc=example,dc=org",
                " (&(objectClass=groupOfNames) (member=uid={0},dc=example,dc=org))",
                new Object[] {username},
                searchControls);
        while (results.hasMore()) {
            var result = results.next();
            groups.add((String) result.getAttributes().get("cn").get(0));
        }

        directory.close();

        return groups;
    }


    public static void main(String[] args) throws NamingException {
        // This assumes using https://hub.docker.com/r/bitnami/openldap/
        System.out.println(new LDAP("ldap://localhost:1389", "cn=admin,dc=example,dc=org", "adminpassword").lookupGroups("user01"));
    }
}
