package de.visiongaia.gedefense.tv.platform.titan.privilege;

interface ITitanShizukuBridge {

    String probeIdentity() = 1;

    Bundle runAllowlisted(String program, in String[] args, long timeoutMillis, int maxBytes) = 2;

    oneway void destroy() = 16777114;
}
