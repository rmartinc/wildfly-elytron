/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.ssl;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.function.BiFunction;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import static org.wildfly.security.ssl.ElytronMessages.log;

final class JDKSpecific {

    private static Method sslEngineGetApplicationProtocol;
    private static Method sslEngineGetHandshakeApplicationProtocol;
    private static Method sslEngineSetHandshakeApplicationProtocolSelector;
    private static Method sslEngineGetHandshakeApplicationProtocolSelector;
    private static Method sslParametersGetApplicationProtocols;
    private static Method sslParametersSetApplicationProtocols;
    private static Method sslSocketGetApplicationProtocol;
    private static Method sslSocketGetHandshakeApplicationProtocol;
    private static Method sslSocketSetHandshakeApplicationProtocolSelector;
    private static Method sslSocketGetHandshakeApplicationProtocolSelector;

    static {
        try {
            // SSLEngine
            sslEngineGetApplicationProtocol = SSLEngine.class.getMethod("getApplicationProtocol");
            sslEngineGetHandshakeApplicationProtocol = SSLEngine.class.getMethod("getHandshakeApplicationProtocol");
            sslEngineSetHandshakeApplicationProtocolSelector = SSLEngine.class.getMethod("setHandshakeApplicationProtocolSelector", BiFunction.class);
            sslEngineGetHandshakeApplicationProtocolSelector = SSLEngine.class.getMethod("getHandshakeApplicationProtocolSelector");
            // SSLParameters
            sslParametersGetApplicationProtocols = SSLParameters.class.getMethod("getApplicationProtocols");
            sslParametersSetApplicationProtocols = SSLParameters.class.getMethod("setApplicationProtocols", String[].class);
            // SSLSocket
            sslSocketGetApplicationProtocol = SSLSocket.class.getMethod("getApplicationProtocol");
            sslSocketGetHandshakeApplicationProtocol = SSLSocket.class.getMethod("getHandshakeApplicationProtocol");
            sslSocketSetHandshakeApplicationProtocolSelector = SSLSocket.class.getMethod("setHandshakeApplicationProtocolSelector", BiFunction.class);
            sslSocketGetHandshakeApplicationProtocolSelector = SSLSocket.class.getMethod("getHandshakeApplicationProtocolSelector");
        } catch (NoSuchMethodException|SecurityException e) {
            log.trace("JDK implementation does not have the new TLS methods, all methods will throw UnsupportedOperationException");
            sslEngineGetApplicationProtocol = null;
            sslEngineGetHandshakeApplicationProtocol = null;
            sslEngineSetHandshakeApplicationProtocolSelector = null;
            sslEngineGetHandshakeApplicationProtocolSelector = null;
            sslSocketGetApplicationProtocol = null;
            sslSocketGetHandshakeApplicationProtocol = null;
            sslSocketSetHandshakeApplicationProtocolSelector = null;
            sslSocketGetHandshakeApplicationProtocolSelector = null;
        }
    }

    /*
     * SSLEngine
     */

    static String getApplicationProtocol(SSLEngine sslEngine) {
        if (sslEngineGetApplicationProtocol != null) {
            try {
                return (String) sslEngineGetApplicationProtocol.invoke(sslEngine);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    static String getHandshakeApplicationProtocol(SSLEngine sslEngine) {
        if (sslEngineGetHandshakeApplicationProtocol != null) {
            try {
                return (String) sslEngineGetHandshakeApplicationProtocol.invoke(sslEngine);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    static void setHandshakeApplicationProtocolSelector(SSLEngine sslEngine, BiFunction<SSLEngine, List<String>, String> selector) {
        if (sslEngineSetHandshakeApplicationProtocolSelector != null) {
            try {
                sslEngineSetHandshakeApplicationProtocolSelector.invoke(sslEngine, selector);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    static BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector(SSLEngine sslEngine) {
        if (sslEngineGetHandshakeApplicationProtocolSelector != null) {
            try {
                return (BiFunction<SSLEngine, List<String>, String>) sslEngineGetHandshakeApplicationProtocolSelector.invoke(sslEngine);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    /*
     * SSLParameters
     */

    static String[] getApplicationProtocols(SSLParameters parameters) {
        if (sslParametersGetApplicationProtocols != null) {
            try {
                return (String[]) sslParametersGetApplicationProtocols.invoke(parameters);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    static void setApplicationProtocols(SSLParameters parameters, String[] protocols) {
        if (sslParametersSetApplicationProtocols != null) {
            try {
                sslParametersSetApplicationProtocols.invoke(parameters, (Object) protocols);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    /**
     * Copies SSLParameters' fields available in java 8.
     *
     * @param original SSLParameters that should be applied to new instance
     * @return instance of SSLParameters with fields copied from original
     */
    static SSLParameters setSSLParameters(SSLParameters original) {
        SSLParameters params = new SSLParameters();
        params.setProtocols(original.getProtocols());
        params.setCipherSuites(original.getCipherSuites());
        params.setUseCipherSuitesOrder(original.getUseCipherSuitesOrder());
        params.setServerNames(original.getServerNames());
        params.setSNIMatchers(original.getSNIMatchers());
        params.setAlgorithmConstraints(original.getAlgorithmConstraints());
        params.setEndpointIdentificationAlgorithm(original.getEndpointIdentificationAlgorithm());
        if (original.getWantClientAuth()) {
            params.setWantClientAuth(original.getWantClientAuth());
        } else if (original.getNeedClientAuth()) {
            params.setNeedClientAuth(original.getNeedClientAuth());
        }
        return params;
    }

    /*
     * SSLSocket
     */

    static String getApplicationProtocol(SSLSocket socket) {
        if (sslSocketGetApplicationProtocol != null) {
            try {
                return (String) sslSocketGetApplicationProtocol.invoke(socket);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    static String getHandshakeApplicationProtocol(SSLSocket socket) {
        if (sslSocketGetHandshakeApplicationProtocol != null) {
            try {
                return (String) sslSocketGetHandshakeApplicationProtocol.invoke(socket);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    static void setHandshakeApplicationProtocolSelector(SSLSocket socket, BiFunction<SSLSocket, List<String>, String> selector) {
        if (sslSocketSetHandshakeApplicationProtocolSelector != null) {
            try {
                sslSocketSetHandshakeApplicationProtocolSelector.invoke(socket, selector);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    static BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector(SSLSocket socket) {
        if (sslSocketGetHandshakeApplicationProtocolSelector != null) {
            try {
                return (BiFunction<SSLSocket, List<String>, String>) sslSocketGetHandshakeApplicationProtocolSelector.invoke(socket);
            } catch (IllegalAccessException|IllegalArgumentException|InvocationTargetException e) {
                throw new UnsupportedOperationException(e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

}
