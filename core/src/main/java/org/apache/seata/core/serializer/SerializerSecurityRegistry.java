/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.seata.core.serializer;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.apache.seata.core.exception.TransactionExceptionCode;
import org.apache.seata.core.model.BranchStatus;
import org.apache.seata.core.model.BranchType;
import org.apache.seata.core.model.GlobalStatus;
import org.apache.seata.core.protocol.ResultCode;

/**
 * Serializer Security Registry
 */
public class SerializerSecurityRegistry {
    private static final Set<Class<?>> ALLOW_CLAZZ_SET = new HashSet<>();

    private static final Set<String> ALLOW_CLAZZ_PATTERN = new HashSet<>();

    private static final Set<String> DENY_CLAZZ_PATTERN = new HashSet<>();

    private static final String CLASS_POSTFIX = ".class";

    private static final String ABSTRACT_CLASS_ID = "Abstract";

    private static final String REQUEST_CLASS_ID = "Request";

    private static final String RESPONSE_CLASS_ID = "Response";

    private static final String MESSAGE_CLASS_ID = "Message";

    static {
        ALLOW_CLAZZ_SET.addAll(Arrays.asList(getBasicClassType()));
        ALLOW_CLAZZ_SET.addAll(Arrays.asList(getCollectionClassType()));
        ALLOW_CLAZZ_SET.addAll(getProtocolType());
        ALLOW_CLAZZ_SET.addAll(Arrays.asList(getProtocolInnerFields()));

        for (Class<?> clazz : ALLOW_CLAZZ_SET) {
            ALLOW_CLAZZ_PATTERN.add(clazz.getCanonicalName());
        }
        ALLOW_CLAZZ_PATTERN.add(getSeataClassPattern());

        DENY_CLAZZ_PATTERN.addAll(Arrays.asList(getDenyClassPatternList()));
    }

    public static Set<Class<?>> getAllowClassType() {
        return Collections.unmodifiableSet(ALLOW_CLAZZ_SET);
    }

    public static Set<String> getAllowClassPattern() {
        return Collections.unmodifiableSet(ALLOW_CLAZZ_PATTERN);
    }

    public static Set<String> getDenyClassPattern() {
        return Collections.unmodifiableSet(DENY_CLAZZ_PATTERN);
    }

    private static Class<?>[] getBasicClassType() {
        return new Class[] {Boolean.class, Byte.class, Character.class, Double.class, Float.class, Integer.class,
            Long.class, Short.class, Number.class, Class.class, String.class};
    }

    private static Class<?>[] getCollectionClassType() {
        return new Class[] {ArrayList.class, LinkedList.class, HashSet.class,
            LinkedHashSet.class, TreeSet.class, HashMap.class, LinkedHashMap.class, TreeMap.class};
    }

    private static String getSeataClassPattern() {
        return "org.apache.seata.*";
    }

    private static String[] getDenyClassPatternList() {
        return new String[] {"javax.naming.InitialContext", "javax.net.ssl.*", "com.unboundid.ldap.*", "java.lang.Runtime"};
    }

    private static Set<Class<?>> getProtocolType() {
        Set<Class<?>> classNameSet = new HashSet<>();

        try {
            String packageName = "org.apache.seata.core.protocol";
            Enumeration<URL> packageDir = Thread.currentThread().getContextClassLoader().getResources(packageName.replace(".", "/"));
            while (packageDir.hasMoreElements()) {
                URL resource = packageDir.nextElement();
                if (resource.getProtocol().equals("file")) {
                    String filePath = resource.getFile();
                    findProtocolClassByFile(filePath, packageName, classNameSet);
                }else if(resource.getProtocol().equals("jar")){
                    findProtocolClassByJar(packageName, resource, classNameSet);
                }
            }
        } catch (IOException ignore) {
        }

        return classNameSet;
    }

    private static void findProtocolClassByFile(String classPath, String rootPackageName, Set<Class<?>> classNameSet) {
        File file = new File(classPath);
        if (!file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (null == files) {
                return;
            }
            for (File path : files) {
                if (path.isDirectory()) {
                    findProtocolClassByFile(path.getAbsolutePath(), rootPackageName + "." + path.getName(),
                        classNameSet);
                } else {
                    findProtocolClassByFile(path.getAbsolutePath(), rootPackageName, classNameSet);
                }
            }
        } else {
            if (matchProtocol(file.getName())) {
                String className = file.getName().substring(0, file.getName().length() - CLASS_POSTFIX.length());
                try {
                    classNameSet.add(
                        Thread.currentThread().getContextClassLoader().loadClass(rootPackageName + '.' + className));
                } catch (ClassNotFoundException ignore) {
                    //ignore interface
                }
            }
        }
    }

    private static void findProtocolClassByJar(String packageName, URL resource, Set<Class<?>> classNameSet) {
        String jarPath = resource.getFile().substring(5, resource.getFile().indexOf("!"));
        try (JarFile jar = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (matchProtocol(name)) {
                    String className = name.replace('/', '.').substring(0, name.length() - 6);
                    if (className.startsWith(packageName)) {
                        classNameSet.add(Thread.currentThread().getContextClassLoader().loadClass(className));
                    }
                }

            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            //ignore interface
        }
    }

    private static boolean matchProtocol(String fileName) {
        if (!fileName.endsWith(CLASS_POSTFIX)) {
            return false;
        }
        fileName = fileName.replace(CLASS_POSTFIX, "");
        if (fileName.contains(ABSTRACT_CLASS_ID)) {
            return false;
        }
        if (fileName.contains(REQUEST_CLASS_ID) || fileName.contains(RESPONSE_CLASS_ID) || fileName.endsWith(MESSAGE_CLASS_ID)) {
            return true;
        }
        return false;
    }

    private static Class<?>[] getProtocolInnerFields() {
        return new Class<?>[] {ResultCode.class, GlobalStatus.class, BranchStatus.class, BranchType.class, TransactionExceptionCode.class};
    }
}
