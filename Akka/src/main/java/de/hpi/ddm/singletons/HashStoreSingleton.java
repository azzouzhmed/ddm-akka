package de.hpi.ddm.singletons;

import de.hpi.ddm.configuration.DatasetDescriptor;

import java.util.HashMap;
import java.util.Map;

public class HashStoreSingleton {

    private static HashMap<String, String> hashMap = new HashMap();

    public static void put(String hash, String hint) { hashMap.put(hash, hint); }

    public static void putAll(Map<String,String> map) { hashMap.putAll(map); }

    public static String get(String hash) { return hashMap.get(hash); }

    public static boolean contains(String hash) { return hashMap.containsKey(hash); }
}
