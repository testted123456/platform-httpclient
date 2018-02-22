package com.nonobank.apps;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.conn.DnsResolver;
import org.apache.http.impl.conn.SystemDefaultDnsResolver;

public class NonoDnsResolver implements DnsResolver {
	
	public  final Map<String, InetAddress[]> MAPPINGS =  new HashMap<String, InetAddress[]>(); 
	
	public void addResolve(String host, String ip) { 
        try { 
            MAPPINGS.put(host,  new InetAddress[]{InetAddress.getByName(ip)}); 
        }  catch (UnknownHostException e) { 
            e.printStackTrace(); 
        } 
    } 

	public InetAddress[] resolve(String host) throws UnknownHostException {
		// TODO Auto-generated method stub
		return MAPPINGS.containsKey(host) ? MAPPINGS.get(host) : SystemDefaultDnsResolver.INSTANCE.resolve(host);
	}

}
