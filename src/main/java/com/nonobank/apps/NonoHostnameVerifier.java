package com.nonobank.apps;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

public class NonoHostnameVerifier implements HostnameVerifier {

	public boolean verify(String hostname, SSLSession session) {
		return true;
	}

}
