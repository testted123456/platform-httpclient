package com.nonobank.apps;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.alibaba.fastjson.JSONObject;

public class HttpClient {
	public static Logger logger = LoggerFactory.getLogger(HttpClient.class);

	private String createGetParam(String url, Map<String, String> params) {
		String realUrl = url;
		StringBuffer sb = null;
		if (params != null) {
			Iterator<String> it = params.keySet().iterator();
			while (it.hasNext()) {
				String key = it.next();
				String value = String.valueOf(params.get(key));
				if (sb == null) {
					sb = new StringBuffer();
					sb.append("?");
				} else {
					sb.append("&");
				}
				sb.append(key);
				sb.append("=");
				sb.append(value);
			}
			realUrl += sb.toString();
		}
		return realUrl;
	}

	/**
	 * 获得KeyStore.
	 * @param keyStorePath 密钥库路径
	 * @param password 密码
	 * @return 密钥库
	 * @throws Exception
	 */
	public KeyStore getKeyStore(String password, String keyStorePath) throws Exception {
		// 实例化密钥库
		KeyStore ks = KeyStore.getInstance("JKS");
		// 获得密钥库文件流
		FileInputStream is = new FileInputStream(keyStorePath);
		// 加载密钥库
		ks.load(is, password.toCharArray());
		// 关闭密钥库文件流
		is.close();
		return ks;
	}

	/**
	 * 获得SSLSocketFactory.
	 * @param password 密码
	 * @param keyStorePath 密钥库路径
	 * @param trustStorePath 信任库路径
	 * @return SSLSocketFactory
	 * @throws Exception
	 */
	public SSLContext getSSLContext(String password, String keyStorePath, String trustStorePath)
			throws Exception {
		// 实例化密钥库
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		// 获得密钥库
		KeyStore keyStore = getKeyStore(password, keyStorePath);
		// 初始化密钥工厂
		keyManagerFactory.init(keyStore, password.toCharArray());
		// 实例化信任库
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		// 获得信任库
		KeyStore trustStore = getKeyStore(password, trustStorePath);
		// 初始化信任库
		trustManagerFactory.init(trustStore);
		// 实例化SSL上下文
		SSLContext ctx = SSLContext.getInstance("TLS");
		// 初始化SSL上下文
		ctx.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
		// 获得SSLSocketFactory
		return ctx;
	}

	/**
	 * 初始化HttpsURLConnection.
	 * @param password 密码
	 * @param keyStorePath 密钥库路径
	 * @param trustStorePath 信任库路径
	 * @throws Exception
	 */
	public void initHttpsURLConnection(String password, String keyStorePath, String trustStorePath)
			throws Exception {
		// 声明SSL上下文
		SSLContext sslContext = null;
		// 实例化主机名验证接口
		HostnameVerifier hnv = new NonoHostnameVerifier();
		
		try {
			sslContext = getSSLContext(password, keyStorePath, trustStorePath);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		
		if (sslContext != null) {
			HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
		}
		
		HttpsURLConnection.setDefaultHostnameVerifier(hnv);
	}
	
	public CloseableHttpClient getHttpsClient(DnsResolver dnsResolver) throws KeyManagementException, NoSuchAlgorithmException {
		// 采用绕过验证的方式处理https请求
		SSLContext sslcontext = createIgnoreVerifySSL();

		// 设置协议http和https对应的处理socket链接工厂的对象
		Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
				.register("http", PlainConnectionSocketFactory.INSTANCE)
				.register("https", new SSLConnectionSocketFactory(sslcontext)).build();
		PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry, dnsResolver);
		HttpClients.custom().setConnectionManager(connManager);

		// 创建自定义的httpclient对象
		CloseableHttpClient client = HttpClients.custom().setConnectionManager(connManager).build();
		return client;
	}

	public CloseableHttpClient getHttpsClient() throws KeyManagementException, NoSuchAlgorithmException {
		// 采用绕过验证的方式处理https请求
		SSLContext sslcontext = createIgnoreVerifySSL();

		// 设置协议http和https对应的处理socket链接工厂的对象
		Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
				.register("http", PlainConnectionSocketFactory.INSTANCE)
				.register("https", new SSLConnectionSocketFactory(sslcontext)).build();
		PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
		HttpClients.custom().setConnectionManager(connManager);

		// 创建自定义的httpclient对象
		CloseableHttpClient client = HttpClients.custom().setConnectionManager(connManager).build();
		return client;
	}

	public CloseableHttpClient getHttpClient() {
		return HttpClients.createDefault();
	}
	
	public CloseableHttpClient getHttpClient(NonoDnsResolver dnsResolver) {
		Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
				.register("http", PlainConnectionSocketFactory.INSTANCE).build();
		
		PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry, dnsResolver);
		
		HttpClients.custom().setConnectionManager(connManager);

		// 创建自定义的httpclient对象
		CloseableHttpClient client = HttpClients.custom().setConnectionManager(connManager).build();
		return client;
	}
	
	public void closeConnection(CloseableHttpClient client) throws IOException {
		if (null != client) {
			client.close();
		}
	}
	
	/**
	 * 根据response返回消息体
	 * @param response
	 * @return
	 * @throws IOException 
	 */
	public static String getResBody(CloseableHttpResponse response) throws IOException, HttpException  {
		// 获取结实体
		String body = null;
		
		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
			HttpEntity responseEntity = response.getEntity();
			body = EntityUtils.toString(responseEntity, "utf-8");
			response.close();
			return body;
		} else {
			logger.error("请求失败 : " + response.getStatusLine().getReasonPhrase());
			throw new HttpException("http响应码：" + response.getStatusLine().getStatusCode() + "，原因：" + response.getStatusLine().getReasonPhrase());
		}
	}
	
	/**
	 * 根据response返回消息头
	 * @param response
	 * @return
	 */
	public Map<String, String> getResHeader(CloseableHttpResponse response){
		if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
			Header [] headers = response.getAllHeaders();
			Map<String, String> map = new HashMap<String, String>();
			
			for(Header header : headers){
				map.put(header.getName(), header.getValue());
			}
			
			return map;
		}
		
		return null;
	}

	public CloseableHttpResponse doPostSendXML(CloseableHttpClient client, Map<String, String> header, String url, String xmlStr)
			throws KeyManagementException, NoSuchAlgorithmException, ClientProtocolException, IOException {

		// 创建post方式请求对象
		HttpPost httpPost = new HttpPost(url);
		
		RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(120000).setConnectionRequestTimeout(120000)
                .setSocketTimeout(120000).build();
		
		httpPost.setConfig(requestConfig);
		
		//设置消息头
		if(null != header){
			Set<Entry<String, String>> set = header.entrySet();
			Iterator<Entry<String, String>>  ite = set.iterator();
			while(ite.hasNext()){
				Entry<String, String> entry = ite.next();
				httpPost.setHeader(entry.getKey(), entry.getValue());
			}
		}
		
		StringEntity jsonentity = new StringEntity(xmlStr);
		jsonentity.setContentEncoding("UTF-8");
		jsonentity.setContentType("application/xml");
		httpPost.setEntity(jsonentity);

		logger.info("请求地址：" + url);

		// 执行请求操作，并拿到结果（同步阻塞）
		CloseableHttpResponse response = client.execute(httpPost);
		return response;
	}

	public CloseableHttpResponse doGetSend(CloseableHttpClient client, Map<String, String> header, String url, Map<String, String> map)
			throws IOException
	{
		if (null != map && map.size() > 0) {
			url = createGetParam(url, map);
		}

		logger.info("请求地址：" + url);
		
		RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(120000).setConnectionRequestTimeout(120000)
                .setSocketTimeout(120000).build();

		HttpGet httpGet = new HttpGet(url);
		httpGet.setConfig(requestConfig);
		
		//设置消息头
		httpGet.setHeader("Content-type", "application/x-www-form-urlencoded");
		
		if(null != header){
			Set<Entry<String, String>> set = header.entrySet();
			Iterator<Entry<String, String>>  ite = set.iterator();
			while(ite.hasNext()){
				Entry<String, String> entry = ite.next();
				httpGet.setHeader(entry.getKey(), entry.getValue());
			}
		}

		// 执行请求操作，并拿到结果（同步阻塞）
		CloseableHttpResponse response = client.execute(httpGet);
		return response;
	}

	public CloseableHttpResponse doPostSendJson(CloseableHttpClient client, Map<String, String> header, String url, String jsonStr)
			throws IOException {

		// 创建post方式请求对象
		HttpPost httpPost = new HttpPost(url);
		
		RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(120000).setConnectionRequestTimeout(120000)
                .setSocketTimeout(120000).build();
		
		httpPost.setConfig(requestConfig);
		
		if(null != header){
			Set<Entry<String, String>> set = header.entrySet();
			Iterator<Entry<String, String>>  ite = set.iterator();
			while(ite.hasNext()){
				Entry<String, String> entry = ite.next();
				httpPost.setHeader(entry.getKey(), entry.getValue());
			}
		}
		
		if(null != jsonStr){
			StringEntity jsonentity = new StringEntity(jsonStr,"UTF-8");
			jsonentity.setContentType("application/json;chartSet=UTF-8");
			httpPost.setEntity(jsonentity);	
		}

		logger.info("请求地址：" + url);
		// 执行请求操作，并拿到结果（同步阻塞）
		CloseableHttpResponse response = client.execute(httpPost);
		return response;
	}

	public CloseableHttpResponse doPostSendForm(CloseableHttpClient client, Map<String, String> header, String url, Map<String, String> map)
			throws IOException {

		// 创建post方式请求对象
		HttpPost httpPost = new HttpPost(url);
		
		RequestConfig requestConfig = RequestConfig.custom()
				.setConnectTimeout(120000).setConnectionRequestTimeout(120000)
				.setSocketTimeout(120000).build();

		httpPost.setConfig(requestConfig);

		// 装填参数
		List<NameValuePair> nvps = new ArrayList<NameValuePair>();
		if (map != null) {
			for (Entry<String, String> entry : map.entrySet()) {
				String v = null;
				if(entry.getValue() != v){
					v = String.valueOf(entry.getValue());
				}
				nvps.add(new BasicNameValuePair(entry.getKey(), v));
			}
		}
		// 设置参数到请求对象中
		httpPost.setEntity(new UrlEncodedFormEntity(nvps, "UTF-8"));
//		httpPost.setEntity(new UrlEncodedFormEntity(nvps));
		HttpEntity entity = new UrlEncodedFormEntity(nvps);
		System.out.println("+++++"+entity.toString());
		logger.info("请求地址：" + url);
		logger.info("请求参数：" + nvps.toString());
		// 设置header信息
		// 指定报文头【Content-type】、【User-Agent】
		
		httpPost.setHeader("Content-type", "application/x-www-form-urlencoded");
		
		if(null != header){
			Set<Entry<String, String>> set = header.entrySet();
			Iterator<Entry<String, String>>  ite = set.iterator();
			while(ite.hasNext()){
				Entry<String, String> entry = ite.next();
				httpPost.setHeader(entry.getKey(), entry.getValue());
			}
		}

		// 执行请求操作，并拿到结果（同步阻塞）
		CloseableHttpResponse response = client.execute(httpPost);
		return response;
	}

	// 绕过验证
	public SSLContext createIgnoreVerifySSL() throws NoSuchAlgorithmException, KeyManagementException {
		SSLContext sc = SSLContext.getInstance("SSLv3");

		// 实现一个X509TrustManager接口，用于绕过验证，不用修改里面的方法
		X509TrustManager trustManager = new X509TrustManager() {
			public void checkClientTrusted(java.security.cert.X509Certificate[] paramArrayOfX509Certificate,
					String paramString) throws CertificateException {
			}

			public void checkServerTrusted(java.security.cert.X509Certificate[] paramArrayOfX509Certificate,
					String paramString) throws CertificateException {
			}

			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		};

		sc.init(null, new TrustManager[] { trustManager }, null);
		return sc;
	}

	public String getCookie(CloseableHttpResponse response){
		Header[] headers =response.getHeaders("Set-Cookie");
		StringBuffer stringBuffer = new StringBuffer("");
		for(Header header:headers){
			stringBuffer.append(header.getValue());
			stringBuffer.append(";");
		}
		return stringBuffer.toString();
	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyManagementException {
		
		List<Integer> list = new ArrayList<Integer>();
		list.add(1);
		list.add(2);
		
		System.out.println(list.toString());
		
		JSONObject json = new JSONObject();
		json.put("k", "v");
		System.out.println(String.valueOf(null));
	}
}
