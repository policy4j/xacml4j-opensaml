package org.xacml4j.saml;

/*
 * #%L
 * XACML/OpenSAML Integration
 * %%
 * Copyright (C) 2009 - 2014 Xacml4J.org
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * #L%
 */

import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.expect;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.utils.XMLUtils;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.easymock.IMocksControl;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.w3c.dom.Document;
import org.xacml4j.opensaml.IDPConfiguration;
import org.xacml4j.opensaml.OpenSamlObjectBuilder;
import org.xacml4j.opensaml.XACMLAuthzDecisionQueryEndpoint;
import org.xacml4j.opensaml.XACMLAuthzDecisionQuerySigner;
import org.xacml4j.v30.Decision;
import org.xacml4j.v30.RequestContext;
import org.xacml4j.v30.ResponseContext;
import org.xacml4j.v30.Result;
import org.xacml4j.v30.Status;
import org.xacml4j.v30.pdp.PolicyDecisionPoint;

import com.google.common.io.Closeables;


@ContextConfiguration(locations={"classpath:testMultipleMetadataProvidersApplicationContext.xml"})
@RunWith(SpringJUnit4ClassRunner.class)
public class XACMLAuthzMultipleMetadataProvidersTest
{
	@Autowired
	private IDPConfiguration idpConfiguration;
	private XACMLAuthzDecisionQueryEndpoint endpoint;
	private PolicyDecisionPoint pdp;
	private IMocksControl control;

	private static PrivateKey spPrivateKey;
	private static X509Certificate spPublicKey;
	private static XACMLAuthzDecisionQuerySigner signer;

	@BeforeClass
	public static void init() throws Exception
	{
		DefaultBootstrap.bootstrap();
		KeyStore spKeyStore = getKeyStore("JCEKS", "/test-sp.jceks", "changeme");
		KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) spKeyStore.getEntry("mykey", new KeyStore.PasswordProtection("changeme".toCharArray()));
		spPrivateKey = entry.getPrivateKey();
		spPublicKey = (X509Certificate) entry.getCertificate();

		signer = new XACMLAuthzDecisionQuerySigner(spKeyStore, "mykey", "changeme");
	}

	@Before
	public void testInit() throws Exception
	{
		this.control = EasyMock.createControl();
		this.pdp = control.createMock(PolicyDecisionPoint.class);
		this.endpoint = new XACMLAuthzDecisionQueryEndpoint(idpConfiguration, pdp);
	}

	@Test
	public void testInvalidSignature() throws Exception
	{
		Document query = parse("TestXacmlSamlRequest-invalidSignature.xml");
		XACMLAuthzDecisionQueryType xacmlSamlQuery = OpenSamlObjectBuilder.unmarshallXacml20AuthzDecisionQuery(query.getDocumentElement());

		control.replay();
		Response response = endpoint.handle(xacmlSamlQuery);
		control.verify();

		assertThat(response, notNullValue());
		assertThat(response.getStatus().getStatusCode().getValue(), is(StatusCode.REQUESTER_URI));
	}

	@Test
	public void testInvalidSignature_SignatureValidationDisabled() throws Exception
	{
		endpoint.setRequireSignatureValidation(false);

		Document query = parse("TestXacmlSamlRequest-invalidSignature.xml");
		XACMLAuthzDecisionQueryType xacmlSamlQuery = OpenSamlObjectBuilder.unmarshallXacml20AuthzDecisionQuery(query.getDocumentElement());
		Capture<RequestContext> captureRequest = new Capture<RequestContext>();
		expect(pdp.decide(capture(captureRequest))).andReturn(ResponseContext
				.builder()
				.result(createIndeterminateProcessingError())
				.build());

		control.replay();
		Response response = endpoint.handle(xacmlSamlQuery);
		control.verify();

		assertThat(response, notNullValue());
		assertThat(response.getStatus().getStatusCode().getValue(), is(StatusCode.SUCCESS_URI));
	}

	@Test
	public void testCorrectSignature() throws Exception {
		Document query = parse("TestXacmlSamlRequest-nosignature.xml");
		new ApacheXMLDsigGenerator().signSamlRequest(query.getDocumentElement(), spPrivateKey, spPublicKey);

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(query, bos);

		XACMLAuthzDecisionQueryType xacmlSamlQuery = OpenSamlObjectBuilder.unmarshallXacml20AuthzDecisionQuery(
				query.getDocumentElement());
		Capture<RequestContext> captureRequest = new Capture<RequestContext>();
		expect(pdp.decide(capture(captureRequest))).andReturn(ResponseContext
				.builder()
				.result(createIndeterminateProcessingError())
				.build());
		control.replay();
		Response response1 = endpoint.handle(xacmlSamlQuery);

		assertThat(response1, notNullValue());
		assertThat(response1.getStatus().getStatusCode().getValue(), is(StatusCode.SUCCESS_URI));

		control.verify();
	}

	private static Result createIndeterminateProcessingError() {
		return Result.builder(
				Decision.INDETERMINATE,
				Status.builder(org.xacml4j.v30.StatusCode.createProcessingError()).build())
				.build();
	}

	private static KeyStore getKeyStore(String ksType, String resource, String ksPwd) throws Exception
	{
		InputStream is = null;
		try {
			is = XACMLAuthzDecisionQueryEndpointTest.class.getResourceAsStream(resource);
			KeyStore ks = KeyStore.getInstance(ksType);
			ks.load(is, ksPwd.toCharArray());
			return ks;
		} finally {
			Closeables.closeQuietly(is);
		}
	}

	public static Document parse(String resourcePath) throws Exception {
		InputStream in = null;
		try {
			in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
			assertThat(in, notNullValue());
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			return dbf.newDocumentBuilder().parse(in);
		} finally {
			Closeables.closeQuietly(in);
		}
	}

}
