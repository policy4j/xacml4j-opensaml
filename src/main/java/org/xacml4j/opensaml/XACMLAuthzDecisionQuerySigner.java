package org.xacml4j.opensaml;

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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.KeyStoreX509CredentialAdapter;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class XACMLAuthzDecisionQuerySigner
{
	private final Credential credential;

	public XACMLAuthzDecisionQuerySigner(KeyStore ks,
			String signingKeyName,
			String signingKeyPassword) throws ConfigurationException {
		DefaultBootstrap.bootstrap();
		this.credential = new KeyStoreX509CredentialAdapter(
				ks,
				signingKeyName,
				signingKeyPassword.toCharArray());
	}

	public void signRequest(InputStream request, OutputStream signedRequest) throws SAXException, IOException, ParserConfigurationException, UnmarshallingException, TransformerException, MarshallingException, SecurityException, SignatureException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
	    Document doc = dbf.newDocumentBuilder().parse(request);
	    XACMLAuthzDecisionQueryType xacmlSamlQuery = OpenSamlObjectBuilder.unmarshallXacml20AuthzDecisionQuery(doc.getDocumentElement());
	    signRequest(xacmlSamlQuery);
	    OpenSamlObjectBuilder.serialize(xacmlSamlQuery, signedRequest);
	}

	public void signRequest(RequestAbstractType response) throws SecurityException, MarshallingException, SignatureException {

		Signature dsig = (Signature) Configuration.getBuilderFactory()
	        .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
	        .buildObject(Signature.DEFAULT_ELEMENT_NAME);

		dsig.setSigningCredential(credential);
		dsig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		dsig.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		response.setSignature(dsig);
		SecurityHelper.prepareSignatureParams(dsig, credential, null, null);

		Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
		Signer.signObject(dsig);
	}
}
