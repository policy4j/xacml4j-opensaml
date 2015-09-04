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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.InclusiveNamespaces;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class ApacheXMLDsigGenerator
{
	private final static String SAMLA20_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

	static{
		Init.init();
	}

	private Element getIssuerElement(Element req)
	{
		NodeList found =  req.getElementsByTagNameNS(SAMLA20_NS, "Issuer");
		if(found == null ||
				found.getLength() == 0 ||
				found.getLength() > 1){
			throw new IllegalArgumentException(
					"SAML 2.0 request contains either none or more than one issuer");
		}
		return (Element)found.item(0);
	}

	public void signSamlRequest(Element req,
			PrivateKey privateKey,
			X509Certificate publicKey) throws Exception
	{

		Document doc = req.getOwnerDocument();
		XMLSignature dsig = new XMLSignature(doc, null,
				XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
	          Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		Element issuer = getIssuerElement(req);
		req.insertBefore(dsig.getElement(), issuer.getNextSibling());
		Transforms transforms = new Transforms(doc);
		transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
		InclusiveNamespaces incNS = new InclusiveNamespaces(doc, "ds saml2 xacml-context xacml-samlp");
		transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, incNS.getElement());
		String ID = req.getAttribute("ID");
		if(ID == null){
			throw new IllegalArgumentException(
					"Given request does not have ID attribute set");
		}
		dsig.addDocument("#" + ID, transforms, Constants.ALGO_ID_DIGEST_SHA1);
		dsig.addKeyInfo(publicKey);
		dsig.sign(privateKey);
	}
}
