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

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.xml.namespace.QName;
import javax.xml.transform.dom.DOMResult;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.AuthzService;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xacml4j.v30.Attribute;
import org.xacml4j.v30.Categories;
import org.xacml4j.v30.Category;
import org.xacml4j.v30.Entity;
import org.xacml4j.v30.RequestContext;
import org.xacml4j.v30.ResponseContext;
import org.xacml4j.v30.SubjectAttributes;
import org.xacml4j.v30.XacmlSyntaxException;
import org.xacml4j.v30.marshal.jaxb.Xacml20RequestContextUnmarshaller;
import org.xacml4j.v30.marshal.jaxb.Xacml20ResponseContextMarshaller;
import org.xacml4j.v30.pdp.PolicyDecisionPoint;
import org.xacml4j.v30.types.StringExp;

public class XACMLAuthzDecisionQueryEndpoint implements OpenSamlEndpoint {

	private static final Logger log = LoggerFactory.getLogger(XACMLAuthzDecisionQueryEndpoint.class);

	private final IDPConfiguration idpConfig;

	private final PolicyDecisionPoint pdp;
	private final SigningCredentialSelector credentialSelector;
	private final Xacml20RequestContextUnmarshaller xacmlRequest20Unmarshaller;
	private final Xacml20ResponseContextMarshaller xacmlResponse20Unmarshaller;

	private final BasicParserPool parserPool;

	private boolean requireSignatureValidation;

	@Deprecated
	public XACMLAuthzDecisionQueryEndpoint(
			IDPConfiguration idpConfig,
			PolicyDecisionPoint pdp) {
		this(idpConfig, pdp, null);
	}

	public XACMLAuthzDecisionQueryEndpoint(IDPConfiguration idpConfig, PolicyDecisionPoint pdp,
			SigningCredentialSelector credentialSelector) {
		this.idpConfig = checkNotNull(idpConfig, "'idpConfig' is null.");
		this.pdp = checkNotNull(pdp, "'pdp' is null.");
		this.credentialSelector = checkNotNull(credentialSelector, "'credentialSelector' is null.");

		xacmlRequest20Unmarshaller = new Xacml20RequestContextUnmarshaller();
		xacmlResponse20Unmarshaller = new Xacml20ResponseContextMarshaller();
		parserPool = new BasicParserPool();
		parserPool.setNamespaceAware(true);
		requireSignatureValidation = true;
	}

	public void setRequireSignatureValidation(boolean flag) {
		requireSignatureValidation = flag;
	}

	@Override
	public Response handle(RequestAbstractType request) {
		if (log.isDebugEnabled()) {
			QName n = request.getElementQName();
			log.debug("Processing SAML request type=\"{}:{}\"",
					n.getNamespaceURI(), n.getLocalPart());
		}
		if (!(request instanceof XACMLAuthzDecisionQueryType)) {
			return makeErrorResponse(request, "Invalid request");
		}
		XACMLAuthzDecisionQueryType xacml20DecisionQuery = (XACMLAuthzDecisionQueryType) request;
		RequestType xacmlRequest = xacml20DecisionQuery.getRequest();
		if (xacmlRequest == null) {
			if (log.isDebugEnabled()) {
				log.debug("No XACML request found in the given request");
			}
			return makeErrorResponse(request, "Invalid request");
		}
		try {
			if (requireSignatureValidation) {
				if (!validateRequestSignature(request)) {
					if (log.isDebugEnabled()) {
						log.debug("Failed to validate signature");
					}
					return makeErrorResponse(request, "Failed to validate signature");
				}
			} else {
				log.info("Signature validation has been disabled");
			}
			if (!validateRequest(request)) {
				if (log.isDebugEnabled()) {
					log.debug("Failed to validate request");
				}
				return makeErrorResponse(request, "Failed to validate request");
			}
			Document reqDom = parserPool.newDocument();
			OpenSamlObjectBuilder.marshallXacml20Request(xacmlRequest, reqDom);
			Document resDom = performXacmlRequest(xacml20DecisionQuery.getIssuer().getValue(), reqDom);
			ResponseType xacmlResponse = OpenSamlObjectBuilder.unmarshallXacml20Response(resDom.getDocumentElement());
			Assertion assertion = OpenSamlObjectBuilder.makeXacml20AuthzDecisionAssertion(
					idpConfig.getLocalEntity().getEntityID(),
					xacml20DecisionQuery.isReturnContext() ? xacmlRequest : null, xacmlResponse);
			Response samlResponse = OpenSamlObjectBuilder.makeXacml20AuthzDecisionQueryResponse(
					idpConfig.getLocalEntity().getEntityID(), xacml20DecisionQuery, assertion);
			signResponse(request, samlResponse);
			return samlResponse;
		} catch (Exception e) {
			log.error("Caught exception while processing XacmlAuthDecisionQuery", e);
			return makeErrorResponse(request, "Internal error");
		}
	}

	private Response makeErrorResponse(RequestAbstractType request, String errorMessage) {
		Response response = OpenSamlObjectBuilder.makeResponse(request,
				OpenSamlObjectBuilder.makeStatus(StatusCode.REQUESTER_URI, errorMessage));
		response.setIssuer(OpenSamlObjectBuilder.makeIssuer(idpConfig.getLocalEntity().getEntityID()));
		return response;
	}

	private boolean validateRequestSignature(RequestAbstractType request)
			throws ValidationException, SecurityException {
		SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
		if (request.getSignature() == null) {
			log.debug("Request is not signed");
			return false;
		}
		validator.validate(request.getSignature());
		if (request.getIssuer() == null || request.getIssuer().getValue() == null) {
			if (log.isDebugEnabled()) {
				log.debug("Request does not have issuer");
			}
			return false;
		}
		CriteriaSet criteriaSet = new CriteriaSet();
		criteriaSet.add(new EntityIDCriteria(request.getIssuer().getValue()));
		criteriaSet.add(new MetadataCriteria(SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
		criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
		boolean dsigTrusted = idpConfig.getSignatureTrustEngine().validate(request.getSignature(), criteriaSet);
		if (log.isDebugEnabled()) {
			log.debug("Is SAML request XML dsig trusted=\"{}\"", dsigTrusted);
		}
		return dsigTrusted;
	}

	private boolean validateRequest(RequestAbstractType request) {
		AuthzService authzService = idpConfig.getAuthzServiceByLocation(request.getDestination());
		if (authzService == null) {
			if (log.isDebugEnabled()) {
				log.debug("Failed to get authorization service by destination location");
			}
			return false;
		}
		return true;
	}

	public Document performXacmlRequest(String issuer, Document reqDom) throws IOException, XMLParserException {
		try {
			RequestContext xacmlReq = xacmlRequest20Unmarshaller.unmarshal(reqDom);
			xacmlReq = addIssuerToRequest(issuer, xacmlReq);
			if (log.isDebugEnabled()) {
				log.debug("XACML request=\"{}\"", xacmlReq);
			}
			ResponseContext xacmlRes = pdp.decide(xacmlReq);
			Document resDom = parserPool.newDocument();
			xacmlResponse20Unmarshaller.marshal(xacmlRes, new DOMResult(resDom));
			return resDom;
		} catch (XacmlSyntaxException e) {
			if (log.isDebugEnabled()) {
				log.debug(e.getMessage(), e);
			}
			throw e;
		} catch (IOException e) {
			if (log.isDebugEnabled()) {
				log.debug(e.getMessage(), e);
			}
			throw e;
		} catch (XMLParserException e) {
			if (log.isDebugEnabled()) {
				log.debug(e.getMessage(), e);
			}
			throw e;
		}
	}

	private void signResponse(RequestAbstractType request, Response response)
			throws SecurityException, MarshallingException, SignatureException {
		Credential signingCredential = credentialSelector.selectCredential(request, response, idpConfig);

		Signature dsig = (Signature) Configuration
				.getBuilderFactory()
				.getBuilder(Signature.DEFAULT_ELEMENT_NAME)
				.buildObject(Signature.DEFAULT_ELEMENT_NAME);
		dsig.setSigningCredential(signingCredential);
		dsig.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		dsig.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		response.setSignature(dsig);

		SecurityHelper.prepareSignatureParams(dsig, signingCredential, null, null);
		Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
		Signer.signObject(dsig);
	}

	private RequestContext addIssuerToRequest(String issuer, RequestContext req) {
		Category intermediarySubject =
				Category.builder(Categories.SUBJECT_INTERMEDIARY)
						.entity(
						       Entity
						               .builder()
						               .attribute(
						                       Attribute
						                               .builder(SubjectAttributes.SUBJECT_ID.toString())
						                               .value(StringExp.of(issuer))
						                               .build())
						               .build())
						.build();
		Collection<Category> filtered = new ArrayList<Category>();
		filtered.add(intermediarySubject);
		for (Category category : req.getAttributes()) {
			if (!category.getCategoryId().equals(intermediarySubject.getCategoryId())) {
				filtered.add(category);
			}
		}
		return RequestContext.builder().copyOf(req, filtered).build();
	}
}
