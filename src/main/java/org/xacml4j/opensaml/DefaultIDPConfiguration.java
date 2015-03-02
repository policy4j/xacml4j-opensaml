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

import org.opensaml.saml2.metadata.AuthzService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.util.DatatypeHelper;

import com.google.common.base.Preconditions;

public class DefaultIDPConfiguration implements IDPConfiguration
{
	private static final String SAML20_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

	private final EntityDescriptor localEntity;
	private final SignatureTrustEngine trustEngine;
	private final Credential idpSigningCredential;

	public DefaultIDPConfiguration(String localEntityId,
			MetadataProvider metadata,
			Credential idpSigningCredential)
		throws MetadataProviderException
	{
		Preconditions.checkNotNull(localEntityId);
		Preconditions.checkNotNull(metadata);
		Preconditions.checkNotNull(idpSigningCredential);
		this.localEntity = metadata.getEntityDescriptor(localEntityId);
		Preconditions.checkState(localEntity != null);
		this.trustEngine = createDefaultSignatureTrustEngine(metadata);
		this.idpSigningCredential = idpSigningCredential;
	}

	@Override
	public EntityDescriptor getLocalEntity() {
		return localEntity;
	}

	@Override
	public SignatureTrustEngine getSignatureTrustEngine(){
		return trustEngine;
	}

	@Override
	public AuthzService getAuthzServiceByLocation(
			String locationURL){
		PDPDescriptor pdp = localEntity.getPDPDescriptor(SAML20_PROTOCOL);
		if(pdp == null){
			return null;
		}
		for(AuthzService s : pdp.getAuthzServices()){
			if(DatatypeHelper.safeEquals(locationURL, s.getLocation())){
				return s;
			}
		}
		return null;
	}

	@Override
	public Credential getSigningCredential()
	{
		return idpSigningCredential;
	}

	private static SignatureTrustEngine createDefaultSignatureTrustEngine(MetadataProvider metadata)
	{
		MetadataCredentialResolver mdCredResolver = new MetadataCredentialResolver(metadata);
		KeyInfoCredentialResolver keyInfoCredResolver = Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();
		return new ExplicitKeySignatureTrustEngine(mdCredResolver, keyInfoCredResolver);
	}
}
